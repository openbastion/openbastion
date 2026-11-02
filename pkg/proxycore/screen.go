package proxycore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

var (
	ErrScreenInputInvalid = errors.New("proxycore: invalid screen input")
	ErrScreenSequence     = errors.New("proxycore: invalid screen frame sequence")
)

// ScreenCodec opens a protocol-specific graphical client only after the shared
// lifecycle has admitted the session and fetched its ephemeral credential.
type ScreenCodec interface {
	Open(ctx context.Context, cred *Credential) (ScreenSession, error)
}

// ScreenSession is the live graphical connection to the target. Close must
// unblock Frames and any protocol I/O; Input is deliberately typed and bounded.
type ScreenSession interface {
	Frames() <-chan screenstream.Message
	Input(screenstream.InputEvent) error
	Err() error
	Close() error
}

// FrameRecorder durably records a frame and acknowledges the highest persisted
// sequence. Seal writes the terminal marker through the last acknowledged frame.
type FrameRecorder interface {
	Record(ctx context.Context, sessionID string, frame screenstream.Message) (throughSequence uint64, err error)
	Seal(ctx context.Context, sessionID string, throughSequence uint64) error
}

// ScreenRecorderGate is separate from command recording: graphical sessions must
// prove that the Video Recorder is ready before the Vault's one-use scope is spent.
type ScreenRecorderGate interface {
	Ready(ctx context.Context) error
}

// ScreenSink sends the exact frame bytes after durable recorder acknowledgement.
type ScreenSink interface {
	Send(ctx context.Context, message screenstream.Message) error
}

// ServeScreen runs a graphical session through the same revocable lifecycle as
// SSH. The Video Recorder is mandatory; break-glass and best-effort recording are
// intentionally unavailable for screens (ADR-0069/0070/0071).
func (l *Listener) ServeScreen(ctx context.Context, meta SessionMetadata, codec ScreenCodec, recorder FrameRecorder, gate ScreenRecorderGate, sink ScreenSink) error {
	if codec == nil || recorder == nil || gate == nil || sink == nil || meta.SessionID == "" || meta.ExpiresAt.IsZero() ||
		(meta.ScreenProtocol != screenstream.ProtocolRDP && meta.ScreenProtocol != screenstream.ProtocolVNC) {
		return fmt.Errorf("proxycore: graphical session configuration is incomplete")
	}
	if meta.BreakGlass {
		return fmt.Errorf("proxycore: break-glass is forbidden for graphical sessions")
	}
	admit := func(ctx context.Context, meta SessionMetadata) (Admission, error) {
		probeCtx, cancel := context.WithTimeout(ctx, defaultGateTimeout)
		defer cancel()
		if err := gate.Ready(probeCtx); err != nil {
			_ = l.Terminator.EmitRecordingUnavailable(ctx, meta.SessionID)
			return Admission{}, fmt.Errorf("%w: video recorder is not ready", ErrRecordingUnavailable)
		}
		return Admission{sessionID: meta.SessionID, granted: true}, nil
	}
	// A command-session admission cannot stand in for the Video Recorder's
	// readiness proof, even if the caller reused metadata from another path.
	meta.Admission = Admission{}
	return l.serveWithRelay(ctx, meta, admit, func(relayCtx, cleanupCtx context.Context, cred *Credential) error {
		return relayScreen(relayCtx, cleanupCtx, meta, cred, codec, recorder, sink)
	})
}

func relayScreen(ctx, cleanupCtx context.Context, meta SessionMetadata, cred *Credential, codec ScreenCodec, recorder FrameRecorder, sink ScreenSink) (relayErr error) {
	session, err := codec.Open(ctx, cred)
	if err != nil {
		return err
	}
	lastAck := uint64(0)
	defer func() {
		if closeErr := session.Close(); relayErr == nil && closeErr != nil {
			relayErr = closeErr
		}
		// A terminal marker is attempted even after revocation, expiry or an
		// ambiguous frame acknowledgement. It is bounded and independent of the
		// relay context so cancellation cannot silently skip finalization.
		sealCtx, cancel := context.WithTimeout(context.WithoutCancel(cleanupCtx), 2*time.Second)
		sealErr := recorder.Seal(sealCtx, meta.SessionID, lastAck)
		cancel()
		if sealErr != nil {
			relayErr = errors.Join(relayErr, fmt.Errorf("%w: sealing screen recording", ErrRecordingUnavailable))
		}
	}()

	frames := session.Frames()
	if frames == nil {
		return errors.New("proxycore: screen engine returned no frame stream")
	}
	sequence := uint64(1)
	hello := screenstream.Message{
		Type: screenstream.TypeHello, Sequence: sequence, Timestamp: time.Now().UTC(),
		Protocol: meta.ScreenProtocol, ExpiresAt: meta.ExpiresAt, SessionID: meta.SessionID,
	}
	if _, err := screenstream.Encode(hello); err != nil {
		return fmt.Errorf("proxycore: invalid screen HELLO: %w", err)
	}
	if err := sink.Send(ctx, hello); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			if errors.Is(context.Cause(ctx), ErrSessionRevoked) {
				return ErrSessionRevoked
			}
			return ctx.Err()
		case frame, ok := <-frames:
			if !ok {
				if err := session.Err(); err != nil {
					return err
				}
				return nil
			}
			if frame.Type != screenstream.TypeFrame || frame.Sequence != sequence || frame.Timestamp.IsZero() {
				return ErrScreenSequence
			}
			if _, err := screenstream.Encode(frame); err != nil {
				return fmt.Errorf("%w: invalid frame", ErrRecordingUnavailable)
			}
			// The recorder is a trust boundary: pass it its own byte slice so a
			// buggy adapter cannot mutate the exact frame we later display.
			recordFrame := frame
			recordFrame.PNG = append([]byte(nil), frame.PNG...)
			ack, err := recorder.Record(ctx, meta.SessionID, recordFrame)
			if err != nil || ack != frame.Sequence {
				return fmt.Errorf("%w: frame acknowledgement missing or ambiguous", ErrRecordingUnavailable)
			}
			lastAck = ack
			if err := sink.Send(ctx, frame); err != nil {
				// The frame is durable even if the operator disconnected. Seal the
				// recording on the caller context before returning the relay error.
				return err
			}
			sequence++
		}
	}
}

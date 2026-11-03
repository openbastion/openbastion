package proxycore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

var (
	ErrScreenInputInvalid     = errors.New("proxycore: invalid screen input")
	ErrScreenSequence         = errors.New("proxycore: invalid screen frame sequence")
	ErrScreenCodecUnavailable = errors.New("proxycore: screen codec unavailable")
	ErrRecordingLost          = errors.New("proxycore: screen recording lost")
)

// ScreenFailure carries a stable public END code without exposing the internal cause.
type ScreenFailure struct {
	Code string
	Err  error
}

func (e *ScreenFailure) Error() string         { return "proxycore: screen failure (" + e.Code + ")" }
func (e *ScreenFailure) Unwrap() error         { return e.Err }
func (e *ScreenFailure) ScreenEndCode() string { return e.Code }

// ScreenCodec opens the protocol engine using a one-use Vault credential.
type ScreenCodec interface {
	Open(context.Context, *Credential) (ScreenSession, error)
}

type ScreenSession interface {
	Frames() <-chan screenstream.Message
	Input(screenstream.InputEvent) error
	Err() error
	Close() error
}

type FrameRecorder interface {
	Record(context.Context, string, screenstream.Message) (uint64, error)
	Seal(context.Context, string, uint64) error
}

type ScreenRecorderGate interface{ Ready(context.Context) error }

// ScreenSink sends the exact frame bytes after durable recorder acknowledgement.
type ScreenSink interface {
	Send(ctx context.Context, message screenstream.Message) error
}

// ScreenInputSource is implemented by interactive transports. Input bytes are
// decoded and bounded by proxycore against the current framebuffer before they
// reach the protocol engine.
type ScreenInputSource interface {
	ReceiveInput(ctx context.Context) ([]byte, error)
}

// ServeScreen runs a graphical session through the same revocable lifecycle as
// SSH. The Video Recorder is mandatory; break-glass and best-effort recording are
// intentionally unavailable for screens (ADR-0069/0070/0071).
func (l *Listener) ServeScreen(ctx context.Context, meta SessionMetadata, codec ScreenCodec, recorder FrameRecorder, gate ScreenRecorderGate, sink ScreenSink) (relayErr error) {
	var tracked *trackingScreenSink
	if sink != nil {
		tracked = &trackingScreenSink{ScreenSink: sink}
		if input, ok := sink.(ScreenInputSource); ok {
			sink = &trackingInputScreenSink{trackingScreenSink: tracked, input: input}
		} else {
			sink = tracked
		}
	}
	defer func() {
		if tracked == nil || tracked.ended() {
			return
		}
		code, text := screenEndStatus(relayErr)
		endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 500*time.Millisecond)
		endErr := tracked.Send(endCtx, screenstream.Message{Type: screenstream.TypeEnd, Sequence: 1, Timestamp: time.Now().UTC(), EndCode: code, Text: text})
		cancel()
		if relayErr == nil && endErr != nil {
			relayErr = endErr
		}
	}()
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

func screenEndStatus(err error) (uint16, string) {
	switch {
	case errors.Is(err, ErrSessionRevoked):
		return screenstream.EndCodeSessionRevoked, "session_revoked"
	case errors.Is(err, ErrSessionExpired):
		return screenstream.EndCodeSessionExpired, "session_expired"
	case errors.Is(err, ErrRecordingUnavailable):
		return screenstream.EndCodeRecordingUnavailable, "recording_unavailable"
	case errors.Is(err, ErrRecordingLost):
		return screenstream.EndCodeRecordingLost, "recording_lost"
	case errors.Is(err, ErrScreenInputInvalid):
		return screenstream.EndCodeInputInvalid, "input_invalid"
	case errors.Is(err, ErrScreenSequence):
		return screenstream.EndCodeProtocolVersionUnsupported, "protocol_version_unsupported"
	case errors.Is(err, ErrScreenCodecUnavailable):
		return screenstream.EndCodeCodecUnsupported, "codec_unsupported"
	case err == nil:
		return screenstream.EndCodeSessionEnded, "session_ended"
	}
	var coded interface{ ScreenEndCode() string }
	if errors.As(err, &coded) {
		switch coded.ScreenEndCode() {
		case "pin_missing":
			return screenstream.EndCodePinMissing, "pin_missing"
		case "pin_mismatch":
			return screenstream.EndCodePinMismatch, "pin_mismatch"
		case "tls_required":
			return screenstream.EndCodeTLSRequired, "tls_required"
		case "nla_required":
			return screenstream.EndCodeNLARequired, "nla_required"
		case "protocol_version_unsupported":
			return screenstream.EndCodeProtocolVersionUnsupported, "protocol_version_unsupported"
		case "codec_unsupported":
			return screenstream.EndCodeCodecUnsupported, "codec_unsupported"
		case "recording_unavailable":
			return screenstream.EndCodeRecordingUnavailable, "recording_unavailable"
		case "recording_lost":
			return screenstream.EndCodeRecordingLost, "recording_lost"
		case "ticket_invalid":
			return screenstream.EndCodeTicketInvalid, "ticket_invalid"
		case "input_invalid":
			return screenstream.EndCodeInputInvalid, "input_invalid"
		case "session_expired":
			return screenstream.EndCodeSessionExpired, "session_expired"
		case "session_revoked":
			return screenstream.EndCodeSessionRevoked, "session_revoked"
		case "target_unreachable":
			return screenstream.EndCodeTargetUnreachable, "target_unreachable"
		}
	}
	return screenstream.EndCodeTargetUnreachable, "target_unreachable"
}

type trackingScreenSink struct {
	ScreenSink
	mu      sync.Mutex
	endSent bool
}
type trackingInputScreenSink struct {
	*trackingScreenSink
	input ScreenInputSource
}

func (s *trackingInputScreenSink) ReceiveInput(ctx context.Context) ([]byte, error) {
	return s.input.ReceiveInput(ctx)
}

func (s *trackingScreenSink) Send(ctx context.Context, message screenstream.Message) error {
	if err := s.ScreenSink.Send(ctx, message); err != nil {
		return err
	}
	if message.Type == screenstream.TypeEnd {
		s.mu.Lock()
		s.endSent = true
		s.mu.Unlock()
	}
	return nil
}
func (s *trackingScreenSink) ended() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.endSent }

type screenInputResult struct {
	data []byte
	err  error
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
			relayErr = errors.Join(relayErr, fmt.Errorf("%w: sealing screen recording", ErrRecordingLost))
		}
		endCode, endText := screenEndStatus(relayErr)
		endCtx, endCancel := context.WithTimeout(context.WithoutCancel(cleanupCtx), 500*time.Millisecond)
		endErr := sink.Send(endCtx, screenstream.Message{Type: screenstream.TypeEnd, Sequence: lastAck + 1, Timestamp: time.Now().UTC(), EndCode: endCode, Text: endText})
		endCancel()
		if relayErr == nil && endErr != nil {
			relayErr = endErr
		}
	}()

	frames := session.Frames()
	var inputResults <-chan screenInputResult
	if source, ok := sink.(ScreenInputSource); ok {
		ch := make(chan screenInputResult, 1)
		inputResults = ch
		go func() {
			for {
				data, err := source.ReceiveInput(ctx)
				select {
				case ch <- screenInputResult{data: data, err: err}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}()
	}
	var frameWidth, frameHeight uint32
	if frames == nil {
		return errors.New("proxycore: screen engine returned no frame stream")
	}
	sequence := uint64(1)
	hello := screenstream.Message{
		Type: screenstream.TypeHello, Sequence: 0, Timestamp: time.Now().UTC(),
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
		case incoming, ok := <-inputResults:
			if !ok || incoming.err != nil {
				return fmt.Errorf("proxycore: screen input transport closed")
			}
			event, err := screenstream.DecodeInput(incoming.data, frameWidth, frameHeight)
			if err != nil {
				return fmt.Errorf("%w: invalid operator input", ErrScreenInputInvalid)
			}
			if err := session.Input(event); err != nil {
				return fmt.Errorf("%w: protocol engine rejected input", ErrScreenInputInvalid)
			}
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
				return fmt.Errorf("%w: invalid frame", ErrScreenCodecUnavailable)
			}
			// The recorder is a trust boundary: pass it its own byte slice so a
			// buggy adapter cannot mutate the exact frame we later display.
			recordFrame := frame
			recordFrame.PNG = append([]byte(nil), frame.PNG...)
			ack, err := recorder.Record(ctx, meta.SessionID, recordFrame)
			if err != nil || ack != frame.Sequence {
				return fmt.Errorf("%w: frame acknowledgement missing or ambiguous", ErrRecordingLost)
			}
			lastAck = ack
			frameWidth, frameHeight = frame.Width, frame.Height
			if err := sink.Send(ctx, frame); err != nil {
				// The frame is durable even if the operator disconnected. Seal the
				// recording on the caller context before returning the relay error.
				return err
			}
			sequence++
		}
	}
}

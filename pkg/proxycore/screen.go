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

// isTLSPinMismatch says the target did not present the certificate the Vault pinned for it: what
// someone taking the target's place looks like. Nothing of the secret was sent (ADR-0071 §3).
func isTLSPinMismatch(err error) bool {
	var coded interface{ ScreenEndCode() string }
	return errors.As(err, &coded) && coded.ScreenEndCode() == "pin_mismatch"
}

// ScreenInputLimits bounds what one session may send to its target (ADR-0071 §6): moves beyond
// the budget are coalesced, anything else beyond it closes the session. Zero means the defaults.
type ScreenInputLimits struct {
	RatePerSecond int
	Burst         int
}

const (
	DefaultScreenInputRate  = 200
	DefaultScreenInputBurst = 400
	// DefaultScreenAckTimeout leaves room to persist a whole 4 MiB frame: past it, a recorder that
	// says nothing is a recording that is lost, not a session that waits for its deadline.
	DefaultScreenAckTimeout = 10 * time.Second
	// screenAckGrace is what a frame already sent to the recorder gets after the session ended:
	// its acknowledgement is what lets the terminal marker say the recording is complete.
	screenAckGrace = 2 * time.Second
)

// screenInputBudget is a token bucket that belongs to one relay, so it takes no lock.
type screenInputBudget struct {
	rate, burst, tokens float64
	last                time.Time
	buttons             byte
}

func newScreenInputBudget(limits ScreenInputLimits, now time.Time) *screenInputBudget {
	rate, burst := limits.RatePerSecond, limits.Burst
	if rate <= 0 {
		rate = DefaultScreenInputRate
	}
	if burst <= 0 {
		burst = DefaultScreenInputBurst
	}
	return &screenInputBudget{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now}
}

type screenInputVerdict int

const (
	screenInputForward screenInputVerdict = iota
	screenInputCoalesce
	screenInputRefuse
)

// admit spends one token. Out of tokens, a mere move is dropped, since the next one carries a later
// position; a key or a button change is not a thing to lose or to guess, so it ends the session.
func (b *screenInputBudget) admit(e screenstream.InputEvent, now time.Time) screenInputVerdict {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
		b.last = now
	}
	isMove := e.Type == screenstream.InputPointer && e.Buttons == b.buttons && e.Wheel == 0
	if e.Type == screenstream.InputPointer {
		b.buttons = e.Buttons
	}
	if b.tokens >= 1 {
		b.tokens--
		return screenInputForward
	}
	if isMove {
		return screenInputCoalesce
	}
	return screenInputRefuse
}

// screenDisplay sends acknowledged frames to the operator without ever holding up the relay: a
// stalled browser must not stop the recording nor the input (ADR-0071 §11). One frame is in
// flight, one waits, and a newer one replaces the one that waits: frames are complete, so nothing
// is lost but an intermediate picture, which the recorder has anyway.
type screenDisplay struct {
	sink    ScreenSink
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	pending *screenstream.Message
	sending bool
	failed  chan error
	idle    chan struct{}
}

// The display does not end with the relay's context: an interrupted write closes a WebSocket, and
// the END that says why the session ended must still get through. close is what bounds it.
func newScreenDisplay(ctx context.Context, sink ScreenSink) *screenDisplay {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &screenDisplay{sink: sink, ctx: ctx, cancel: cancel, failed: make(chan error, 1)}
}

func (d *screenDisplay) offer(frame screenstream.Message) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sending {
		d.pending = &frame
		return
	}
	d.sending = true
	d.idle = make(chan struct{})
	go d.run(frame, d.idle)
}

func (d *screenDisplay) run(frame screenstream.Message, idle chan struct{}) {
	defer close(idle)
	for {
		if err := d.sink.Send(d.ctx, frame); err != nil {
			d.mu.Lock()
			d.sending, d.pending = false, nil
			d.mu.Unlock()
			select {
			case d.failed <- err:
			default:
			}
			return
		}
		d.mu.Lock()
		if d.pending == nil {
			d.sending = false
			d.mu.Unlock()
			return
		}
		frame = *d.pending
		d.pending = nil
		d.mu.Unlock()
	}
}

// close gives what is under way the time to reach the operator, then cuts it: END must follow the
// last frame on the wire, and a stalled browser must not hold up the end of a session.
func (d *screenDisplay) close(grace time.Duration) {
	d.mu.Lock()
	idle := d.idle
	d.mu.Unlock()
	if idle != nil {
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-idle:
		case <-timer.C:
		}
	}
	d.cancel()
	if idle != nil {
		<-idle
	}
}

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

// PointerDrawer is a ScreenSession that may draw the target's pointer into its frames (ADR-0091);
// the HELLO then tells the client, which hides its own pointer. A session that is not one draws none.
type PointerDrawer interface {
	PointerDrawn() bool
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
		return relayScreen(relayCtx, cleanupCtx, meta, cred, codec, recorder, sink, l.ScreenInput, l.ScreenAckTimeout)
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

// recordScreenFrame waits for the acknowledgement of one frame, for ackTimeout at most. The end of
// the session does not abandon it at once: the frame is on its way, and giving up now would leave a
// recording the terminal marker cannot call complete. It gets screenAckGrace more, no longer.
func recordScreenFrame(ctx context.Context, recorder FrameRecorder, sessionID string, frame screenstream.Message, ackTimeout time.Duration) (uint64, error) {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
		case <-recordCtx.Done():
			return
		}
		timer := time.NewTimer(screenAckGrace)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel()
		case <-recordCtx.Done():
		}
	}()
	return recorder.Record(recordCtx, sessionID, frame)
}

// screenContextEnd says why the session's context ended, in the terms END and the audit use.
func screenContextEnd(ctx context.Context) error {
	switch {
	case errors.Is(context.Cause(ctx), ErrSessionRevoked):
		return ErrSessionRevoked
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrSessionExpired
	}
	return ctx.Err()
}

func relayScreen(ctx, cleanupCtx context.Context, meta SessionMetadata, cred *Credential, codec ScreenCodec, recorder FrameRecorder, sink ScreenSink, limits ScreenInputLimits, ackTimeout time.Duration) (relayErr error) {
	if ackTimeout <= 0 {
		ackTimeout = DefaultScreenAckTimeout
	}
	session, err := codec.Open(ctx, cred)
	if err != nil {
		return err
	}
	lastAck := uint64(0)
	display := newScreenDisplay(ctx, sink)
	// Ending a session cuts the target at once (ADR-0018), even with an acknowledgement under way.
	// Once, and over before the relay returns: whoever comes second waits for the first.
	closeTarget := sync.OnceValue(session.Close)
	stopCut := context.AfterFunc(ctx, func() { _ = closeTarget() })
	defer stopCut()
	defer func() {
		if closeErr := closeTarget(); relayErr == nil && closeErr != nil {
			relayErr = closeErr
		}
		display.close(500 * time.Millisecond)
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
	budget := newScreenInputBudget(limits, time.Now())
	if frames == nil {
		return errors.New("proxycore: screen engine returned no frame stream")
	}
	sequence := uint64(1)
	hello := screenstream.Message{
		Type: screenstream.TypeHello, Sequence: 0, Timestamp: time.Now().UTC(),
		Protocol: meta.ScreenProtocol, ExpiresAt: meta.ExpiresAt, SessionID: meta.SessionID,
	}
	if drawer, ok := session.(PointerDrawer); ok {
		hello.PointerDrawn = drawer.PointerDrawn()
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
			return screenContextEnd(ctx)
		case incoming, ok := <-inputResults:
			if !ok || incoming.err != nil {
				return fmt.Errorf("proxycore: screen input transport closed")
			}
			event, err := screenstream.DecodeInput(incoming.data, frameWidth, frameHeight)
			if err != nil {
				return fmt.Errorf("%w: invalid operator input", ErrScreenInputInvalid)
			}
			switch budget.admit(event, time.Now()) {
			case screenInputCoalesce:
				continue
			case screenInputRefuse:
				return fmt.Errorf("%w: input beyond the session's budget", ErrScreenInputInvalid)
			}
			if err := session.Input(event); err != nil {
				return fmt.Errorf("%w: protocol engine rejected input", ErrScreenInputInvalid)
			}
		case err := <-display.failed:
			return err
		case frame, ok := <-frames:
			if !ok {
				// Ending the session closes the target, which closes this stream: that is the
				// session's end, whatever the target's side of it looks like.
				if ctx.Err() != nil {
					return screenContextEnd(ctx)
				}
				// A screen too large to record ends the session as a recording loss (ADR-0070):
				// said so to the operator, and audited as one.
				if err := session.Err(); errors.Is(err, screenstream.ErrFrameTooLarge) {
					return fmt.Errorf("%w: %w", ErrRecordingLost, err)
				}
				return session.Err()
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
			ack, err := recordScreenFrame(ctx, recorder, meta.SessionID, recordFrame, ackTimeout)
			if err != nil || ack != frame.Sequence {
				return fmt.Errorf("%w: frame acknowledgement missing or ambiguous", ErrRecordingLost)
			}
			lastAck = ack
			frameWidth, frameHeight = frame.Width, frame.Height
			// The frame is durable from here on, whatever becomes of the operator.
			display.offer(frame)
			sequence++
		}
	}
}

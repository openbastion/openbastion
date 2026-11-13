package proxycore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

type fakeScreenCodec struct {
	session  *fakeScreenSession
	opened   int
	cred     *Credential
	openedCh chan struct{}
	openErr  error
}

func (c *fakeScreenCodec) Open(_ context.Context, cred *Credential) (ScreenSession, error) {
	c.opened++
	c.cred = cred
	if c.openedCh != nil {
		close(c.openedCh)
	}
	if c.openErr != nil {
		return nil, c.openErr
	}
	return c.session, nil
}

type fakeScreenSession struct {
	frames chan screenstream.Message
	mu     sync.Mutex
	err    error
	closed bool
	inputs []screenstream.InputEvent
}

func newFakeScreenSession(frames ...screenstream.Message) *fakeScreenSession {
	ch := make(chan screenstream.Message, len(frames))
	for _, frame := range frames {
		ch <- frame
	}
	close(ch)
	return &fakeScreenSession{frames: ch}
}
func (s *fakeScreenSession) Frames() <-chan screenstream.Message { return s.frames }
func (s *fakeScreenSession) Input(e screenstream.InputEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputs = append(s.inputs, e)
	return nil
}
func (s *fakeScreenSession) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *fakeScreenSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type fakeScreenGate struct {
	err   error
	calls int
}

func (g *fakeScreenGate) Ready(context.Context) error { g.calls++; return g.err }

type fakeFrameRecorder struct {
	mu           sync.Mutex
	frames       []screenstream.Message
	acks         map[uint64]uint64
	err          error
	sealed       []uint64
	sealErr      error
	mutateRecord bool
}

func (r *fakeFrameRecorder) Record(_ context.Context, _ string, f screenstream.Message) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mutateRecord && len(f.PNG) > 8 {
		f.PNG[8] = 'X'
	}
	r.frames = append(r.frames, f)
	if r.err != nil {
		return 0, r.err
	}
	if ack, ok := r.acks[f.Sequence]; ok {
		return ack, nil
	}
	return f.Sequence, nil
}
func (r *fakeFrameRecorder) Seal(_ context.Context, _ string, seq uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sealed = append(r.sealed, seq)
	return r.sealErr
}

type fakeScreenSink struct {
	mu       sync.Mutex
	messages []screenstream.Message
	err      error
}

func (s *fakeScreenSink) Send(_ context.Context, m screenstream.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, m)
	return nil
}

func (s *fakeScreenSink) snapshot() []screenstream.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]screenstream.Message(nil), s.messages...)
}

type fakeInputScreenSink struct {
	fakeScreenSink
	input []byte
	read  chan struct{}
}

func (s *fakeInputScreenSink) ReceiveInput(ctx context.Context) ([]byte, error) {
	select {
	case s.read <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if s.input != nil {
		data := s.input
		s.input = nil
		return data, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func validScreenFrame(seq uint64) screenstream.Message {
	return screenstream.Message{Type: screenstream.TypeFrame, Sequence: seq, Timestamp: time.Unix(int64(seq), 0).UTC(), Width: 1, Height: 1, PNG: []byte("\x89PNG\r\n\x1a\nframe")}
}

func screenListener(vault VaultClient) (*Listener, *fakeAudit) {
	audit := &fakeAudit{}
	l := NewListener(NewCredentialFetcher(vault, "rdp-vnc-proxy"), NewTerminator(audit))
	// Screen admission is performed by the mandatory Video Recorder gate.
	l.Recording = RecordingConfig{Policy: RecordingBestEffort}
	return l, audit
}

func screenMeta() SessionMetadata {
	return SessionMetadata{SessionID: "screen-1", TargetHost: "target:5900", ScopeToken: "one-use", ScreenProtocol: screenstream.ProtocolVNC, ExpiresAt: time.Now().Add(time.Minute)}
}

func TestServeScreen_DecodesAndRelaysBoundedOperatorInput(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	frames := make(chan screenstream.Message)
	session := &fakeScreenSession{frames: frames}
	codec := &fakeScreenCodec{session: session}
	event := screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61}
	encoded, err := screenstream.EncodeInput(event)
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeInputScreenSink{input: encoded, read: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(context.Background(), screenMeta(), codec, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	}()
	select {
	case <-sink.read:
	case <-time.After(time.Second):
		t.Fatal("input source was not read")
	}
	deadline := time.Now().Add(time.Second)
	for {
		session.mu.Lock()
		n := len(session.inputs)
		session.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("valid key input was not relayed")
		}
		time.Sleep(time.Millisecond)
	}
	frames <- validScreenFrame(1)
	close(frames)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.inputs) != 1 || session.inputs[0] != event {
		t.Fatalf("inputs %#v, want %#v", session.inputs, event)
	}
}

func TestServeScreenSendsStableEndWhenCodecOpenFails(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	sink := &fakeScreenSink{}
	codec := &fakeScreenCodec{openErr: errors.New("target certificate rejected")}
	err := l.ServeScreen(context.Background(), screenMeta(), codec, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	if err == nil {
		t.Fatal("codec-open failure was hidden")
	}
	if len(sink.messages) != 1 || sink.messages[0].Type != screenstream.TypeEnd || sink.messages[0].Text != "target_unreachable" {
		t.Fatalf("terminal messages=%#v", sink.messages)
	}
}

func TestServeScreen_OnlyDisplaysDurablyAcknowledgedFrames(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	codec := &fakeScreenCodec{session: newFakeScreenSession(validScreenFrame(1), validScreenFrame(2))}
	recorder := &fakeFrameRecorder{mutateRecord: true}
	sink := &fakeScreenSink{}
	gate := &fakeScreenGate{}

	if err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, gate, sink); err != nil {
		t.Fatal(err)
	}
	if len(recorder.frames) != 2 || len(sink.messages) != 4 {
		t.Fatalf("recorded=%d sent=%d; want 2 recorded frames plus HELLO and END", len(recorder.frames), len(sink.messages))
	}
	if sink.messages[0].Type != screenstream.TypeHello || sink.messages[1].Sequence != 1 || sink.messages[2].Sequence != 2 || sink.messages[3].Type != screenstream.TypeEnd {
		t.Fatalf("unexpected stream: %#v", sink.messages)
	}
	if got := string(sink.messages[1].PNG[8:]); got != "frame" {
		t.Fatalf("recorder mutated the frame later sent to the operator: %q", got)
	}
	if !codec.session.closed {
		t.Fatal("target screen session was not closed")
	}
	if !reflect.DeepEqual(recorder.sealed, []uint64{2}) {
		t.Fatalf("sealed sequences %v, want [2]", recorder.sealed)
	}
	if len(audit.events) != 1 || audit.events[0] != "session.terminate" {
		t.Fatalf("audit events %v", audit.events)
	}
	if !codec.cred.Purged() {
		t.Fatal("credential not purged")
	}
}

func TestServeScreen_AmbiguousRecorderAcknowledgementNeverReachesOperator(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	codec := &fakeScreenCodec{session: newFakeScreenSession(validScreenFrame(1))}
	recorder := &fakeFrameRecorder{acks: map[uint64]uint64{1: 0}}
	sink := &fakeScreenSink{}

	err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, sink)
	if !errors.Is(err, ErrRecordingLost) {
		t.Fatalf("error = %v, want ErrRecordingLost", err)
	}
	if len(sink.messages) != 2 || sink.messages[0].Type != screenstream.TypeHello || sink.messages[1].Type != screenstream.TypeEnd {
		t.Fatalf("unacknowledged frame was sent or END missing: %#v", sink.messages)
	}
	if !reflect.DeepEqual(audit.events, []string{"session.recording_lost", "session.terminate"}) {
		t.Fatalf("audit events %v", audit.events)
	}
	if !codec.cred.Purged() {
		t.Fatal("credential not purged")
	}
	if !reflect.DeepEqual(recorder.sealed, []uint64{0}) {
		t.Fatalf("sealed %v, want [0]", recorder.sealed)
	}
}

func TestServeScreen_RecorderUnavailableRefusesBeforeFetchingCredential(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	codec := &fakeScreenCodec{session: newFakeScreenSession()}
	gate := &fakeScreenGate{err: errors.New("recorder offline")}

	meta := screenMeta()
	// An admission from another path must not bypass the Video Recorder gate.
	meta.Admission = Admission{sessionID: meta.SessionID, granted: true}
	err := l.ServeScreen(context.Background(), meta, codec, &fakeFrameRecorder{}, gate, &fakeScreenSink{})
	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if vault.calls != 0 || codec.opened != 0 {
		t.Fatalf("vault calls=%d codec opens=%d; expected zero", vault.calls, codec.opened)
	}
	if !reflect.DeepEqual(audit.events, []string{"session.recording_unavailable"}) {
		t.Fatalf("audit events %v", audit.events)
	}
}

func TestServeScreen_RejectsInvalidSequenceAndSealsLastAcknowledgedFrame(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	codec := &fakeScreenCodec{session: newFakeScreenSession(validScreenFrame(2))}
	recorder := &fakeFrameRecorder{}
	sink := &fakeScreenSink{}

	err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, sink)
	if !errors.Is(err, ErrScreenSequence) {
		t.Fatalf("error = %v, want ErrScreenSequence", err)
	}
	if len(recorder.frames) != 0 || len(sink.messages) != 2 || sink.messages[1].Type != screenstream.TypeEnd {
		t.Fatalf("recorded=%d sent=%d; malformed frame must not be recorded or sent and END must be sent", len(recorder.frames), len(sink.messages))
	}
	if !reflect.DeepEqual(recorder.sealed, []uint64{0}) {
		t.Fatalf("sealed %v, want [0]", recorder.sealed)
	}
}

func TestServeScreen_RevocationClosesTargetAndPurgesCredential(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	frames := make(chan screenstream.Message)
	session := &fakeScreenSession{frames: frames}
	codec := &fakeScreenCodec{session: session, openedCh: make(chan struct{})}
	recorder := &fakeFrameRecorder{}
	sink := &fakeScreenSink{}
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, sink)
	}()
	select {
	case <-codec.openedCh:
	case <-time.After(time.Second):
		t.Fatal("screen engine did not open")
	}
	rev := l.Live.Revoke("screen-1", time.Now().Add(time.Minute))
	if rev.Cut() != 1 || rev.Wait(time.Second) != 0 {
		t.Fatal("revocation did not finish the screen relay")
	}
	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("ServeScreen error = %v", err)
	}
	if !session.closed || !codec.cred.Purged() {
		t.Fatalf("closed=%v purged=%v", session.closed, codec.cred.Purged())
	}
	if !reflect.DeepEqual(recorder.sealed, []uint64{0}) {
		t.Fatalf("sealed %v", recorder.sealed)
	}
	if !reflect.DeepEqual(audit.events, []string{"session.revoked", "session.terminate"}) {
		t.Fatalf("audit events %v", audit.events)
	}
}

func TestServeScreen_SealFailureIsRecordingLoss(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	codec := &fakeScreenCodec{session: newFakeScreenSession()}
	recorder := &fakeFrameRecorder{sealErr: errors.New("terminal marker unavailable")}

	err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, &fakeScreenSink{})
	if !errors.Is(err, ErrRecordingLost) {
		t.Fatalf("error = %v, want ErrRecordingLost", err)
	}
	if !reflect.DeepEqual(audit.events, []string{"session.recording_lost", "session.terminate"}) {
		t.Fatalf("audit events %v", audit.events)
	}
	if !codec.cred.Purged() {
		t.Fatal("credential not purged after recorder seal failure")
	}
}

func TestServeScreen_NilFrameStreamStillSealsAndPurges(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	session := &fakeScreenSession{frames: nil}
	codec := &fakeScreenCodec{session: session}
	recorder := &fakeFrameRecorder{}

	err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, &fakeScreenSink{})
	if err == nil {
		t.Fatal("expected error for a nil frame stream")
	}
	if !session.closed || !codec.cred.Purged() {
		t.Fatalf("closed=%v purged=%v", session.closed, codec.cred.Purged())
	}
	if !reflect.DeepEqual(recorder.sealed, []uint64{0}) {
		t.Fatalf("sealed %v, want [0]", recorder.sealed)
	}
}

// The audit says that someone took a target's place, and that the secret stayed: the operator's
// END says pin_mismatch and nothing more (ADR-0071 §3).
func TestServeScreen_PinMismatchIsOnTheRecordAndTheCredentialPurged(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	codec := &fakeScreenCodec{openErr: &ScreenFailure{Code: "pin_mismatch", Err: errors.New("the leaf differs")}}
	sink := &fakeScreenSink{}
	if err := l.ServeScreen(context.Background(), screenMeta(), codec, &fakeFrameRecorder{}, &fakeScreenGate{}, sink); err == nil {
		t.Fatal("a mismatch was hidden")
	}
	if !reflect.DeepEqual(audit.events, []string{"session.tls_certificate_mismatch", "session.terminate"}) {
		t.Fatalf("audit events %v", audit.events)
	}
	if !codec.cred.Purged() {
		t.Fatal("credential not purged")
	}
	if last := sink.messages[len(sink.messages)-1]; last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodePinMismatch {
		t.Fatalf("END = %#v", last)
	}

	// Any other refusal says nothing of the kind.
	l2, audit2 := screenListener(&fakeVault{material: []byte("ephemeral-secret")})
	other := &fakeScreenCodec{openErr: &ScreenFailure{Code: "target_unreachable", Err: errors.New("no route")}}
	_ = l2.ServeScreen(context.Background(), screenMeta(), other, &fakeFrameRecorder{}, &fakeScreenGate{}, &fakeScreenSink{})
	if !reflect.DeepEqual(audit2.events, []string{"session.terminate"}) {
		t.Fatalf("audit events %v", audit2.events)
	}
}

func TestScreenInputBudget_CoalescesMovesAndRefusesTheRest(t *testing.T) {
	start := time.Unix(1000, 0)
	key := screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61}
	move := screenstream.InputEvent{Type: screenstream.InputPointer, X: 1, Y: 1}
	press := screenstream.InputEvent{Type: screenstream.InputPointer, X: 1, Y: 1, Buttons: 1}
	wheel := screenstream.InputEvent{Type: screenstream.InputPointer, X: 1, Y: 1, Wheel: 1}

	b := newScreenInputBudget(ScreenInputLimits{RatePerSecond: 10, Burst: 2}, start)
	for i := 0; i < 2; i++ {
		if got := b.admit(move, start); got != screenInputForward {
			t.Fatalf("event %d within the burst: %v", i, got)
		}
	}
	if got := b.admit(move, start); got != screenInputCoalesce {
		t.Fatalf("a move beyond the burst: %v", got)
	}
	for name, e := range map[string]screenstream.InputEvent{"key": key, "press": press, "release-all": {Type: screenstream.InputReleaseAll}} {
		fresh := newScreenInputBudget(ScreenInputLimits{RatePerSecond: 10, Burst: 1}, start)
		fresh.admit(move, start)
		if got := fresh.admit(e, start); got != screenInputRefuse {
			t.Errorf("%s beyond the burst: %v", name, got)
		}
	}
	fresh := newScreenInputBudget(ScreenInputLimits{RatePerSecond: 10, Burst: 1}, start)
	fresh.admit(move, start)
	if got := fresh.admit(wheel, start); got != screenInputRefuse {
		t.Errorf("a wheel notch is not a move: %v", got)
	}
	// Tokens come back with time, up to the burst and no further.
	if got := b.admit(key, start.Add(100*time.Millisecond)); got != screenInputForward {
		t.Fatalf("after the refill: %v", got)
	}
	b.admit(move, start.Add(time.Hour))
	if b.tokens > b.burst {
		t.Fatalf("tokens %v above the burst", b.tokens)
	}
	if d := newScreenInputBudget(ScreenInputLimits{}, start); d.rate != DefaultScreenInputRate || d.burst != DefaultScreenInputBurst {
		t.Fatalf("defaults %v/%v", d.rate, d.burst)
	}
}

// Flooding keys closes the session with input_invalid, before more of them reach the target.
func TestServeScreen_KeyFloodClosesTheSession(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	l.ScreenInput = ScreenInputLimits{RatePerSecond: 1, Burst: 3}
	frames := make(chan screenstream.Message)
	session := &fakeScreenSession{frames: frames}
	encoded, err := screenstream.EncodeInput(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61})
	if err != nil {
		t.Fatal(err)
	}
	sink := &floodSink{event: encoded}
	err = l.ServeScreen(context.Background(), screenMeta(), &fakeScreenCodec{session: session}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	if !errors.Is(err, ErrScreenInputInvalid) {
		t.Fatalf("error = %v, want ErrScreenInputInvalid", err)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.inputs) != 3 {
		t.Fatalf("%d events reached the target, want the burst of 3", len(session.inputs))
	}
	if last := sink.messages[len(sink.messages)-1]; last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodeInputInvalid {
		t.Fatalf("END = %#v", last)
	}
}

type floodSink struct {
	fakeScreenSink
	event []byte
}

func (s *floodSink) ReceiveInput(context.Context) ([]byte, error) { return s.event, nil }

// A browser that stops reading holds up neither the recording nor the input. What it finally
// shows is the latest acknowledged frame, and revocation does not wait for it.
func TestServeScreen_StalledOperatorHoldsUpNeitherTheRecordingNorTheEnd(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	frames := make(chan screenstream.Message)
	session := &fakeScreenSession{frames: frames}
	recorder := &fakeFrameRecorder{}
	sink := newStallingSink()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(ctx, screenMeta(), &fakeScreenCodec{session: session}, recorder, &fakeScreenGate{}, sink)
	}()
	for seq := uint64(1); seq <= 5; seq++ {
		select {
		case frames <- validScreenFrame(seq):
		case <-time.After(2 * time.Second):
			t.Fatalf("frame %d was not taken: a stalled operator held up the recording", seq)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		recorder.mu.Lock()
		n := len(recorder.frames)
		recorder.mu.Unlock()
		if n == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d frames recorded, want all 5", n)
		}
		time.Sleep(time.Millisecond)
	}
	// The operator comes back: frame 1 was under way, and only the latest of the others follows.
	close(sink.release)
	deadline = time.Now().Add(2 * time.Second)
	for sink.frameCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("frames sent: %v", sink.frameSequences())
		}
		time.Sleep(time.Millisecond)
	}
	close(frames)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Frame 1 was under way, 5 is the latest. In between, at most the frame the relay was
	// recording when the operator came back.
	if got := sink.frameSequences(); got[0] != 1 || got[len(got)-1] != 5 || len(got) > 3 {
		t.Fatalf("frames shown %v, want 1, then the latest", got)
	}
	last := sink.sent[len(sink.sent)-1]
	if last.Type != screenstream.TypeEnd || last.Sequence != 6 {
		t.Fatalf("END = %#v, want the sequence after the last acknowledged frame", last)
	}
}

// A recorder that says nothing is a lost recording, now, not a session that waits for its
// deadline with nothing recorded and nothing shown.
func TestServeScreen_RecorderSilenceIsARecordingLoss(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	l.ScreenAckTimeout = 30 * time.Millisecond
	frames := make(chan screenstream.Message, 1)
	frames <- validScreenFrame(1)
	session := &fakeScreenSession{frames: frames}
	sink := &fakeScreenSink{}
	err := l.ServeScreen(context.Background(), screenMeta(), &fakeScreenCodec{session: session}, silentRecorder{}, &fakeScreenGate{}, sink)
	if !errors.Is(err, ErrRecordingLost) {
		t.Fatalf("error = %v, want ErrRecordingLost", err)
	}
	if !session.closed {
		t.Fatal("target not closed")
	}
	if !slices.Contains(audit.events, "session.recording_lost") {
		t.Fatalf("audit events %v", audit.events)
	}
	for _, m := range sink.messages {
		if m.Type == screenstream.TypeFrame {
			t.Fatal("a frame nobody acknowledged reached the operator")
		}
	}
}

type silentRecorder struct{}

func (silentRecorder) Record(ctx context.Context, _ string, _ screenstream.Message) (uint64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}
func (silentRecorder) Seal(context.Context, string, uint64) error { return nil }

func TestServeScreen_EndIsNotHeldUpByAFrameThatNeverLeaves(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	sink := newStallingSink()
	session := newFakeScreenSession(validScreenFrame(1))
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(context.Background(), screenMeta(), &fakeScreenCodec{session: session}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the end of the session waited for a stalled operator")
	}
	if !session.closed {
		t.Fatal("target not closed")
	}
}

type stallingSink struct {
	mu      sync.Mutex
	sent    []screenstream.Message
	started int
	release chan struct{}
}

func (s *stallingSink) frameStarted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

func newStallingSink() *stallingSink { return &stallingSink{release: make(chan struct{})} }

// Send holds every frame until release, as a socket whose peer stopped reading does.
func (s *stallingSink) Send(ctx context.Context, m screenstream.Message) error {
	if m.Type == screenstream.TypeFrame {
		s.mu.Lock()
		s.started++
		s.mu.Unlock()
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m)
	return nil
}

func (s *stallingSink) frameSequences() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []uint64
	for _, m := range s.sent {
		if m.Type == screenstream.TypeFrame {
			out = append(out, m.Sequence)
		}
	}
	return out
}

func (s *stallingSink) frameCount() int { return len(s.frameSequences()) }

// Revocation lands while a frame is on its way: the frame finishes, on a context that does not
// end with the session, and END follows. An interrupted write would close the socket before END.
func TestServeScreen_RevocationLetsTheFrameUnderWayFinishThenSaysWhy(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	frames := make(chan screenstream.Message)
	session := &fakeScreenSession{frames: frames}
	sink := newStallingSink()
	meta := screenMeta()
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(context.Background(), meta, &fakeScreenCodec{session: session}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	}()
	frames <- validScreenFrame(1)
	deadline := time.Now().Add(2 * time.Second)
	for sink.frameStarted() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the frame never left")
		}
		time.Sleep(time.Millisecond)
	}
	revocation := l.Live.Revoke(meta.SessionID, time.Now().Add(time.Minute))
	revocation.Cut()
	time.Sleep(50 * time.Millisecond)
	close(sink.release)
	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("error = %v, want ErrSessionRevoked", err)
	}
	if got := sink.frameSequences(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the frame under way was cut: %v", got)
	}
	last := sink.sent[len(sink.sent)-1]
	if last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodeSessionRevoked {
		t.Fatalf("END = %#v", last)
	}
}

// Revocation lands while the recorder is about to acknowledge a frame already sent. The target is
// cut at once, the acknowledgement is still awaited, and the terminal marker covers the frame: a
// recording cut this way is complete, and END says revoked, not lost.
func TestServeScreen_RevocationDuringAnAcknowledgementCutsTheTargetAndKeepsTheRecordingWhole(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	frames := make(chan screenstream.Message, 1)
	frames <- validScreenFrame(1)
	session := &fakeScreenSession{frames: frames}
	recorder := &slowAckRecorder{received: make(chan struct{}), release: make(chan struct{})}
	sink := &fakeScreenSink{}
	meta := screenMeta()
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(context.Background(), meta, &fakeScreenCodec{session: session}, recorder, &fakeScreenGate{}, sink)
	}()
	<-recorder.received
	l.Live.Revoke(meta.SessionID, time.Now().Add(time.Minute)).Cut()
	deadline := time.Now().Add(time.Second)
	for {
		session.mu.Lock()
		closed := session.closed
		session.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the target stayed open while the acknowledgement was awaited")
		}
		time.Sleep(time.Millisecond)
	}
	close(recorder.release)
	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("error = %v, want ErrSessionRevoked", err)
	}
	if !reflect.DeepEqual(recorder.sealed, []uint64{1}) {
		t.Fatalf("sealed through %v, want the frame under way", recorder.sealed)
	}
	last := sink.messages[len(sink.messages)-1]
	if last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodeSessionRevoked {
		t.Fatalf("END = %#v, want session_revoked", last)
	}
	if slices.Contains(audit.events, "session.recording_lost") {
		t.Fatalf("audit events %v", audit.events)
	}
}

// A recorder that never answers does not hold up a revoked session beyond the grace.
func TestServeScreen_RevocationGivesASilentRecorderOnlyTheGrace(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := screenListener(vault)
	frames := make(chan screenstream.Message, 1)
	frames <- validScreenFrame(1)
	session := &fakeScreenSession{frames: frames}
	meta := screenMeta()
	received := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.ServeScreen(context.Background(), meta, &fakeScreenCodec{session: session}, silentAfterReceipt{received}, &fakeScreenGate{}, &fakeScreenSink{})
	}()
	<-received
	start := time.Now()
	l.Live.Revoke(meta.SessionID, time.Now().Add(time.Minute)).Cut()
	select {
	case <-done:
		if waited := time.Since(start); waited > screenAckGrace+time.Second {
			t.Fatalf("the relay took %v to end", waited)
		}
	case <-time.After(screenAckGrace + 5*time.Second):
		t.Fatal("a silent recorder held up a revoked session")
	}
}

type silentAfterReceipt struct{ received chan struct{} }

func (r silentAfterReceipt) Record(ctx context.Context, _ string, _ screenstream.Message) (uint64, error) {
	close(r.received)
	<-ctx.Done()
	return 0, ctx.Err()
}
func (silentAfterReceipt) Seal(context.Context, string, uint64) error { return nil }

type slowAckRecorder struct {
	received chan struct{}
	release  chan struct{}
	sealed   []uint64
}

func (r *slowAckRecorder) Record(ctx context.Context, _ string, f screenstream.Message) (uint64, error) {
	close(r.received)
	select {
	case <-r.release:
		return f.Sequence, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (r *slowAckRecorder) Seal(_ context.Context, _ string, seq uint64) error {
	r.sealed = append(r.sealed, seq)
	return nil
}

// Ending a session closes the target, which closes the frame stream: the relay can wake to either,
// and picks at random when both are ready. Both are ready here, every time. Whichever it picks, a
// revoked session says revoked, and an expired one expired.
func TestRelayScreen_ClosedStreamDoesNotHideWhyTheSessionEnded(t *testing.T) {
	for name, want := range map[string]struct {
		end func() (context.Context, context.CancelFunc)
		err error
		tag uint16
	}{
		"revoked": {func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(ErrSessionRevoked)
			return ctx, func() {}
		}, ErrSessionRevoked, screenstream.EndCodeSessionRevoked},
		"expired": {func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, ErrSessionExpired, screenstream.EndCodeSessionExpired},
	} {
		for i := 0; i < 64; i++ {
			frames := make(chan screenstream.Message)
			close(frames)
			session := &fakeScreenSession{frames: frames}
			sink := &fakeScreenSink{}
			ctx, cancel := want.end()
			err := relayScreen(ctx, context.Background(), screenMeta(), nil, &fakeScreenCodec{session: session}, &fakeFrameRecorder{}, sink, ScreenInputLimits{}, time.Second, nil)
			cancel()
			if !errors.Is(err, want.err) {
				t.Fatalf("%s: error = %v", name, err)
			}
			if last := sink.messages[len(sink.messages)-1]; last.Type != screenstream.TypeEnd || last.EndCode != want.tag {
				t.Fatalf("%s: END = %#v", name, last)
			}
		}
	}
}

// The deadline of a session: the operator is told it expired, the audit too, and the context the
// audit and the purge run on is still alive.
func TestServeScreen_ExpiryIsSaidAndAudited(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	session := &closingScreenSession{fakeScreenSession: fakeScreenSession{frames: make(chan screenstream.Message)}}
	sink := &fakeScreenSink{}
	meta := screenMeta()
	meta.ExpiresAt = time.Now().Add(30 * time.Millisecond)
	opened := make(chan struct{})
	codec := openedCodec{session: session, opened: opened}
	err := l.ServeScreen(context.Background(), meta, codec, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("error = %v, want ErrSessionExpired", err)
	}
	last := sink.messages[len(sink.messages)-1]
	if last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodeSessionExpired {
		t.Fatalf("END = %#v, want session_expired", last)
	}
	if !slices.Contains(audit.events, "session.expire") || !slices.Contains(audit.events, "session.terminate") {
		t.Fatalf("audit events %v", audit.events)
	}
}

// closingScreenSession closes its frame stream on Close, as a real target's reader does.
type closingScreenSession struct {
	fakeScreenSession
	once sync.Once
}

func (s *closingScreenSession) Close() error {
	s.once.Do(func() { close(s.frames) })
	return s.fakeScreenSession.Close()
}

type openedCodec struct {
	session ScreenSession
	opened  chan struct{}
}

func (c openedCodec) Open(context.Context, *Credential) (ScreenSession, error) {
	close(c.opened)
	return c.session, nil
}

// A screen past 4 MiB cannot be recorded (ADR-0070): the session ends as a recording loss, said to
// the operator and audited, whatever engine found it out (ADR-0071 §8).
func TestServeScreen_AFrameBeyondTheRecordableSizeIsARecordingLoss(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	session := newFakeScreenSession()
	session.err = fmt.Errorf("rdp: invalid framebuffer update: %w", screenstream.ErrFrameTooLarge)
	sink := &fakeScreenSink{}
	err := l.ServeScreen(context.Background(), screenMeta(), &fakeScreenCodec{session: session}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	if !errors.Is(err, ErrRecordingLost) {
		t.Fatalf("error = %v, want ErrRecordingLost", err)
	}
	if last := sink.messages[len(sink.messages)-1]; last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodeRecordingLost {
		t.Fatalf("END = %#v, want recording_lost", last)
	}
	if !reflect.DeepEqual(audit.events, []string{"session.recording_lost", "session.terminate"}) {
		t.Fatalf("audit events %v", audit.events)
	}
}

// drawingScreenSession is a session that says whether it draws the pointer (ADR-0091).
type drawingScreenSession struct {
	*fakeScreenSession
	drawn bool
}

func (s drawingScreenSession) PointerDrawn() bool { return s.drawn }

type drawingScreenCodec struct{ session ScreenSession }

func (c drawingScreenCodec) Open(context.Context, *Credential) (ScreenSession, error) {
	return c.session, nil
}

// The HELLO says what the session says: the pointer is in the frames, or it is not; a session that
// says nothing draws none.
func TestServeScreen_TheHelloSaysWhetherThePointerIsDrawn(t *testing.T) {
	for name, c := range map[string]struct {
		session ScreenSession
		want    bool
	}{
		"drawn":     {drawingScreenSession{newFakeScreenSession(validScreenFrame(1)), true}, true},
		"not drawn": {drawingScreenSession{newFakeScreenSession(validScreenFrame(1)), false}, false},
		"silent":    {newFakeScreenSession(validScreenFrame(1)), false},
	} {
		l, _ := screenListener(&fakeVault{material: []byte("ephemeral-secret")})
		sink := &fakeScreenSink{}
		if err := l.ServeScreen(context.Background(), screenMeta(), drawingScreenCodec{c.session}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(sink.messages) == 0 || sink.messages[0].Type != screenstream.TypeHello || sink.messages[0].PointerDrawn != c.want {
			t.Fatalf("%s: HELLO %+v, want PointerDrawn %v", name, sink.messages, c.want)
		}
	}
}

func validDeltaFrame(seq uint64, w, h uint32) screenstream.Message {
	return screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: seq, Timestamp: time.Unix(int64(seq), 0).UTC(), Width: w, Height: h,
		Rects: []screenstream.Rect{{Width: 1, Height: 1, PNG: []byte("\x89PNG\r\n\x1a\nrect")}}}
}

// Partial frames go through the relay as key frames do, recorded before shown (ADR-0092); the
// Recorder gets its own copy of their rectangles. A partial frame first, or of another size than the
// screen it changes, ends the session.
func TestServeScreen_RelaysPartialFramesOnTheirScreen(t *testing.T) {
	recorder := &fakeFrameRecorder{mutateRecord: true}
	sink := &fakeScreenSink{}
	l, _ := screenListener(&fakeVault{material: []byte("ephemeral-secret")})
	codec := &fakeScreenCodec{session: newFakeScreenSession(validScreenFrame(1), validDeltaFrame(2, 1, 1))}
	if err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, sink); err != nil {
		t.Fatal(err)
	}
	if len(recorder.frames) != 2 || recorder.frames[1].Type != screenstream.TypeFrameDelta ||
		len(sink.messages) != 4 || sink.messages[2].Type != screenstream.TypeFrameDelta {
		t.Fatalf("recorded %d, shown %+v", len(recorder.frames), sink.messages)
	}
	// The recorder wrote into its copy of the rectangle; the operator's is untouched.
	recorder.frames[1].Rects[0].PNG[8] = 'X'
	if string(sink.messages[2].Rects[0].PNG[8:]) != "rect" {
		t.Fatal("the recorder shares the rectangles shown to the operator")
	}

	for name, frames := range map[string][]screenstream.Message{
		"a partial frame first":           {validDeltaFrame(1, 1, 1)},
		"of another size than its screen": {validScreenFrame(1), validDeltaFrame(2, 2, 1)},
	} {
		recorder := &fakeFrameRecorder{}
		codec := &fakeScreenCodec{session: newFakeScreenSession(frames...)}
		l, _ := screenListener(&fakeVault{material: []byte("ephemeral-secret")})
		if err := l.ServeScreen(context.Background(), screenMeta(), codec, recorder, &fakeScreenGate{}, &fakeScreenSink{}); !errors.Is(err, ErrScreenSequence) {
			t.Errorf("%s: %v, want ErrScreenSequence", name, err)
		}
		for _, f := range recorder.frames {
			if f.Type == screenstream.TypeFrameDelta {
				t.Errorf("%s: the partial frame was recorded", name)
			}
		}
	}
}

// resizingScreenSession is a session that says whether it follows InputResize (ADR-0095).
type resizingScreenSession struct {
	*fakeScreenSession
	resizable bool
}

func (s resizingScreenSession) Resizable() bool { return s.resizable }

// scriptedInputSink gives the relay the inputs of script, each when the test sends on next.
type scriptedInputSink struct {
	fakeScreenSink
	next chan []byte
}

func (s *scriptedInputSink) ReceiveInput(ctx context.Context) ([]byte, error) {
	select {
	case data := <-s.next:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func resizeInput(t *testing.T, w, h uint16) []byte {
	t.Helper()
	raw, err := screenstream.EncodeInput(screenstream.InputEvent{Type: screenstream.InputResize, X: w, Y: h})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (s *fakeScreenSession) snapshotInputs() []screenstream.InputEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]screenstream.InputEvent(nil), s.inputs...)
}

// serveResizing runs a session that stays open, gives it the inputs, waits, and returns what the
// session received.
func serveResizing(t *testing.T, resizable bool, limits ScreenInputLimits, wait time.Duration, inputs ...[]byte) ([]screenstream.InputEvent, []screenstream.Message, error) {
	t.Helper()
	l, _ := screenListener(&fakeVault{material: []byte("ephemeral-secret")})
	l.ScreenInput = limits
	session := &fakeScreenSession{frames: make(chan screenstream.Message)}
	sink := &scriptedInputSink{next: make(chan []byte)}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- l.ServeScreen(ctx, screenMeta(), drawingScreenCodec{resizingScreenSession{session, resizable}}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink)
	}()
	for _, input := range inputs {
		select {
		case sink.next <- input:
		case err := <-served:
			cancel()
			return session.snapshotInputs(), sink.snapshot(), err
		}
	}
	time.Sleep(wait)
	cancel()
	err := <-served
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return session.snapshotInputs(), sink.snapshot(), err
}

func TestServeScreen_TheHelloSaysWhetherTheSessionResizes(t *testing.T) {
	for name, c := range map[string]struct {
		session ScreenSession
		want    bool
	}{
		"resizable":     {resizingScreenSession{newFakeScreenSession(validScreenFrame(1)), true}, true},
		"not resizable": {resizingScreenSession{newFakeScreenSession(validScreenFrame(1)), false}, false},
		"silent":        {newFakeScreenSession(validScreenFrame(1)), false},
	} {
		l, _ := screenListener(&fakeVault{material: []byte("ephemeral-secret")})
		sink := &fakeScreenSink{}
		if err := l.ServeScreen(context.Background(), screenMeta(), drawingScreenCodec{c.session}, &fakeFrameRecorder{}, &fakeScreenGate{}, sink); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(sink.messages) == 0 || sink.messages[0].Resizable != c.want {
			t.Fatalf("%s: HELLO %+v, want Resizable %v", name, sink.messages, c.want)
		}
	}
}

func TestServeScreen_ASessionThatCannotResizeReceivesNone(t *testing.T) {
	inputs, _, err := serveResizing(t, false, ScreenInputLimits{}, 100*time.Millisecond, resizeInput(t, 1920, 1080))
	if err != nil || len(inputs) != 0 {
		t.Fatalf("inputs %+v, %v: want none, and the session going on", inputs, err)
	}
}

func TestServeScreen_AResizeIsBroughtWithinTheBounds(t *testing.T) {
	inputs, _, err := serveResizing(t, true, ScreenInputLimits{}, 100*time.Millisecond, resizeInput(t, 9001, 100))
	if err != nil || len(inputs) != 1 || inputs[0].X != screenstream.MaxResizeWidth || inputs[0].Y != screenstream.MinResizeHeight {
		t.Fatalf("inputs %+v, %v: want one resize of %d x %d", inputs, err, screenstream.MaxResizeWidth, screenstream.MinResizeHeight)
	}
}

// One resize a second: the first goes at once, those that follow sooner wait, and only the latest
// of them goes, once its turn comes.
func TestServeScreen_ResizesArePacedAndOnlyTheLatestWaits(t *testing.T) {
	start := time.Now()
	inputs, _, err := serveResizing(t, true, ScreenInputLimits{}, MinResizeInterval+300*time.Millisecond,
		resizeInput(t, 1024, 768), resizeInput(t, 1280, 800), resizeInput(t, 1920, 1080))
	if err != nil || len(inputs) != 2 || inputs[0].X != 1024 || inputs[1].X != 1920 || inputs[1].Y != 1080 {
		t.Fatalf("inputs %+v, %v: want 1024 x 768 then 1920 x 1080 alone", inputs, err)
	}
	if time.Since(start) < MinResizeInterval {
		t.Fatal("the second resize went before its turn")
	}
	inputs, _, _ = serveResizing(t, true, ScreenInputLimits{}, MinResizeInterval/2,
		resizeInput(t, 1024, 768), resizeInput(t, 1920, 1080))
	if len(inputs) != 1 {
		t.Fatalf("%d resizes within half a second, want 1", len(inputs))
	}
}

// The resizes are paced on their own, out of the input budget: a budget of one does not refuse them.
func TestServeScreen_ResizesAreOutOfTheInputBudget(t *testing.T) {
	inputs, _, err := serveResizing(t, true, ScreenInputLimits{RatePerSecond: 1, Burst: 1}, 50*time.Millisecond,
		resizeInput(t, 1024, 768), resizeInput(t, 1280, 800), resizeInput(t, 1920, 1080), resizeInput(t, 1600, 900))
	if err != nil || len(inputs) != 1 {
		t.Fatalf("inputs %+v, %v: want the first resize forwarded and the session going on", inputs, err)
	}
}

// A target that refuses the account's credentials (ADR-0071 §12): the operator's END says
// target_auth_failed, the audit names it for whoever keeps the Vault, and the credential is purged.
func TestServeScreen_ATargetRefusingTheCredentialsIsSaidAndAudited(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := screenListener(vault)
	codec := &fakeScreenCodec{openErr: &ScreenFailure{Code: "target_auth_failed", Err: errors.New("NTSTATUS 0xC000006D")}}
	sink := &fakeScreenSink{}
	if err := l.ServeScreen(context.Background(), screenMeta(), codec, &fakeFrameRecorder{}, &fakeScreenGate{}, sink); err == nil {
		t.Fatal("a refusal was hidden")
	}
	if !reflect.DeepEqual(audit.events, []string{"session.target_auth_failed", "session.terminate"}) {
		t.Fatalf("audit events %v", audit.events)
	}
	if !codec.cred.Purged() {
		t.Fatal("credential not purged")
	}
	if last := sink.messages[len(sink.messages)-1]; last.Type != screenstream.TypeEnd || last.EndCode != screenstream.EndCodeTargetAuthFailed || last.Text != "target_auth_failed" {
		t.Fatalf("END = %#v", last)
	}
}

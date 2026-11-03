package proxycore

import (
	"context"
	"errors"
	"reflect"
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

package proxycore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The clipboard's transfers (ADR-0096, increment 3b): bounded, audited, recorded and acknowledged,
// then delivered; refused, they move nothing and the session goes on.

type clipboardSteps struct {
	mu    sync.Mutex
	steps []string
}

func (s *clipboardSteps) add(step string) {
	s.mu.Lock()
	s.steps = append(s.steps, step)
	s.mu.Unlock()
}
func (s *clipboardSteps) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.steps...)
}

type fakeClipboardAudit struct {
	steps       *clipboardSteps
	mu          sync.Mutex
	events      []ClipboardEvent
	failSuccess bool
}

func (a *fakeClipboardAudit) EmitClipboard(_ context.Context, sessionID string, event ClipboardEvent) error {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
	if a.steps != nil {
		a.steps.add("audit:" + map[bool]string{true: "ok", false: "refused:" + event.Reason}[event.Success])
	}
	if event.Success && a.failSuccess {
		return errors.New("audit down")
	}
	return nil
}

func (a *fakeClipboardAudit) snapshot() []ClipboardEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]ClipboardEvent(nil), a.events...)
}

type stepRecorder struct {
	fakeFrameRecorder
	steps *clipboardSteps
}

func (r *stepRecorder) Record(ctx context.Context, id string, f screenstream.Message) (uint64, error) {
	if r.steps != nil {
		r.steps.add("record")
	}
	return r.fakeFrameRecorder.Record(ctx, id, f)
}

type clipboardScreenSession struct {
	fakeScreenSession
	texts    chan string
	steps    *clipboardSteps
	offered  []string
	offerErr error
}

func (s *clipboardScreenSession) ClipboardTexts() <-chan string { return s.texts }
func (s *clipboardScreenSession) OfferClipboardText(text string) error {
	s.mu.Lock()
	s.offered = append(s.offered, text)
	s.mu.Unlock()
	if s.steps != nil {
		s.steps.add("offer")
	}
	return s.offerErr
}

func newClipboardRelay(steps *clipboardSteps) (*clipboardRelay, *fakeClipboardAudit, *stepRecorder, *clipboardScreenSession) {
	audit := &fakeClipboardAudit{steps: steps}
	recorder := &stepRecorder{steps: steps}
	session := &clipboardScreenSession{steps: steps}
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	return &clipboardRelay{sessionID: "screen-1", audit: audit, recorder: recorder, session: session, ackTimeout: time.Second,
		now: func() time.Time { return at }}, audit, recorder, session
}

// A text pasted: audited (direction, size and hash, never the text), recorded and acknowledged, and
// only then offered to the target.
func TestClipboardTransfer_AuditedThenRecordedThenDelivered(t *testing.T) {
	steps := &clipboardSteps{}
	relay, audit, recorder, session := newClipboardRelay(steps)
	text := "pasted é €"
	message, moved, err := relay.transfer(context.Background(), screenstream.ClipboardToTarget, text, 5)
	if err != nil || !moved {
		t.Fatalf("transfer: %v %v", moved, err)
	}
	if got := strings.Join(steps.all(), ","); got != "audit:ok,record,offer" {
		t.Fatalf("steps %s, want audit, record, then offer", got)
	}
	sum := sha256.Sum256([]byte(text))
	events := audit.snapshot()
	if len(events) != 1 || events[0].Direction != screenstream.ClipboardToTarget || events[0].Bytes != len(text) ||
		events[0].SHA256 != hex.EncodeToString(sum[:]) || !events[0].Success {
		t.Fatalf("audit %+v", events)
	}
	details := ClipboardDetails(events[0])
	for _, v := range details {
		if strings.Contains(v, "pasted") {
			t.Fatalf("the audit details hold the text: %v", details)
		}
	}
	if details["direction"] != "to-target" || details["bytes"] != "13" || len(details) != 3 {
		t.Fatalf("details %v", details)
	}
	if len(recorder.frames) != 1 || recorder.frames[0].Type != screenstream.TypeClipboard || recorder.frames[0].Sequence != 5 ||
		recorder.frames[0].ClipboardText != text || recorder.frames[0].Direction != screenstream.ClipboardToTarget {
		t.Fatalf("recorded %+v", recorder.frames)
	}
	if len(session.offered) != 1 || session.offered[0] != text || message.Sequence != 5 || message.ClipboardText != text {
		t.Fatalf("offered %q, shown %+v", session.offered, message)
	}
	// Copied from the target: the same, but nothing is offered to the target.
	steps2 := &clipboardSteps{}
	relay2, _, _, session2 := newClipboardRelay(steps2)
	if _, moved, err := relay2.transfer(context.Background(), screenstream.ClipboardFromTarget, "copied", 1); err != nil || !moved {
		t.Fatalf("from the target: %v %v", moved, err)
	}
	if got := strings.Join(steps2.all(), ","); got != "audit:ok,record" || len(session2.offered) != 0 {
		t.Fatalf("from the target: steps %s, offered %q", got, session2.offered)
	}
}

// Without its audit event, a transfer does not happen: nothing recorded, nothing offered, the
// refusal audited (best effort), and the session goes on.
func TestClipboardTransfer_RefusedWithoutItsAudit(t *testing.T) {
	steps := &clipboardSteps{}
	relay, audit, recorder, session := newClipboardRelay(steps)
	audit.failSuccess = true
	_, moved, err := relay.transfer(context.Background(), screenstream.ClipboardToTarget, "pasted", 1)
	if err != nil || moved {
		t.Fatalf("transfer with the audit down: moved %v, %v", moved, err)
	}
	if got := strings.Join(steps.all(), ","); got != "audit:ok,audit:refused:"+ClipboardRefusedAudit {
		t.Fatalf("steps %s", got)
	}
	if len(recorder.frames) != 0 || len(session.offered) != 0 {
		t.Fatalf("recorded %d, offered %d", len(recorder.frames), len(session.offered))
	}
}

// Ten transfers a minute, both directions together; the eleventh is refused and audited as such,
// and a minute later a transfer passes again.
func TestClipboardTransfer_TenAMinute(t *testing.T) {
	relay, audit, recorder, _ := newClipboardRelay(nil)
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	relay.now = func() time.Time { return at }
	for i := 0; i < MaxClipboardTransfersPerMinute; i++ {
		direction := screenstream.ClipboardDirection(1 + i%2)
		if _, moved, err := relay.transfer(context.Background(), direction, "t", uint64(i+1)); err != nil || !moved {
			t.Fatalf("transfer %d: %v %v", i+1, moved, err)
		}
		at = at.Add(time.Second)
	}
	if _, moved, err := relay.transfer(context.Background(), screenstream.ClipboardFromTarget, "t", 11); err != nil || moved {
		t.Fatalf("the eleventh: moved %v, %v", moved, err)
	}
	events := audit.snapshot()
	if last := events[len(events)-1]; last.Success || last.Reason != ClipboardRefusedRate {
		t.Fatalf("the refusal was audited as %+v", last)
	}
	if len(recorder.frames) != MaxClipboardTransfersPerMinute {
		t.Fatalf("%d recorded", len(recorder.frames))
	}
	at = at.Add(51 * time.Second) // the first one is now a minute old
	if _, moved, err := relay.transfer(context.Background(), screenstream.ClipboardFromTarget, "t", 11); err != nil || !moved {
		t.Fatalf("a minute later: moved %v, %v", moved, err)
	}
}

// A text the contract does not carry is refused before anything else, and audited as invalid.
func TestClipboardTransfer_RefusesWhatTheContractDoesNot(t *testing.T) {
	for name, text := range map[string]string{
		"a NUL":          "a\x00b",
		"broken UTF-8":   "a\xffb",
		"past the bound": strings.Repeat("a", screenstream.MaxClipboardTextUnits+1),
	} {
		relay, audit, recorder, session := newClipboardRelay(nil)
		if _, moved, err := relay.transfer(context.Background(), screenstream.ClipboardToTarget, text, 1); err != nil || moved {
			t.Fatalf("%s: moved %v, %v", name, moved, err)
		}
		events := audit.snapshot()
		if len(events) != 1 || events[0].Success || events[0].Reason != ClipboardRefusedInvalid || len(recorder.frames) != 0 || len(session.offered) != 0 {
			t.Fatalf("%s: audit %+v, recorded %d, offered %d", name, events, len(recorder.frames), len(session.offered))
		}
	}
}

// A transfer whose recording is not acknowledged, or acknowledged as another sequence, is a
// recording lost: the session ends, and nothing is offered to the target.
func TestClipboardTransfer_AnUnrecordedTransferIsNotDelivered(t *testing.T) {
	for name, set := range map[string]func(*stepRecorder){
		"no acknowledgement":     func(r *stepRecorder) { r.err = errors.New("recorder down") },
		"another sequence's ack": func(r *stepRecorder) { r.acks = map[uint64]uint64{3: 2} },
	} {
		relay, _, recorder, session := newClipboardRelay(nil)
		set(recorder)
		if _, moved, err := relay.transfer(context.Background(), screenstream.ClipboardToTarget, "pasted", 3); !errors.Is(err, ErrRecordingLost) || moved {
			t.Fatalf("%s: moved %v, %v", name, moved, err)
		}
		if len(session.offered) != 0 {
			t.Fatalf("%s: offered %q", name, session.offered)
		}
	}
}

// clipboardCodec counts how sessions were opened, and with which rights.
type clipboardCodec struct {
	opened, withClipboard int
	toTarget, fromTarget  bool
}

func clipMeta(to, from bool) SessionMetadata {
	meta := screenMeta()
	meta.ScreenProtocol = screenstream.ProtocolRDP
	meta.ClipboardToTarget, meta.ClipboardFromTarget = to, from
	return meta
}

func partialFrame(seq uint64) screenstream.Message {
	return screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: seq, Timestamp: time.Unix(int64(seq), 0).UTC(), Width: 1, Height: 1,
		Rects: []screenstream.Rect{{Width: 1, Height: 1, PNG: []byte("\x89PNG\r\n\x1a\nrect")}}}
}

// A text copied on the target, between two frames: recorded and shown in the one sequence, the
// frames after it numbered after it, the partial frame still on the key frame's screen.
func TestRelayScreen_ACopiedTextTakesItsPlaceInTheSequence(t *testing.T) {
	frames := make(chan screenstream.Message)
	session := &clipboardScreenSession{fakeScreenSession: fakeScreenSession{frames: frames}, texts: make(chan string)}
	codec := &clipboardCodec{}
	recorder := &fakeFrameRecorder{}
	sink := &fakeScreenSink{}
	audit := &fakeClipboardAudit{}
	opened := &clipboardOpenCodec{inner: codec, session: session}
	recorded := func(n int) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; {
			recorder.mu.Lock()
			got := len(recorder.frames)
			recorder.mu.Unlock()
			if got >= n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d recorded, want %d", got, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- relayScreen(context.Background(), context.Background(), clipMeta(false, true), nil, opened, recorder, sink, ScreenInputLimits{}, time.Second, audit)
	}()
	frames <- validScreenFrame(1)
	recorded(1)
	session.texts <- "copied é"
	recorded(2)
	frames <- partialFrame(2)
	recorded(3)
	close(frames)
	if err := <-done; err != nil {
		t.Fatalf("relay: %v", err)
	}
	if codec.withClipboard != 1 || codec.toTarget || !codec.fromTarget {
		t.Fatalf("opened with the clipboard %d time(s), to %v from %v", codec.withClipboard, codec.toTarget, codec.fromTarget)
	}
	recorder.mu.Lock()
	got := append([]screenstream.Message(nil), recorder.frames...)
	recorder.mu.Unlock()
	if len(got) != 3 || got[0].Type != screenstream.TypeFrame || got[0].Sequence != 1 ||
		got[1].Type != screenstream.TypeClipboard || got[1].Sequence != 2 || got[1].ClipboardText != "copied é" || got[1].Direction != screenstream.ClipboardFromTarget ||
		got[2].Type != screenstream.TypeFrameDelta || got[2].Sequence != 3 {
		t.Fatalf("recorded %+v", got)
	}
	var shown []string
	for _, m := range sink.snapshot() {
		shown = append(shown, map[screenstream.MessageType]string{screenstream.TypeHello: "hello", screenstream.TypeFrame: "frame",
			screenstream.TypeClipboard: "clipboard", screenstream.TypeFrameDelta: "delta", screenstream.TypeEnd: "end"}[m.Type]+
			":"+string(rune('0'+m.Sequence)))
	}
	if strings.Join(shown, ",") != "hello:0,frame:1,clipboard:2,delta:3,end:4" {
		t.Fatalf("shown %v", shown)
	}
	if events := audit.snapshot(); len(events) != 1 || !events[0].Success || events[0].Direction != screenstream.ClipboardFromTarget {
		t.Fatalf("audit %+v", events)
	}
}

// clipboardOpenCodec opens session, with or without the clipboard, counting each.
type clipboardOpenCodec struct {
	inner   *clipboardCodec
	session ScreenSession
}

func (c *clipboardOpenCodec) Open(context.Context, *Credential) (ScreenSession, error) {
	c.inner.opened++
	return c.session, nil
}
func (c *clipboardOpenCodec) OpenWithClipboard(_ context.Context, _ *Credential, to, from bool) (ScreenSession, error) {
	c.inner.withClipboard++
	c.inner.toTarget, c.inner.fromTarget = to, from
	return c.session, nil
}

// The clipboard opens only with a right, a codec that can, and an auditor; copying is read only
// with its own right.
func TestRelayScreen_TheClipboardOpensOnlyWhenEverythingSaysSo(t *testing.T) {
	for name, c := range map[string]struct {
		to, from      bool
		audit         bool
		withClipboard bool
	}{
		"no right":     {false, false, true, false},
		"no auditor":   {true, true, false, false},
		"pasting only": {true, false, true, true},
		"copying only": {false, true, true, true},
		"both":         {true, true, true, true},
	} {
		frames := make(chan screenstream.Message, 1)
		frames <- validScreenFrame(1)
		close(frames)
		texts := make(chan string, 1)
		texts <- "never read without the right to copy"
		session := &clipboardScreenSession{fakeScreenSession: fakeScreenSession{frames: frames}, texts: texts}
		codec := &clipboardOpenCodec{inner: &clipboardCodec{}, session: session}
		var audit ClipboardAuditor
		if c.audit {
			audit = &fakeClipboardAudit{}
		}
		recorder := &fakeFrameRecorder{}
		sink := &fakeScreenSink{}
		_ = relayScreen(context.Background(), context.Background(), clipMeta(c.to, c.from), nil, codec, recorder, sink, ScreenInputLimits{}, time.Second, audit)
		if hello := sink.snapshot()[0]; hello.ClipboardToTarget != (c.withClipboard && c.to) || hello.ClipboardFromTarget != (c.withClipboard && c.from) {
			t.Fatalf("%s: the HELLO offers to %v from %v", name, hello.ClipboardToTarget, hello.ClipboardFromTarget)
		}
		if (codec.inner.withClipboard == 1) != c.withClipboard || codec.inner.withClipboard+codec.inner.opened != 1 {
			t.Fatalf("%s: opened %d, with the clipboard %d", name, codec.inner.opened, codec.inner.withClipboard)
		}
		if c.withClipboard && (codec.inner.toTarget != c.to || codec.inner.fromTarget != c.from) {
			t.Fatalf("%s: rights passed to %v from %v", name, codec.inner.toTarget, codec.inner.fromTarget)
		}
		if !c.from || !c.audit {
			for _, f := range recorder.frames {
				if f.Type == screenstream.TypeClipboard {
					t.Fatalf("%s: a text was read and recorded without the right to copy", name)
				}
			}
		}
	}
}

// The display never drops a clipboard text: not for a key frame, not past the partial frames'
// bound, not while it waits for a key frame.
func TestScreenDisplay_KeepsEveryClipboardText(t *testing.T) {
	clip := func(seq uint64) screenstream.Message {
		return screenstream.Message{Type: screenstream.TypeClipboard, Sequence: seq, ClipboardText: "t"}
	}
	sink := &gateSink{release: make(chan struct{})}
	d := newScreenDisplay(context.Background(), sink)
	requested := 0
	d.requestKey = func() { requested++ }
	d.offer(displayKey(1)) // held by the sink
	d.offer(clip(2))
	d.offer(displayDelta(3, 1))
	d.offer(displayKey(4)) // replaces what waits, but the text
	seq := uint64(5)
	d.offer(clip(seq))
	seq++
	for i := 0; i <= maxPendingDeltas; i++ { // past the bound: the deltas go, the texts stay
		d.offer(displayDelta(seq, 1))
		seq++
	}
	d.offer(clip(seq)) // while a key frame is awaited
	textSeq := seq
	seq++
	d.offer(displayDelta(seq, 1)) // dropped: a key frame is awaited
	close(sink.release)
	waitDisplayIdle(t, d)
	got := sink.sequences()
	want := []uint64{1, 2, 5, textSeq}
	if requested != 1 || len(got) != len(want) {
		t.Fatalf("sent %v (asked for %d key frame(s)), want %v", got, requested, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sent %v, want %v", got, want)
		}
	}
}

// With the right to paste and not to copy, the relay never takes a text the target copied, however
// long the session lasts: what the target offers stays where it is.
func TestRelayScreen_NothingIsCopiedWithoutTheRightToCopy(t *testing.T) {
	for _, from := range []bool{false, true} {
		frames := make(chan screenstream.Message)
		texts := make(chan string)
		session := &clipboardScreenSession{fakeScreenSession: fakeScreenSession{frames: frames}, texts: texts}
		codec := &clipboardOpenCodec{inner: &clipboardCodec{}, session: session}
		done := make(chan error, 1)
		go func() {
			done <- relayScreen(context.Background(), context.Background(), clipMeta(true, from), nil, codec, &fakeFrameRecorder{},
				&fakeScreenSink{}, ScreenInputLimits{}, time.Second, &fakeClipboardAudit{})
		}()
		frames <- validScreenFrame(1)
		taken := false
		select {
		case texts <- "copied on the target":
			taken = true
		case <-time.After(300 * time.Millisecond):
		}
		close(frames)
		<-done
		if taken != from {
			t.Fatalf("right to copy %v: the relay took a text %v", from, taken)
		}
	}
}

// A text pasted by the operator, with the right to paste: audited, recorded in the sequence,
// offered to the target, and shown back. The HELLO said pasting was allowed, and copying not.
func TestRelayScreen_APastedTextReachesTheTargetAfterItsRecording(t *testing.T) {
	frames := make(chan screenstream.Message)
	session := &clipboardScreenSession{fakeScreenSession: fakeScreenSession{frames: frames}}
	codec := &clipboardOpenCodec{inner: &clipboardCodec{}, session: session}
	input, err := screenstream.EncodeClipboardInput("pasted é")
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeInputScreenSink{input: input, read: make(chan struct{}, 4)}
	recorder := &fakeFrameRecorder{}
	audit := &fakeClipboardAudit{}
	done := make(chan error, 1)
	go func() {
		done <- relayScreen(context.Background(), context.Background(), clipMeta(true, false), nil, codec, recorder, sink, ScreenInputLimits{}, time.Second, audit)
	}()
	frames <- validScreenFrame(1)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		session.mu.Lock()
		offered := len(session.offered)
		session.mu.Unlock()
		if offered == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the pasted text never reached the target")
		}
	}
	close(frames)
	if err := <-done; err != nil {
		t.Fatalf("relay: %v", err)
	}
	if session.offered[0] != "pasted é" {
		t.Fatalf("offered %q", session.offered)
	}
	var clip *screenstream.Message
	recorder.mu.Lock()
	for i := range recorder.frames {
		if recorder.frames[i].Type == screenstream.TypeClipboard {
			clip = &recorder.frames[i]
		}
	}
	recorder.mu.Unlock()
	if clip == nil || clip.Direction != screenstream.ClipboardToTarget || clip.ClipboardText != "pasted é" {
		t.Fatalf("recorded %+v", clip)
	}
	messages := sink.snapshot()
	hello := messages[0]
	if hello.Type != screenstream.TypeHello || !hello.ClipboardToTarget || hello.ClipboardFromTarget {
		t.Fatalf("HELLO %+v", hello)
	}
	shown := false
	for _, m := range messages {
		shown = shown || (m.Type == screenstream.TypeClipboard && m.Sequence == clip.Sequence && m.ClipboardText == "pasted é")
	}
	if !shown || len(audit.snapshot()) != 1 {
		t.Fatalf("shown %v, audited %d", shown, len(audit.snapshot()))
	}
}

// A text pasted on a session that does not take one ends it, as any invalid input does, and
// nothing reaches the target: with the right to copy only, with no clipboard at all, or malformed.
func TestRelayScreen_APastedTextTheSessionDoesNotTakeEndsIt(t *testing.T) {
	good, _ := screenstream.EncodeClipboardInput("pasted")
	malformed := append([]byte(nil), good...)
	malformed[3] = 1
	for name, c := range map[string]struct {
		meta  SessionMetadata
		audit ClipboardAuditor
		input []byte
	}{
		"the right to copy only": {clipMeta(false, true), &fakeClipboardAudit{}, good},
		"no right":               {clipMeta(false, false), &fakeClipboardAudit{}, good},
		"no auditor":             {clipMeta(true, true), nil, good},
		"a malformed text":       {clipMeta(true, false), &fakeClipboardAudit{}, malformed},
	} {
		frames := make(chan screenstream.Message)
		session := &clipboardScreenSession{fakeScreenSession: fakeScreenSession{frames: frames}}
		codec := &clipboardOpenCodec{inner: &clipboardCodec{}, session: session}
		sink := &fakeInputScreenSink{input: c.input, read: make(chan struct{}, 4)}
		err := relayScreen(context.Background(), context.Background(), c.meta, nil, codec, &fakeFrameRecorder{}, sink, ScreenInputLimits{}, time.Second, c.audit)
		if !errors.Is(err, ErrScreenInputInvalid) || len(session.offered) != 0 {
			t.Fatalf("%s: %v, offered %q", name, err, session.offered)
		}
		if hello := sink.snapshot()[0]; hello.ClipboardToTarget && c.meta.ClipboardToTarget == false {
			t.Fatalf("%s: the HELLO offered pasting", name)
		}
	}
}

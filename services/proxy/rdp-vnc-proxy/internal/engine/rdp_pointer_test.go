package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The pointer drawn into the frames (ADR-0091): what the operator sees is what is recorded.

func grayDesktop(width, height int) rdp.RDPBitmapUpdate {
	pixels := make([]byte, width*height*4)
	for i := 0; i < len(pixels); i += 4 {
		pixels[i], pixels[i+1], pixels[i+2], pixels[i+3] = 0x80, 0x80, 0x80, 0xff
	}
	return rdp.RDPBitmapUpdate{Rectangles: []rdp.RDPBitmapRectangle{{Width: uint16(width), Height: uint16(height), Pixels: pixels}}}
}

func redDot(index uint16) rdp.RDPBitmapUpdate {
	return rdp.RDPBitmapUpdate{Pointer: &rdp.RDPPointerUpdate{Kind: rdp.RDPPointerShape, CacheIndex: index,
		Shape: &rdp.RDPPointerImage{Width: 1, Height: 1, RGBA: []byte{0xff, 0, 0, 0xff}, XOR: []bool{false}}}}
}

func pointerUpdate(update rdp.RDPPointerUpdate) rdp.RDPBitmapUpdate {
	return rdp.RDPBitmapUpdate{Pointer: &update}
}

func openPointerSession(t *testing.T, target *fakeRDPDesktop, draw bool) proxycore.ScreenSession {
	t.Helper()
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), DrawPointer: draw,
		openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func nextFrame(t *testing.T, session proxycore.ScreenSession, what string) image.Image {
	t.Helper()
	select {
	case frame, ok := <-session.Frames():
		if !ok {
			t.Fatalf("%s: the stream ended (%v)", what, session.Err())
		}
		shown, err := png.Decode(bytes.NewReader(frame.PNG))
		if err != nil {
			t.Fatal(err)
		}
		return shown
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: no frame", what)
	}
	return nil
}

func noFrame(t *testing.T, session proxycore.ScreenSession, what string) {
	t.Helper()
	select {
	case frame, ok := <-session.Frames():
		if ok {
			t.Fatalf("%s: frame %d", what, frame.Sequence)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

func rgbAt(img image.Image, x, y int) [3]byte {
	r, g, b, _ := img.At(x, y).RGBA()
	return [3]byte{byte(r >> 8), byte(g >> 8), byte(b >> 8)}
}

var (
	gray  = [3]byte{0x80, 0x80, 0x80}
	black = [3]byte{0, 0, 0}
	white = [3]byte{0xff, 0xff, 0xff}
	red   = [3]byte{0xff, 0, 0}
)

// The operator's move is a frame with the arrow at the pointer, and the same position again is not.
func TestRDPCodec_TheOperatorsPointerIsInTheFrame(t *testing.T) {
	target := &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{grayDesktop(16, 16)}}
	session := openPointerSession(t, target, true)
	if got := rgbAt(nextFrame(t, session, "desktop"), 5, 5); got != gray {
		t.Fatalf("a pointer before any move: %v", got)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 5, Y: 5}); err != nil {
		t.Fatal(err)
	}
	shown := nextFrame(t, session, "the move")
	if rgbAt(shown, 5, 5) != black || rgbAt(shown, 6, 7) != white || rgbAt(shown, 4, 5) != gray {
		t.Fatalf("the arrow is not at (5,5): tip %v, inside %v, left %v", rgbAt(shown, 5, 5), rgbAt(shown, 6, 7), rgbAt(shown, 4, 5))
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 5, Y: 5, Buttons: 1}); err != nil {
		t.Fatal(err)
	}
	noFrame(t, session, "a click where the pointer already is")
}

// The target's shape, position, hiding and cache are followed, frame by frame.
func TestRDPCodec_TheTargetsPointerIsFollowed(t *testing.T) {
	target := &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{
		grayDesktop(16, 16),
		redDot(2),
		pointerUpdate(rdp.RDPPointerUpdate{Kind: rdp.RDPPointerPosition, X: 3, Y: 3}),
		pointerUpdate(rdp.RDPPointerUpdate{Kind: rdp.RDPPointerHidden}),
		pointerUpdate(rdp.RDPPointerUpdate{Kind: rdp.RDPPointerCached, CacheIndex: 2}),
	}}
	session := openPointerSession(t, target, true)
	nextFrame(t, session, "desktop")
	if got := rgbAt(nextFrame(t, session, "the shape, not yet placed"), 3, 3); got != gray {
		t.Fatalf("drawn before any position: %v", got)
	}
	if got := rgbAt(nextFrame(t, session, "the position"), 3, 3); got != red {
		t.Fatalf("(3,3) %v, want the target's red shape", got)
	}
	if got := rgbAt(nextFrame(t, session, "hidden"), 3, 3); got != gray {
		t.Fatalf("hidden, (3,3) is %v", got)
	}
	if got := rgbAt(nextFrame(t, session, "cached"), 3, 3); got != red {
		t.Fatalf("the cached shape, (3,3) is %v", got)
	}
}

// A cache entry the target never filled ends the stream with the pointer's refusal; so does one a
// reactivation emptied.
func TestRDPCodec_APointerOutsideTheProfileEndsTheStream(t *testing.T) {
	cached := pointerUpdate(rdp.RDPPointerUpdate{Kind: rdp.RDPPointerCached, CacheIndex: 2})
	reactivated := grayDesktop(16, 16)
	reactivated.Reactivated = true
	for name, updates := range map[string][]rdp.RDPBitmapUpdate{
		"never filled":          {grayDesktop(16, 16), cached},
		"emptied by reactivate": {grayDesktop(16, 16), redDot(2), reactivated, cached},
	} {
		target := &fakeRDPDesktop{width: 16, height: 16, updates: updates}
		session := openPointerSession(t, target, true)
		for range session.Frames() {
		}
		if err := session.Err(); !errors.Is(err, rdp.ErrRDPPointer) {
			t.Errorf("%s: %v, want ErrRDPPointer", name, err)
		}
	}
}

// Not drawn, the operator's move is no frame, and a pointer update, which the client did not ask
// for, ends the stream.
func TestRDPCodec_APointerNotDrawnIsNotInTheFrame(t *testing.T) {
	target := &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{grayDesktop(16, 16)}}
	session := openPointerSession(t, target, false)
	nextFrame(t, session, "desktop")
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 5, Y: 5}); err != nil {
		t.Fatal(err)
	}
	noFrame(t, session, "a move, the pointer not drawn")

	target = &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{grayDesktop(16, 16), redDot(0)}}
	session = openPointerSession(t, target, false)
	for range session.Frames() {
	}
	if err := session.Err(); !errors.Is(err, rdp.ErrRDPPointer) {
		t.Fatalf("a pointer update not asked for: %v", err)
	}
}

// Moves within the interval are one frame, the latest position, at the interval.
func TestRDPCodec_PointerMovesFollowTheCadence(t *testing.T) {
	target := &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{grayDesktop(16, 16)}}
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), DrawPointer: true, FrameInterval: 150 * time.Millisecond,
		openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	nextFrame(t, session, "desktop")
	for x := uint16(1); x <= 10; x++ {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: x, Y: 2}); err != nil {
			t.Fatal(err)
		}
	}
	shown := nextFrame(t, session, "the moves")
	if rgbAt(shown, 10, 2) != black || rgbAt(shown, 1, 2) != gray {
		t.Fatalf("the frame is not the latest position: (10,2) %v, (1,2) %v", rgbAt(shown, 10, 2), rgbAt(shown, 1, 2))
	}
	noFrame(t, session, "after the moves")
}

// provePointerIsDrawn is the interoperability check of ADR-0091, against FreeRDP and Windows: with
// the pointer drawn, the session lives through the target's pointer updates (a shape outside the
// profile would end it), and the operator's move puts the pointer in the frame, where it was not.
// What a person must judge, the shape itself, goes to dump. targetSendsPointer: the target must
// send pointer updates (Windows does, FreeRDP's test server does not).
func provePointerIsDrawn(t *testing.T, session proxycore.ScreenSession, targetSendsPointer bool, dump func(string, screenstream.Message)) {
	t.Helper()
	next := func(limit time.Duration) (screenstream.Message, bool) {
		select {
		case message, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the stream ended with the pointer drawn: %v", session.Err())
			}
			return message, true
		case <-time.After(limit):
			return screenstream.Message{}, false
		}
	}
	settle := func(frame screenstream.Message, quiet time.Duration) screenstream.Message {
		for {
			following, ok := next(quiet)
			if !ok {
				return frame
			}
			frame = following
		}
	}
	first, ok := next(90 * time.Second)
	if !ok {
		t.Fatalf("no frame in 90 s: %v", session.Err())
	}
	before := settle(first, 10*time.Second)
	dump("pointer-0-before.png", before)
	x, y := int(before.Width/2)+40, int(before.Height/2)+40
	for _, at := range [][2]int{{x - 20, y - 20}, {x, y}} {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: uint16(at[0]), Y: uint16(at[1])}); err != nil {
			t.Fatalf("pointer: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	moved, ok := next(10 * time.Second)
	if !ok {
		t.Fatal("no frame after the pointer moved")
	}
	after := settle(moved, 5*time.Second)
	dump("pointer-1-moved.png", after)
	decode := func(m screenstream.Message) image.Image {
		img, err := png.Decode(bytes.NewReader(m.PNG))
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	was, is := decode(before), decode(after)
	differs := 0
	for dy := 0; dy < 32; dy++ {
		for dx := 0; dx < 32; dx++ {
			if rgbAt(was, x+dx, y+dy) != rgbAt(is, x+dx, y+dy) {
				differs++
			}
		}
	}
	if differs == 0 {
		t.Fatal("the frame is the same under the pointer: it was not drawn (pointer-1-moved.png)")
	}
	adapter, _ := session.(*rdpScreenSessionAdapter)
	if adapter == nil || adapter.pointer == nil {
		t.Fatal("the pointer is not drawn by this session")
	}
	adapter.pointerMu.Lock()
	updates, fromTarget := adapter.pointerUpdates, adapter.pointer.FromTarget()
	adapter.pointerMu.Unlock()
	t.Logf("%d pixel(s) changed under the pointer; %d pointer update(s) from the target; shape from the target: %t (pointer-1-moved.png)",
		differs, updates, fromTarget)
	// Windows sends its pointer once the cache is announced; FreeRDP's test server sends none.
	if targetSendsPointer && updates == 0 {
		t.Fatal("no pointer update from the target: the pointer cache was not announced, or the updates are still ignored")
	}
}

// The session says whether it draws the pointer: the HELLO carries it to the operator's browser.
func TestRDPCodec_TheSessionSaysWhetherItDrawsThePointer(t *testing.T) {
	for _, draw := range []bool{false, true} {
		target := &fakeRDPDesktop{width: 16, height: 16, updates: []rdp.RDPBitmapUpdate{grayDesktop(16, 16)}}
		session := openPointerSession(t, target, draw)
		drawer, ok := session.(proxycore.PointerDrawer)
		if !ok || drawer.PointerDrawn() != draw {
			t.Fatalf("DrawPointer %v: the session says %v (%v)", draw, ok && drawer.PointerDrawn(), ok)
		}
	}
}

// The VNC session's word passes through the wrapper that maps its errors: an embedded interface
// would hide it.
func TestVNCScreenSessionPassesOnWhetherItDrawsThePointer(t *testing.T) {
	if drawn := (vncScreenSession{drawingSession{true}}).PointerDrawn(); !drawn {
		t.Fatal("a VNC session drawing the pointer is said not to")
	}
	if (vncScreenSession{drawingSession{false}}).PointerDrawn() || (vncScreenSession{silentSession{}}).PointerDrawn() {
		t.Fatal("a VNC session not drawing the pointer is said to")
	}
}

type silentSession struct{}

func (silentSession) Frames() <-chan screenstream.Message { return nil }
func (silentSession) Input(screenstream.InputEvent) error { return nil }
func (silentSession) Err() error                          { return nil }
func (silentSession) Close() error                        { return nil }

type drawingSession struct{ drawn bool }

func (d drawingSession) Frames() <-chan screenstream.Message { return nil }
func (d drawingSession) Input(screenstream.InputEvent) error { return nil }
func (d drawingSession) Err() error                          { return nil }
func (d drawingSession) Close() error                        { return nil }
func (d drawingSession) PointerDrawn() bool                  { return d.drawn }

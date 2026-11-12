package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The frames of ADR-0092 from the RDP codec: a key frame, then partial frames of what changed, the
// pointer included; composed, they are the screen a key frame of the same moment shows.

func openPartialSession(t *testing.T, target *fakeRDPDesktop) proxycore.ScreenSession {
	t.Helper()
	codec := &RDPCodec{TLSRoots: x509.NewCertPool(), DrawPointer: true, PartialFrames: true,
		openSession: func(context.Context, *proxycore.Credential) (rdpScreenSession, error) { return target, nil }}
	session, err := codec.Open(context.Background(), rdpTestCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func nextMessage(t *testing.T, session proxycore.ScreenSession, what string) screenstream.Message {
	t.Helper()
	select {
	case m, ok := <-session.Frames():
		if !ok {
			t.Fatalf("%s: the stream ended (%v)", what, session.Err())
		}
		return m
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: no frame", what)
	}
	return screenstream.Message{}
}

func redPixel(x, y uint16) rdp.RDPBitmapUpdate {
	return rdp.RDPBitmapUpdate{Rectangles: []rdp.RDPBitmapRectangle{{X: x, Y: y, Width: 1, Height: 1, Pixels: []byte{0xff, 0, 0, 0xff}}}}
}

func TestRDPCodec_PartialFramesCarryOnlyWhatChanged(t *testing.T) {
	target := &fakeRDPDesktop{width: 128, height: 96, updates: []rdp.RDPBitmapUpdate{grayDesktop(128, 96), redPixel(100, 80)}}
	session := openPartialSession(t, target)
	var composer screenstream.Composer
	apply := func(m screenstream.Message) {
		t.Helper()
		if err := composer.Apply(m); err != nil {
			t.Fatalf("sequence %d (%v): %v", m.Sequence, m.Type, err)
		}
	}
	key := nextMessage(t, session, "the desktop")
	if key.Type != screenstream.TypeFrame {
		t.Fatalf("the first frame is a %v", key.Type)
	}
	apply(key)
	pixel := nextMessage(t, session, "one pixel")
	if pixel.Type != screenstream.TypeFrameDelta || len(pixel.Rects) != 1 || pixel.Rects[0].X != 96 || pixel.Rects[0].Y != 64 {
		t.Fatalf("one pixel changed: %v %+v", pixel.Type, pixel.Rects)
	}
	apply(pixel)
	if c := composer.Screen().RGBAAt(100, 80); c.R != 0xff || c.G != 0 {
		t.Fatalf("(100,80) composed as %v", c)
	}
	// The operator's pointer: the arrow's tiles, nothing else.
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 10, Y: 10}); err != nil {
		t.Fatal(err)
	}
	moved := nextMessage(t, session, "the move")
	if moved.Type != screenstream.TypeFrameDelta || len(moved.Rects) != 1 || moved.Rects[0].Width != 32 || moved.Rects[0].Height != 32 {
		t.Fatalf("the pointer at (10,10): %v %+v", moved.Type, moved.Rects)
	}
	apply(moved)
	// And moving on: the tile it left, repainted, and the one it reached.
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 74, Y: 10}); err != nil {
		t.Fatal(err)
	}
	again := nextMessage(t, session, "the second move")
	if again.Type != screenstream.TypeFrameDelta || len(again.Rects) == 0 {
		t.Fatalf("the second move: %v", again.Type)
	}
	apply(again)
	if c := composer.Screen().RGBAAt(10, 10); c.R != 0x80 {
		t.Fatalf("(10,10) still shows the pointer it left: %v", c)
	}
	if c := composer.Screen().RGBAAt(74, 10); c.R != 0 || c.A != 0xff {
		t.Fatalf("(74,10) is %v, want the arrow's black tip", c)
	}
	// The composed screen is the screen: the framebuffer's own key frame of this moment says so.
	adapter := session.(*rdpScreenSessionAdapter)
	adapter.pointerMu.Lock()
	adapter.framebuffer.ForceKeyFrame()
	snapshot, err := adapter.framebuffer.FrameWithPointer(time.Now(), adapter.pointer)
	adapter.pointerMu.Unlock()
	if err != nil || snapshot.Type != screenstream.TypeFrame {
		t.Fatalf("a key frame of this moment: %v, %v", snapshot.Type, err)
	}
	var fromKey screenstream.Composer
	if err := fromKey.Apply(snapshot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromKey.Screen().Pix, composer.Screen().Pix) {
		t.Fatal("the composed screen is not the screen a key frame of the same moment shows")
	}
}

// What changes nothing on the screen makes no frame: a click where the pointer is, a pointer shape
// before the pointer is placed.
func TestRDPCodec_PartialFramesSendNothingForNothing(t *testing.T) {
	target := &fakeRDPDesktop{width: 64, height: 64, updates: []rdp.RDPBitmapUpdate{grayDesktop(64, 64), redDot(1)}}
	session := openPartialSession(t, target)
	if m := nextMessage(t, session, "the desktop"); m.Type != screenstream.TypeFrame {
		t.Fatalf("%v", m.Type)
	}
	noFrame(t, session, "a shape not yet placed")
}

// A reactivation is followed by a key frame (ADR-0092 §3), even at the same size.
func TestRDPCodec_AReactivationMakesAKeyFrame(t *testing.T) {
	again := redPixel(3, 3)
	again.Reactivated = true
	target := &fakeRDPDesktop{width: 64, height: 64, updates: []rdp.RDPBitmapUpdate{grayDesktop(64, 64), redPixel(1, 1), again}}
	session := openPartialSession(t, target)
	kinds := []screenstream.MessageType{}
	for i := 0; i < 3; i++ {
		kinds = append(kinds, nextMessage(t, session, "frame").Type)
	}
	if kinds[0] != screenstream.TypeFrame || kinds[1] != screenstream.TypeFrameDelta || kinds[2] != screenstream.TypeFrame {
		t.Fatalf("frames %v: want key, partial, key after the reactivation", kinds)
	}
}

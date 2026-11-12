package vnc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// Partial frames from VNC (ADR-0092, increment 5): the same encoder as RDP, so the same frames.

func partialSession(t *testing.T, w, h uint32) (*Session, func([]byte)) {
	t.Helper()
	s, server := pipeSession(t, w, h)
	s.drawPointer, s.pointerMoved = true, make(chan struct{}, 1)
	s.partial, s.keyWanted = &screenstream.FrameEncoder{}, make(chan struct{}, 1)
	s.pointerLoopDone = make(chan struct{})
	go s.pointerLoop()
	go s.readLoop()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	t.Cleanup(func() { _ = s.Close() })
	return s, func(message []byte) {
		if err := writeFull(server, message); err != nil {
			t.Fatalf("server: %v", err)
		}
	}
}

func nextVNCMessage(t *testing.T, s *Session, what string) screenstream.Message {
	t.Helper()
	select {
	case m, ok := <-s.Frames():
		if !ok {
			t.Fatalf("%s: the stream ended: %v", what, s.Err())
		}
		return m
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: no frame", what)
	}
	return screenstream.Message{}
}

func redRaw(w, h int) []byte {
	var body []byte
	for i := 0; i < w*h; i++ {
		body = append(body, 0, 0, 0xff, 0)
	}
	return body
}

func TestVNCPartialFramesCarryOnlyWhatChanged(t *testing.T) {
	s, send := partialSession(t, 128, 96)
	var composer screenstream.Composer
	apply := func(m screenstream.Message) {
		t.Helper()
		if err := composer.Apply(m); err != nil {
			t.Fatalf("sequence %d (%v): %v", m.Sequence, m.Type, err)
		}
	}
	send(update(rectangle(0, 0, 128, 96, 0, grayRaw(128, 96))))
	key := nextVNCMessage(t, s, "the desktop")
	if key.Type != screenstream.TypeFrame {
		t.Fatalf("the first frame is a %v", key.Type)
	}
	apply(key)
	send(update(rectangle(100, 70, 2, 2, 0, redRaw(2, 2))))
	changed := nextVNCMessage(t, s, "a 2x2 change")
	if changed.Type != screenstream.TypeFrameDelta || len(changed.Rects) != 1 || changed.Rects[0].X != 96 || changed.Rects[0].Y != 64 {
		t.Fatalf("a 2x2 change: %v %+v", changed.Type, changed.Rects)
	}
	apply(changed)
	// A repaint of the same pixels: no frame.
	send(update(rectangle(100, 70, 2, 2, 0, redRaw(2, 2))))
	noVNCFrame(t, s, "a repaint of the same pixels")
	// The pointer: its shape's tiles, nothing else.
	send(update(rectangle(1, 1, 2, 2, -239, cursorBody(2, 2, [4]byte{0xff, 0, 0, 0}, []byte{0xc0, 0xc0}))))
	noVNCFrame(t, s, "a shape before the pointer is placed")
	if err := s.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 10, Y: 10}); err != nil {
		t.Fatal(err)
	}
	moved := nextVNCMessage(t, s, "the move")
	if moved.Type != screenstream.TypeFrameDelta || len(moved.Rects) != 1 || moved.Rects[0].Width != 32 {
		t.Fatalf("the pointer at (10,10): %v %+v", moved.Type, moved.Rects)
	}
	apply(moved)
	if c := composer.Screen().RGBAAt(10, 10); c.B != 0xff || c.R != 0 {
		t.Fatalf("(10,10) composed as %v, want the blue cursor", c)
	}
	// Asked for, a key frame comes at once, on a still screen, and it is the screen composed.
	s.RequestKeyFrame()
	again := nextVNCMessage(t, s, "the key frame asked for")
	if again.Type != screenstream.TypeFrame {
		t.Fatalf("asked for a key frame, got a %v", again.Type)
	}
	var fromKey screenstream.Composer
	if err := fromKey.Apply(again); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromKey.Screen().Pix, composer.Screen().Pix) {
		t.Fatal("the composed screen is not the screen the key frame of this moment shows")
	}
}

// A new desktop size is a key frame (ADR-0092 §3).
func TestVNCPartialFramesMakeAKeyFrameOnANewSize(t *testing.T) {
	s, send := partialSession(t, 64, 64)
	send(update(rectangle(0, 0, 64, 64, 0, grayRaw(64, 64))))
	nextVNCMessage(t, s, "the desktop")
	send(update(rectangle(0, 0, 96, 64, -223, nil), rectangle(0, 0, 96, 64, 0, grayRaw(96, 64))))
	if m := nextVNCMessage(t, s, "the new size"); m.Type != screenstream.TypeFrame || m.Width != 96 {
		t.Fatalf("after a new size: %v %dx%d", m.Type, m.Width, m.Height)
	}
}

// Without partial frames, nothing changes: whole frames, and a request for a key frame is ignored.
func TestVNCWithoutPartialFramesSendsWholeFrames(t *testing.T) {
	s, send := drawingSession(t, false)
	send(update(rectangle(0, 0, 8, 8, 0, grayRaw(8, 8))))
	if m := nextVNCMessage(t, s, "the desktop"); m.Type != screenstream.TypeFrame {
		t.Fatalf("%v", m.Type)
	}
	send(update(rectangle(1, 1, 1, 1, 0, redRaw(1, 1))))
	if m := nextVNCMessage(t, s, "a change"); m.Type != screenstream.TypeFrame {
		t.Fatalf("whole frames off partial: %v", m.Type)
	}
	s.RequestKeyFrame() // no-op
	noVNCFrame(t, s, "a key frame request without partial frames")
}

// Open turns partial frames on when asked, and only then; a key frame is asked for even before any
// cursor shape, on a still screen.
func TestOpenWithPartialFramesMakesKeyFramesOnRequest(t *testing.T) {
	for _, partial := range []bool{false, true} {
		serverCert, leaf := vncTestCertificate(t)
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		pinSum := sha256.Sum256(serverCert.Certificate[0])
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		eventsSeen := make(chan struct{})
		serverResult := make(chan error, 1)
		go func() { serverResult <- serveFakeVeNCrypt(t, listener, serverCert, eventsSeen) }()
		client := &Client{Config: Config{Address: listener.Addr().String(), Username: "operator", Password: []byte("vault-password"),
			TLSFingerprint: hex.EncodeToString(pinSum[:]), TLSRoots: roots, TLSServerName: "target.test", DialTimeout: 3 * time.Second,
			PartialFrames: partial}}
		session, err := client.Open(context.Background())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if (session.partial != nil) != partial || (session.keyWanted != nil) != partial || (session.pointerLoopDone != nil) != partial {
			t.Fatalf("partial %v: encoder %v, request channel %v, loop %v", partial, session.partial != nil, session.keyWanted != nil, session.pointerLoopDone != nil)
		}
		if frame := nextVNCMessage(t, session, "the first frame"); frame.Type != screenstream.TypeFrame {
			t.Fatalf("the first frame is a %v", frame.Type)
		}
		if partial {
			session.RequestKeyFrame()
			if frame := nextVNCMessage(t, session, "the key frame asked for"); frame.Type != screenstream.TypeFrame || frame.Sequence != 2 {
				t.Fatalf("asked for a key frame: %v, sequence %d", frame.Type, frame.Sequence)
			}
		}
		_ = session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61})
		_ = session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 0, Y: 0, Buttons: 1})
		_ = session.Input(screenstream.InputEvent{Type: screenstream.InputReleaseAll})
		<-eventsSeen
		_ = session.Close()
		<-serverResult
		listener.Close()
	}
}

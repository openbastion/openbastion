package vnc

import (
	"bytes"
	"encoding/binary"
	"image"
	"net"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// fuzzConn is a target that says what the fuzzer gives, and hears everything (ADR-0071, increment 4).
type fuzzConn struct{ r *bytes.Reader }

func (c fuzzConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c fuzzConn) Close() error                     { return nil }
func (c fuzzConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c fuzzConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c fuzzConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzReadServerInit(f *testing.F) {
	init := make([]byte, 24)
	binary.BigEndian.PutUint16(init[0:2], 8)
	binary.BigEndian.PutUint16(init[2:4], 6)
	init[4], init[5], init[6], init[7] = 32, 24, 0, 1
	binary.BigEndian.PutUint32(init[20:24], 1)
	f.Add(append(init, 'x'))
	f.Fuzz(func(t *testing.T, data []byte) {
		w, h, err := readServerInit(fuzzConn{bytes.NewReader(data)})
		if err == nil && (w == 0 || h == 0 || uint64(w)*uint64(h) > screenstream.MaxPixels) {
			t.Fatalf("a %dx%d desktop was accepted", w, h)
		}
	})
}

// What a hostile target can send once the session runs: updates, rectangles, encodings, resizes,
// a bell, clipboard text. Bounded, refused, never a panic; the framebuffer stays within its bounds.
func FuzzReadServerMessage(f *testing.F) {
	raw := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0} // one 1x1 Raw rectangle at 0,0
	f.Add(append(raw, 1, 2, 3, 0))
	f.Add([]byte{2, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c'}) // ServerCutText, discarded
	f.Add([]byte{1})                                     // Bell
	f.Fuzz(func(t *testing.T, data []byte) {
		s := &Session{conn: fuzzConn{bytes.NewReader(data)}, frames: make(chan screenstream.Message), width: 8, height: 6,
			framebuffer: image.NewRGBA(image.Rect(0, 0, 8, 6)), done: make(chan struct{}), pressed: map[uint32]struct{}{}}
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for range s.frames {
			}
		}()
		for i := 0; i < 64; i++ {
			if s.readServerMessage() != nil {
				break
			}
		}
		close(s.frames)
		<-drained
		b := s.framebuffer.Bounds()
		if uint32(b.Dx()) != s.width || uint32(b.Dy()) != s.height || uint64(b.Dx())*uint64(b.Dy()) > screenstream.MaxPixels {
			t.Fatalf("framebuffer %v for a %dx%d session", b, s.width, s.height)
		}
	})
}

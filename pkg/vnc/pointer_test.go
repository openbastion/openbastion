package vnc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/png"
	"io"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// cursorBody is what a target sends after a Cursor rectangle's header: pixels (B, G, R, X, the
// session's 32-bit little-endian format) and the bitmask, most significant bit first.
func cursorBody(width, height int, pixel [4]byte, mask []byte) []byte {
	var body []byte
	for i := 0; i < width*height; i++ {
		body = append(body, pixel[:]...)
	}
	return append(body, mask...)
}

func rectangle(x, y, w, h uint16, encoding int32, body []byte) []byte {
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], x)
	binary.BigEndian.PutUint16(hdr[2:4], y)
	binary.BigEndian.PutUint16(hdr[4:6], w)
	binary.BigEndian.PutUint16(hdr[6:8], h)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(encoding))
	return append(hdr[:], body...)
}

func update(rectangles ...[]byte) []byte {
	out := []byte{0, 0, 0, byte(len(rectangles))}
	for _, r := range rectangles {
		out = append(out, r...)
	}
	return out
}

func TestReadCursorDecodesTheShapeAndItsMask(t *testing.T) {
	// 3×2, red; the mask keeps the first and third pixels of the top row and the second below:
	// 0b101_00000, 0b010_00000.
	c, err := readCursor(bytes.NewReader(cursorBody(3, 2, [4]byte{0, 0, 0xff, 0}, []byte{0xa0, 0x40})), 1, 0, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if c.width != 3 || c.height != 2 || c.hotX != 1 || c.hotY != 0 {
		t.Fatalf("%+v", c)
	}
	want := [][4]byte{{0xff, 0, 0, 0xff}, {}, {0xff, 0, 0, 0xff}, {}, {0xff, 0, 0, 0xff}, {}}
	for i, w := range want {
		if got := [4]byte(c.rgba[i*4 : i*4+4]); got != w {
			t.Fatalf("pixel %d is %v, want %v", i, got, w)
		}
	}
	if c, err := readCursor(bytes.NewReader(nil), 0, 0, 0, 0); err != nil || c.width != 0 {
		t.Fatalf("an empty cursor hides the pointer: %+v, %v", c, err)
	}
}

func TestReadCursorRefusesWhatIsOutOfBounds(t *testing.T) {
	big := cursorBody(129, 1, [4]byte{}, make([]byte, 17))
	for name, read := range map[string]func() (*cursor, error){
		"129 wide":             func() (*cursor, error) { return readCursor(bytes.NewReader(big), 0, 0, 129, 1) },
		"129 high":             func() (*cursor, error) { return readCursor(bytes.NewReader(big), 0, 0, 1, 129) },
		"hot spot x at 128":    func() (*cursor, error) { return readCursor(bytes.NewReader(big), 128, 0, 1, 1) },
		"hot spot y at 128":    func() (*cursor, error) { return readCursor(bytes.NewReader(big), 0, 128, 1, 1) },
		"width without height": func() (*cursor, error) { return readCursor(bytes.NewReader(big), 0, 0, 1, 0) },
		"height without width": func() (*cursor, error) { return readCursor(bytes.NewReader(big), 0, 0, 0, 1) },
	} {
		if _, err := read(); !errors.Is(err, ErrInvalidFramebuffer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := readCursor(bytes.NewReader(make([]byte, 128*128*4+16*128)), 127, 127, 128, 128); err != nil {
		t.Fatalf("128×128 is the bound, not beyond it: %v", err)
	}
	if _, err := readCursor(bytes.NewReader(cursorBody(2, 2, [4]byte{}, []byte{0xc0})), 0, 0, 2, 2); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a mask cut short: %v", err)
	}
}

func TestCursorIsDrawnAtItsHotSpotAndClipped(t *testing.T) {
	c, err := readCursor(bytes.NewReader(cursorBody(2, 2, [4]byte{0, 0, 0xff, 0}, []byte{0xc0, 0x40})), 1, 1, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	gray := func() *image.RGBA {
		img := image.NewRGBA(image.Rect(0, 0, 4, 4))
		for i := range img.Pix {
			img.Pix[i] = 0x80
		}
		return img
	}
	img := gray()
	c.drawOn(img, 2, 2)
	for _, at := range [][2]int{{1, 1}, {2, 1}, {2, 2}} {
		if got := img.RGBAAt(at[0], at[1]); got.R != 0xff || got.A != 0xff {
			t.Fatalf("(%d,%d) is %v, want red", at[0], at[1], got)
		}
	}
	if got := img.RGBAAt(1, 2); got.R != 0x80 || got.A != 0x80 {
		t.Fatalf("(1,2) is under a clear pixel of the mask: the desktop must show, got %v", got)
	}
	// Clipped at the right edge: the column past it is not written into the next row.
	right := gray()
	c.drawOn(right, 4, 1)
	if got := right.RGBAAt(3, 0); got.R != 0xff {
		t.Fatalf("(3,0) is %v, want red", got)
	}
	for _, at := range [][2]int{{0, 1}, {0, 2}} {
		if got := right.RGBAAt(at[0], at[1]); got.R != 0x80 {
			t.Fatalf("(%d,%d) is %v: a pixel past the right edge wrapped into the next row", at[0], at[1], got)
		}
	}
	corner := image.NewRGBA(image.Rect(0, 0, 4, 4))
	c.drawOn(corner, 0, 0) // only the shape's bottom-right pixel lands, on (0,0)
	if got := corner.RGBAAt(0, 0); got.R != 0xff {
		t.Fatalf("clipped at the corner: (0,0) is %v", got)
	}
	c.drawOn(corner, -500, 70000) // nothing lands, nothing panics
}

// drawingSession is a session over a pipe that draws the pointer, its reader and pointer loop
// running as Open starts them; the server's side drains what the client writes.
func drawingSession(t *testing.T, draw bool) (*Session, func([]byte)) {
	t.Helper()
	s, server := pipeSession(t, 8, 8)
	if draw {
		s.drawPointer, s.pointerMoved, s.pointerLoopDone = true, make(chan struct{}, 1), make(chan struct{})
		go s.pointerLoop()
	}
	go s.readLoop()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	t.Cleanup(func() { _ = s.Close() })
	send := func(message []byte) {
		if err := writeFull(server, message); err != nil {
			t.Fatalf("server: %v", err)
		}
	}
	return s, send
}

func grayRaw(w, h int) []byte {
	var body []byte
	for i := 0; i < w*h; i++ {
		body = append(body, 0x80, 0x80, 0x80, 0)
	}
	return body
}

func nextVNCFrame(t *testing.T, s *Session, what string) *image.RGBA {
	t.Helper()
	select {
	case m, ok := <-s.Frames():
		if !ok {
			t.Fatalf("%s: the stream ended: %v", what, s.Err())
		}
		decoded, err := png.Decode(bytes.NewReader(m.PNG))
		if err != nil {
			t.Fatal(err)
		}
		return decoded.(*image.RGBA)
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: no frame", what)
	}
	return nil
}

func noVNCFrame(t *testing.T, s *Session, what string) {
	t.Helper()
	select {
	case m, ok := <-s.Frames():
		if ok {
			t.Fatalf("%s: frame %d", what, m.Sequence)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

func isRed(img *image.RGBA, x, y int) bool {
	c := img.RGBAAt(x, y)
	return c.R == 0xff && c.G == 0 && c.B == 0
}

// The target's shape is drawn where the operator put the pointer, a move is a frame of its own,
// a click in place is not, and an empty shape hides it.
func TestSessionDrawsTheTargetsCursorWhereTheOperatorPutIt(t *testing.T) {
	s, send := drawingSession(t, true)
	if !s.PointerDrawn() {
		t.Fatal("the session does not say it draws the pointer")
	}
	red := cursorBody(2, 2, [4]byte{0, 0, 0xff, 0}, []byte{0xc0, 0xc0})
	send(update(rectangle(0, 0, 8, 8, 0, grayRaw(8, 8)), rectangle(1, 1, 2, 2, -239, red)))
	if isRed(nextVNCFrame(t, s, "the desktop"), 0, 0) {
		t.Fatal("drawn before the operator placed the pointer")
	}
	if err := s.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 4, Y: 4}); err != nil {
		t.Fatal(err)
	}
	moved := nextVNCFrame(t, s, "the move")
	if !isRed(moved, 3, 3) || !isRed(moved, 4, 4) || isRed(moved, 5, 5) || isRed(moved, 2, 2) {
		t.Fatal("the shape is not at the pointer, hot spot (1,1)")
	}
	if err := s.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 4, Y: 4, Buttons: 1}); err != nil {
		t.Fatal(err)
	}
	noVNCFrame(t, s, "a click in place")
	send(update(rectangle(0, 0, 0, 0, -239, nil)))
	if isRed(nextVNCFrame(t, s, "the empty shape"), 4, 4) {
		t.Fatal("an empty shape still shows the pointer")
	}
	// The framebuffer never held the pointer: a repaint elsewhere does not bring it back.
	if isRed(&image.RGBA{Pix: s.framebuffer.Pix, Stride: s.framebuffer.Stride, Rect: s.framebuffer.Rect}, 4, 4) {
		t.Fatal("the pointer was drawn into the framebuffer")
	}
}

// Not drawn, the shape is read and thrown away as before, and a move is no frame.
func TestSessionNotDrawingThePointerIgnoresIt(t *testing.T) {
	s, send := drawingSession(t, false)
	if s.PointerDrawn() {
		t.Fatal("the session says it draws the pointer")
	}
	send(update(rectangle(0, 0, 8, 8, 0, grayRaw(8, 8)), rectangle(1, 1, 2, 2, -239, cursorBody(2, 2, [4]byte{0, 0, 0xff, 0}, []byte{0xc0, 0xc0}))))
	nextVNCFrame(t, s, "the desktop")
	if err := s.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 4, Y: 4}); err != nil {
		t.Fatal(err)
	}
	noVNCFrame(t, s, "a move, the pointer not drawn")
}

// A shape out of bounds ends the session, with the framebuffer's refusal.
func TestSessionEndsOnACursorOutOfBounds(t *testing.T) {
	s, server := pipeSession(t, 8, 8)
	s.drawPointer, s.pointerMoved, s.pointerLoopDone = true, make(chan struct{}, 1), make(chan struct{})
	go s.pointerLoop()
	go s.readLoop()
	t.Cleanup(func() { _ = s.Close() })
	// The client stops reading at the header it refuses: the rest is written from aside.
	go func() {
		_ = writeFull(server, update(rectangle(0, 0, 129, 1, -239, cursorBody(129, 1, [4]byte{}, make([]byte, 17)))))
	}()
	for range s.Frames() {
	}
	if err := s.Err(); !errors.Is(err, ErrInvalidFramebuffer) {
		t.Fatalf("%v, want ErrInvalidFramebuffer", err)
	}
}

func FuzzReadCursor(f *testing.F) {
	f.Add(uint16(1), uint16(1), uint16(2), uint16(2), cursorBody(2, 2, [4]byte{1, 2, 3, 4}, []byte{0xc0, 0x40}))
	f.Add(uint16(0), uint16(0), uint16(0), uint16(0), []byte{})
	f.Fuzz(func(t *testing.T, hotX, hotY, w, h uint16, body []byte) {
		c, err := readCursor(bytes.NewReader(body), hotX, hotY, w, h)
		if err != nil {
			return
		}
		if c.width > maxCursorSide || c.height > maxCursorSide || c.hotX >= maxCursorSide || c.hotY >= maxCursorSide ||
			len(c.rgba) != c.width*c.height*4 {
			t.Fatalf("an unbounded cursor: %d×%d hot %d,%d, %d bytes", c.width, c.height, c.hotX, c.hotY, len(c.rgba))
		}
		c.drawOn(image.NewRGBA(image.Rect(0, 0, 8, 8)), int(hotX%16)-4, int(hotY%16)-4)
	})
}

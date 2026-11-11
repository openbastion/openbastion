package screenstream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"reflect"
	"testing"
	"time"
)

func pngOf(t testing.TB, w, h int, fill func(x, y int) color.RGBA) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, fill(x, y))
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func solid(c color.RGBA) func(int, int) color.RGBA { return func(int, int) color.RGBA { return c } }

var (
	gray  = color.RGBA{0x80, 0x80, 0x80, 0xff}
	red   = color.RGBA{0xff, 0, 0, 0xff}
	blue  = color.RGBA{0, 0, 0xff, 0xff}
	stamp = time.Unix(1, 0).UTC()
)

func keyFrame(t testing.TB, seq uint64, w, h int, fill func(int, int) color.RGBA) Message {
	return Message{Type: TypeFrame, Sequence: seq, Timestamp: stamp, Width: uint32(w), Height: uint32(h), PNG: pngOf(t, w, h, fill)}
}

func delta(seq uint64, w, h uint32, rects ...Rect) Message {
	return Message{Type: TypeFrameDelta, Sequence: seq, Timestamp: stamp, Width: w, Height: h, Rects: rects}
}

func TestFrameDeltaRoundTrip(t *testing.T) {
	in := delta(7, 16, 8,
		Rect{X: 1, Y: 2, Width: 3, Height: 2, PNG: pngOf(t, 3, 2, solid(red))},
		Rect{X: 15, Y: 7, Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(blue))})
	wire, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if MessageType(wire[1]) != TypeFrameDelta || binary.BigEndian.Uint16(wire[HeaderSize:]) != 2 {
		t.Fatalf("type %d, count %d", wire[1], binary.BigEndian.Uint16(wire[HeaderSize:]))
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip:\n%+v\n%+v", got, in)
	}
}

// Every bound of ADR-0092 §2, at encoding and at decoding.
func TestFrameDeltaOutsideItsBoundsIsRefused(t *testing.T) {
	px := pngOf(t, 1, 1, solid(red))
	one := Rect{X: 0, Y: 0, Width: 1, Height: 1, PNG: px}
	many := make([]Rect, MaxDeltaRects+1)
	for i := range many {
		many[i] = one
	}
	cases := map[string]Message{
		"no rectangle":         delta(1, 4, 4),
		"65 rectangles":        delta(1, 4, 4, many...),
		"empty rectangle":      delta(1, 4, 4, Rect{Width: 0, Height: 1, PNG: px}),
		"past the right edge":  delta(1, 4, 4, Rect{X: 4, Width: 1, Height: 1, PNG: px}),
		"past the bottom edge": delta(1, 4, 4, Rect{Y: 3, Width: 1, Height: 2, PNG: px}),
		"overflowing x":        delta(1, 4, 4, Rect{X: ^uint32(0), Width: 2, Height: 1, PNG: px}),
		"no PNG":               delta(1, 4, 4, Rect{Width: 1, Height: 1}),
		"not a PNG":            delta(1, 4, 4, Rect{Width: 1, Height: 1, PNG: []byte("12345678")}),
		"sequence zero":        delta(0, 4, 4, one),
		"no size":              delta(1, 0, 4, one),
		"too many pixels":      delta(1, MaxPixels, 2, one),
		"a PNG of its own":     func() Message { m := delta(1, 4, 4, one); m.PNG = px; return m }(),
		"over 4 MiB": delta(1, 4, 4, Rect{Width: 1, Height: 1,
			PNG: append(append([]byte(nil), px...), make([]byte, MaxPNGBytes)...)}),
	}
	for name, m := range cases {
		if _, err := Encode(m); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	// A key frame carrying rectangles is not a key frame.
	key := keyFrame(t, 1, 2, 2, solid(gray))
	key.Rects = []Rect{one}
	if _, err := Encode(key); err == nil {
		t.Error("a FRAME with rectangles encoded")
	}

	good, err := Encode(delta(1, 4, 4, one))
	if err != nil {
		t.Fatal(err)
	}
	tamper := func(edit func([]byte) []byte) []byte {
		b := edit(append([]byte(nil), good...))
		binary.BigEndian.PutUint32(b[28:32], uint32(len(b)-HeaderSize))
		return b
	}
	wire := map[string][]byte{
		"count zero":         tamper(func(b []byte) []byte { binary.BigEndian.PutUint16(b[HeaderSize:], 0); return b }),
		"count beyond":       tamper(func(b []byte) []byte { binary.BigEndian.PutUint16(b[HeaderSize:], 2); return b }),
		"PNG length beyond":  tamper(func(b []byte) []byte { binary.BigEndian.PutUint32(b[HeaderSize+2+16:], uint32(len(px)+1)); return b }),
		"PNG length short":   tamper(func(b []byte) []byte { binary.BigEndian.PutUint32(b[HeaderSize+2+16:], uint32(len(px)-1)); return b }),
		"a byte left over":   tamper(func(b []byte) []byte { return append(b, 0) }),
		"header cut":         tamper(func(b []byte) []byte { return b[:HeaderSize+2+10] }),
		"no count":           tamper(func(b []byte) []byte { return b[:HeaderSize+1] }),
		"rectangle outside":  tamper(func(b []byte) []byte { binary.BigEndian.PutUint32(b[HeaderSize+2:], 4); return b }),
		"length lies":        func() []byte { b := append([]byte(nil), good...); binary.BigEndian.PutUint32(b[28:32], 3); return b }(),
		"sequence zero wire": tamper(func(b []byte) []byte { binary.BigEndian.PutUint64(b[4:12], 0); return b }),
	}
	for name, b := range wire {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// The screen composed from a key frame and partial frames is, pixel for pixel, the screen a key
// frame of the same moment shows: what the operator saw is what the auditor replays (ADR-0092 §6).
func TestComposerRebuildsTheScreenAKeyFrameShows(t *testing.T) {
	var c Composer
	if c.Screen() != nil {
		t.Fatal("a screen before any key frame")
	}
	if err := c.Apply(delta(1, 8, 4, Rect{Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(red))})); !errors.Is(err, ErrNoKeyFrame) {
		t.Fatalf("a partial frame first: %v", err)
	}
	steps := []Message{
		keyFrame(t, 1, 8, 4, solid(gray)),
		delta(2, 8, 4, Rect{X: 1, Y: 1, Width: 2, Height: 2, PNG: pngOf(t, 2, 2, solid(red))}),
		delta(3, 8, 4,
			Rect{X: 2, Y: 0, Width: 1, Height: 4, PNG: pngOf(t, 1, 4, solid(blue))},
			Rect{X: 7, Y: 3, Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(red))}),
	}
	for _, m := range steps {
		if err := c.Apply(m); err != nil {
			t.Fatalf("sequence %d: %v", m.Sequence, err)
		}
	}
	want := func(x, y int) color.RGBA {
		switch {
		case x == 2:
			return blue // the second partial frame, over the first
		case x == 1 && (y == 1 || y == 2), x == 7 && y == 3:
			return red
		}
		return gray
	}
	key := keyFrame(t, 3, 8, 4, want)
	var fromKey Composer
	if err := fromKey.Apply(key); err != nil {
		t.Fatal(err)
	}
	if got := c.Screen(); !bytes.Equal(got.Pix, fromKey.Screen().Pix) || c.Sequence() != 3 {
		t.Fatalf("composed screen differs from the key frame of the same moment, at sequence %d", c.Sequence())
	}
	// Screen is a copy: changing it changes nothing composed.
	c.Screen().Pix[0] = 0
	if c.Screen().Pix[0] != 0x80 {
		t.Fatal("Screen hands out the composer's own pixels")
	}
}

func TestComposerRefusesWhatWouldComposeAWrongScreen(t *testing.T) {
	cases := map[string]Message{
		"a gap":                 delta(3, 8, 4, Rect{Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(red))}),
		"another size":          delta(2, 4, 4, Rect{Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(red))}),
		"a PNG of another size": delta(2, 8, 4, Rect{Width: 2, Height: 1, PNG: pngOf(t, 1, 1, solid(red))}),
		"a PNG that does not decode": delta(2, 8, 4, Rect{Width: 1, Height: 1,
			PNG: append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 16)...)}),
	}
	for name, m := range cases {
		var c Composer
		if err := c.Apply(keyFrame(t, 1, 8, 4, solid(gray))); err != nil {
			t.Fatal(err)
		}
		before := c.Screen()
		if err := c.Apply(m); err == nil {
			t.Errorf("%s: composed", name)
			continue
		}
		if c.Screen() != nil {
			t.Errorf("%s: the composer still shows a screen after a refusal", name)
		}
		// Unusable until a key frame, which makes it whole again.
		if err := c.Apply(delta(2, 8, 4, Rect{Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(red))})); !errors.Is(err, ErrNoKeyFrame) {
			t.Errorf("%s: a partial frame after the refusal: %v", name, err)
		}
		if err := c.Apply(keyFrame(t, 5, 8, 4, solid(gray))); err != nil || !bytes.Equal(c.Screen().Pix, before.Pix) {
			t.Errorf("%s: a key frame does not restore the screen: %v", name, err)
		}
	}
	// One bad rectangle among good ones refuses the whole partial frame.
	var c Composer
	_ = c.Apply(keyFrame(t, 1, 8, 4, solid(gray)))
	err := c.Apply(delta(2, 8, 4,
		Rect{Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(red))},
		Rect{X: 1, Width: 2, Height: 1, PNG: pngOf(t, 1, 1, solid(red))}))
	if err == nil {
		t.Fatal("a partial frame with one bad rectangle composed")
	}
}

func FuzzComposer(f *testing.F) {
	good, _ := Encode(delta(2, 8, 4, Rect{X: 1, Y: 1, Width: 2, Height: 2, PNG: pngOf(f, 2, 2, solid(red))}))
	f.Add(good)
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err != nil {
			return
		}
		var c Composer
		if err := c.Apply(keyFrame(t, 1, 8, 4, solid(gray))); err != nil {
			t.Fatal(err)
		}
		if err := c.Apply(m); err != nil {
			return
		}
		if s := c.Screen(); s == nil || s.Bounds().Dx() != int(m.Width) || s.Bounds().Dy() != int(m.Height) {
			t.Fatalf("composed a screen of the wrong size for %+v", m)
		}
	})
}

// A rectangle replaces the pixels under it, it is never blended: even a clear pixel replaces what
// was there, as on the operator's page and in the replay (ADR-0092 §6).
func TestComposerReplacesPixelsWithoutBlending(t *testing.T) {
	var c Composer
	if err := c.Apply(keyFrame(t, 1, 2, 1, solid(gray))); err != nil {
		t.Fatal(err)
	}
	clear := color.RGBA{0, 0, 0, 0}
	if err := c.Apply(delta(2, 2, 1, Rect{X: 1, Width: 1, Height: 1, PNG: pngOf(t, 1, 1, solid(clear))})); err != nil {
		t.Fatal(err)
	}
	if got := c.Screen().RGBAAt(1, 0); got != clear {
		t.Fatalf("(1,0) is %v: the rectangle was blended over the screen, not put in its place", got)
	}
	if got := c.Screen().RGBAAt(0, 0); got != gray {
		t.Fatalf("(0,0) is %v, outside the rectangle", got)
	}
}

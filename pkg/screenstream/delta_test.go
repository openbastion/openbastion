package screenstream

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"math/rand"
	"testing"
	"time"
)

func canvas(w, h int, c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

func fillRect(img *image.RGBA, r image.Rectangle, c color.RGBA) {
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			img.SetRGBA(x, y, c)
		}
	}
}

// encodeAndCompose encodes picture, composes the frame, and checks the composed screen is picture.
func encodeAndCompose(t *testing.T, e *FrameEncoder, c *Composer, picture *image.RGBA, seq uint64, at time.Time) Message {
	t.Helper()
	m, err := e.Encode(picture, seq, at)
	if err != nil {
		t.Fatalf("sequence %d: %v", seq, err)
	}
	wire, err := Encode(m)
	if err != nil {
		t.Fatalf("sequence %d does not encode: %v", seq, err)
	}
	back, err := Decode(wire)
	if err != nil {
		t.Fatalf("sequence %d does not decode: %v", seq, err)
	}
	if err := c.Apply(back); err != nil {
		t.Fatalf("sequence %d does not compose: %v", seq, err)
	}
	if !bytes.Equal(c.Screen().Pix, picture.Pix) {
		t.Fatalf("sequence %d (%v): the composed screen is not the picture", seq, m.Type)
	}
	return m
}

func TestFrameEncoderSendsOnlyWhatChanged(t *testing.T) {
	var e FrameEncoder
	var c Composer
	at := time.Unix(100, 0)
	picture := canvas(128, 96, gray)
	if m := encodeAndCompose(t, &e, &c, picture, 1, at); m.Type != TypeFrame {
		t.Fatalf("the first frame is a %v, want a key frame", m.Type)
	}
	// One pixel: one tile.
	picture.SetRGBA(40, 10, red)
	m := encodeAndCompose(t, &e, &c, picture, 2, at.Add(time.Second))
	if m.Type != TypeFrameDelta || len(m.Rects) != 1 || m.Rects[0].X != 32 || m.Rects[0].Y != 0 || m.Rects[0].Width != 32 || m.Rects[0].Height != 32 {
		t.Fatalf("one pixel changed: %v with %d rectangle(s) %+v", m.Type, len(m.Rects), m.Rects)
	}
	// An aligned 64x64 block: four tiles, one rectangle.
	fillRect(picture, image.Rect(64, 32, 128, 96), blue)
	m = encodeAndCompose(t, &e, &c, picture, 3, at.Add(2*time.Second))
	if m.Type != TypeFrameDelta || len(m.Rects) != 1 || m.Rects[0].Width != 64 || m.Rects[0].Height != 64 {
		t.Fatalf("a 64x64 block: %d rectangle(s) %+v", len(m.Rects), m.Rects)
	}
	// Nothing changed: no frame.
	if _, err := e.Encode(picture, 4, at.Add(3*time.Second)); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("an unchanged picture: %v", err)
	}
	// The encoder keeps a copy: changing the picture afterwards is a change.
	picture.SetRGBA(0, 95, red)
	if m := encodeAndCompose(t, &e, &c, picture, 4, at.Add(4*time.Second)); m.Type != TypeFrameDelta || len(m.Rects) != 1 {
		t.Fatalf("%v, %d rectangle(s)", m.Type, len(m.Rects))
	}
}

func TestFrameEncoderMakesKeyFramesWhenItMust(t *testing.T) {
	at := time.Unix(100, 0)
	t.Run("every KeyFrames frames", func(t *testing.T) {
		e := FrameEncoder{KeyFrames: 3}
		var c Composer
		picture := canvas(64, 64, gray)
		var kinds []MessageType
		for i := 1; i <= 7; i++ {
			picture.SetRGBA(i, i, color.RGBA{byte(i), 0, 0, 0xff})
			kinds = append(kinds, encodeAndCompose(t, &e, &c, picture, uint64(i), at).Type)
		}
		want := []MessageType{TypeFrame, TypeFrameDelta, TypeFrameDelta, TypeFrame, TypeFrameDelta, TypeFrameDelta, TypeFrame}
		for i := range want {
			if kinds[i] != want[i] {
				t.Fatalf("frames %v, want %v", kinds, want)
			}
		}
	})
	t.Run("every KeyInterval", func(t *testing.T) {
		e := FrameEncoder{KeyInterval: 10 * time.Second}
		var c Composer
		picture := canvas(64, 64, gray)
		encodeAndCompose(t, &e, &c, picture, 1, at)
		picture.SetRGBA(1, 1, red)
		if m := encodeAndCompose(t, &e, &c, picture, 2, at.Add(9*time.Second)); m.Type != TypeFrameDelta {
			t.Fatal("a key frame before the interval")
		}
		picture.SetRGBA(2, 2, red)
		if m := encodeAndCompose(t, &e, &c, picture, 3, at.Add(10*time.Second)); m.Type != TypeFrame {
			t.Fatal("no key frame at the interval")
		}
	})
	t.Run("a new size", func(t *testing.T) {
		var e FrameEncoder
		var c Composer
		encodeAndCompose(t, &e, &c, canvas(64, 64, gray), 1, at)
		if m := encodeAndCompose(t, &e, &c, canvas(96, 64, gray), 2, at); m.Type != TypeFrame {
			t.Fatal("no key frame on a new size")
		}
	})
	t.Run("more than half the screen", func(t *testing.T) {
		var e FrameEncoder
		var c Composer
		picture := canvas(64, 64, gray)
		encodeAndCompose(t, &e, &c, picture, 1, at)
		fillRect(picture, image.Rect(0, 0, 64, 33), red) // two rows of tiles of two: all four tiles
		if m := encodeAndCompose(t, &e, &c, picture, 2, at); m.Type != TypeFrame {
			t.Fatal("a change over more than half the screen is not a key frame")
		}
		fillRect(picture, image.Rect(0, 0, 64, 32), blue) // half: two tiles of four
		if m := encodeAndCompose(t, &e, &c, picture, 3, at); m.Type != TypeFrameDelta {
			t.Fatal("exactly half the screen is a partial frame")
		}
	})
	t.Run("more than MaxDeltaRects rectangles", func(t *testing.T) {
		var e FrameEncoder
		var c Composer
		picture := canvas(1280, 800, gray)
		encodeAndCompose(t, &e, &c, picture, 1, at)
		for row := 0; row < 25; row++ {
			for column := row % 2; column < 40; column += 2 { // a checkerboard of tiles: none merges
				picture.SetRGBA(column*32, row*32, red)
			}
		}
		if m := encodeAndCompose(t, &e, &c, picture, 2, at); m.Type != TypeFrame {
			t.Fatal("500 separate tiles are not a key frame")
		}
	})
	t.Run("after Reset", func(t *testing.T) {
		var e FrameEncoder
		var c Composer
		picture := canvas(64, 64, gray)
		encodeAndCompose(t, &e, &c, picture, 1, at)
		e.Reset()
		picture.SetRGBA(1, 1, red)
		if m := encodeAndCompose(t, &e, &c, picture, 2, at); m.Type != TypeFrame {
			t.Fatal("no key frame after Reset")
		}
	})
}

// Whatever changes, in whatever shape, composing the frames gives the pictures back, frame after
// frame: the property ADR-0092 §6 rests on.
func TestFrameEncoderComposesBackToEveryPicture(t *testing.T) {
	random := rand.New(rand.NewSource(92))
	var e FrameEncoder
	var c Composer
	at := time.Unix(100, 0)
	picture := canvas(300, 170, gray) // sizes that are not multiples of the tile
	encodeAndCompose(t, &e, &c, picture, 1, at)
	seq := uint64(1)
	for step := 0; step < 200; step++ {
		for n := random.Intn(4); n >= 0; n-- {
			x, y := random.Intn(300), random.Intn(170)
			r := image.Rect(x, y, x+1+random.Intn(60), y+1+random.Intn(40)).Intersect(picture.Bounds())
			fillRect(picture, r, color.RGBA{byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256)), 0xff})
		}
		m, err := e.Encode(picture, seq+1, at.Add(time.Duration(step)*100*time.Millisecond))
		if errors.Is(err, ErrUnchanged) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		seq++
		if err := c.Apply(m); err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		if !bytes.Equal(c.Screen().Pix, picture.Pix) {
			t.Fatalf("step %d (%v, %d rectangles): the composed screen is not the picture", step, m.Type, len(m.Rects))
		}
	}
}

func TestFrameEncoderRefusesWhatIsNotAFrame(t *testing.T) {
	var e FrameEncoder
	for name, call := range map[string]func() error{
		"no picture":    func() error { _, err := e.Encode(nil, 1, time.Unix(1, 0)); return err },
		"sequence zero": func() error { _, err := e.Encode(canvas(2, 2, gray), 0, time.Unix(1, 0)); return err },
		"no time":       func() error { _, err := e.Encode(canvas(2, 2, gray), 1, time.Time{}); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	// A key frame past MaxPNGBytes ends as a recording loss, as before ADR-0092.
	noise := image.NewRGBA(image.Rect(0, 0, 1600, 1200))
	random := rand.New(rand.NewSource(1))
	random.Read(noise.Pix)
	if _, err := e.Encode(noise, 1, time.Unix(1, 0)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a key frame of %d pixels of noise: %v", len(noise.Pix)/4, err)
	}
}

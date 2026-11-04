package rdp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

func TestRDPFramebufferAppliesPartialRectanglesToCompletePNG(t *testing.T) {
	fb, err := NewRDPFramebuffer(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(10, 0)
	first, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{Width: 1, Height: 1, Pixels: []byte{255, 0, 0, 255}}}}, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || first.Width != 2 || first.Height != 1 {
		t.Fatalf("first frame metadata = %+v", first)
	}
	img1, err := png.Decode(bytes.NewReader(first.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img1.At(0, 0)).(color.RGBA); got != (color.RGBA{R: 255, A: 255}) {
		t.Fatalf("pixel 0 = %#v", got)
	}
	if got := color.RGBAModel.Convert(img1.At(1, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("untouched pixel = %#v", got)
	}

	second, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Width: 1, Height: 1, Pixels: []byte{0, 255, 0, 255}}}}, stamp.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 2 {
		t.Fatalf("sequence = %d", second.Sequence)
	}
	img2, err := png.Decode(bytes.NewReader(second.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img2.At(0, 0)).(color.RGBA); got != (color.RGBA{R: 255, A: 255}) {
		t.Fatalf("preserved pixel = %#v", got)
	}
	if got := color.RGBAModel.Convert(img2.At(1, 0)).(color.RGBA); got != (color.RGBA{G: 255, A: 255}) {
		t.Fatalf("updated pixel = %#v", got)
	}
	if _, err := screenstream.Encode(second); err != nil {
		t.Fatalf("screenstream contract rejected frame: %v", err)
	}
}

func TestRDPFramebufferRejectsInvalidUpdateAtomically(t *testing.T) {
	fb, err := NewRDPFramebuffer(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{
		{Width: 1, Height: 1, Pixels: []byte{255, 0, 0, 255}},
		{X: 2, Width: 1, Height: 1, Pixels: []byte{0, 255, 0, 255}},
	}}, time.Now())
	if err == nil {
		t.Fatal("out-of-bounds rectangle accepted")
	}
	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Width: 1, Height: 1, Pixels: []byte{0, 0, 255, 255}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("invalid update partially mutated framebuffer: %#v", got)
	}
	if frame.Sequence != 1 {
		t.Fatalf("failed update consumed sequence: %d", frame.Sequence)
	}
}

func TestNewRDPFramebufferEnforcesPixelAndDimensionBounds(t *testing.T) {
	for _, tc := range []struct{ w, h uint16 }{{0, 1}, {1, 0}, {4096, 4097}} {
		if _, err := NewRDPFramebuffer(tc.w, tc.h); err == nil {
			t.Fatalf("accepted %dx%d", tc.w, tc.h)
		}
	}
	fb, err := NewRDPFramebuffer(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := fb.image.Bounds(); got != image.Rect(0, 0, 1, 1) {
		t.Fatalf("bounds = %v", got)
	}
}

func TestRDPFramebufferRollsBackWhenPNGExceedsScreenStreamLimit(t *testing.T) {
	const width, height = 1050, 1050
	fb, err := NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	pixels := make([]byte, int(width)*int(height)*4)
	state := uint32(0x9e3779b9)
	for i := range pixels {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		pixels[i] = byte(state)
	}
	_, err = fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{Width: width, Height: height, Pixels: pixels}}}, time.Now())
	if err == nil {
		t.Fatal("oversized PNG was accepted")
	}
	clear(pixels)

	frame, err := fb.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Y: 1, Width: 1, Height: 1, Pixels: []byte{0, 0, 255, 255}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 {
		t.Fatalf("failed encode consumed sequence: %d", frame.Sequence)
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA); got != (color.RGBA{A: 255}) {
		t.Fatalf("oversized update was not rolled back: %#v", got)
	}
}

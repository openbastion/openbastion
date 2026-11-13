package engine

import (
	"image"
	"image/color"
	"testing"
)

// Notepad's text area is found wherever its window is, and nothing is found on a screen without one.
func TestWhiteSquareCentre(t *testing.T) {
	screen := func(white image.Rectangle) *image.RGBA {
		img := image.NewRGBA(image.Rect(0, 0, 1280, 800))
		for y := 0; y < 800; y++ {
			for x := 0; x < 1280; x++ {
				c := color.RGBA{0, 0, 0, 255}
				if (image.Point{x, y}).In(white) {
					c = color.RGBA{255, 255, 255, 255}
				}
				img.Set(x, y, c)
			}
		}
		return img
	}
	for _, area := range []image.Rectangle{image.Rect(1, 75, 782, 525), image.Rect(95, 182, 1022, 632)} {
		x, y, ok := whiteSquareCentre(screen(area), 120)
		if !ok || !(image.Point{int(x), int(y)}).In(area) {
			t.Fatalf("area %v: (%d, %d) %v", area, x, y, ok)
		}
	}
	if _, _, ok := whiteSquareCentre(screen(image.Rect(10, 10, 100, 700)), 120); ok {
		t.Fatal("a white strip narrower than the square was taken for a text area")
	}
}

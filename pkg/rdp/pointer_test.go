package rdp

import (
	"encoding/binary"
	"errors"
	"image"
	"testing"
)

// colorPointer builds a TS_COLORPOINTERATTRIBUTE from top-down pixels (B, G, R[, A] each) and AND
// bits, writing the masks bottom-up with scan lines padded to two bytes, as a target does.
func colorPointer(index, hotX, hotY uint16, width, height, bpp int, pixels [][]byte, and [][]bool) []byte {
	xorLine := evenBytes((width*bpp + 7) / 8)
	andLine := evenBytes((width + 7) / 8)
	xorMask := make([]byte, xorLine*height)
	andMask := make([]byte, andLine*height)
	for y := 0; y < height; y++ {
		row := height - 1 - y
		for x := 0; x < width; x++ {
			copy(xorMask[row*xorLine+x*bpp/8:], pixels[y*width+x])
			if and[y][x] {
				andMask[row*andLine+x/8] |= 0x80 >> (x % 8)
			}
		}
	}
	out := make([]byte, 14)
	binary.LittleEndian.PutUint16(out[0:2], index)
	binary.LittleEndian.PutUint16(out[2:4], hotX)
	binary.LittleEndian.PutUint16(out[4:6], hotY)
	binary.LittleEndian.PutUint16(out[6:8], uint16(width))
	binary.LittleEndian.PutUint16(out[8:10], uint16(height))
	binary.LittleEndian.PutUint16(out[10:12], uint16(len(andMask)))
	binary.LittleEndian.PutUint16(out[12:14], uint16(len(xorMask)))
	return append(append(out, xorMask...), andMask...)
}

func newPointer(bpp int, attribute []byte) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, uint16(bpp)), attribute...)
}

func pointerPDU(messageType uint16, attribute []byte) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, messageType), append([]byte{0, 0}, attribute...)...)
}

func rgbaAt(shape *RDPPointerImage, x, y int) [4]byte {
	i := (y*shape.Width + x) * 4
	return [4]byte(shape.RGBA[i : i+4])
}

// A 24-bit shape, 3×2: the masks are bottom-up, lines padded (9 → 10 bytes, 1 → 2), and the AND and
// XOR masks give opaque, clear and inverting pixels.
func TestColorPointerDecodesBothMasksBottomUp(t *testing.T) {
	red, white, black, blue := []byte{0, 0, 0xff}, []byte{0xff, 0xff, 0xff}, []byte{0, 0, 0}, []byte{0xff, 0, 0}
	attribute := colorPointer(7, 2, 1, 3, 2, 24,
		[][]byte{red, white, black, blue, black, white},
		[][]bool{{false, true, true}, {false, false, true}})
	if len(attribute) != 14+20+4 {
		t.Fatalf("the test builds %d bytes", len(attribute))
	}
	for name, parse := range map[string]func() (RDPPointerUpdate, error){
		"fast-path color": func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(rdpFastPathPointerColor, attribute) },
		"slow-path color": func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessageColor, attribute))
		},
		"fast-path new 24": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerNew, newPointer(24, attribute))
		},
		"padded": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, append(attribute[:len(attribute):len(attribute)], 0))
		},
	} {
		update, err := parse()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		shape := update.Shape
		if update.Kind != RDPPointerShape || update.CacheIndex != 7 || shape.Width != 3 || shape.Height != 2 ||
			shape.HotX != 2 || shape.HotY != 1 {
			t.Fatalf("%s: %+v", name, update)
		}
		if got := rgbaAt(shape, 0, 0); got != [4]byte{0xff, 0, 0, 0xff} || shape.XOR[0] {
			t.Fatalf("%s: top-left is %v, want opaque red", name, got)
		}
		if !shape.XOR[1] || rgbaAt(shape, 1, 0) != [4]byte{0xff, 0xff, 0xff, 0} {
			t.Fatalf("%s: white under AND must invert the desktop", name)
		}
		if shape.XOR[2] || rgbaAt(shape, 2, 0) != [4]byte{} {
			t.Fatalf("%s: black under AND must be clear", name)
		}
		if rgbaAt(shape, 0, 1) != [4]byte{0, 0, 0xff, 0xff} || rgbaAt(shape, 1, 1) != [4]byte{0, 0, 0, 0xff} {
			t.Fatalf("%s: second row %v %v, want opaque blue and black", name, rgbaAt(shape, 0, 1), rgbaAt(shape, 1, 1))
		}
		if !shape.XOR[5] {
			t.Fatalf("%s: bottom-right white under AND must invert", name)
		}
	}
}

// A 32-bit shape carries its alpha; one whose alpha is zero everywhere is read as 24-bit.
func TestNewPointerAt32BitsKeepsItsAlpha(t *testing.T) {
	half := []byte{0x10, 0x20, 0x30, 0x80}
	clear := []byte{0, 0, 0, 0}
	update, err := parseRDPFastPathPointer(rdpFastPathPointerNew, newPointer(32,
		colorPointer(0, 0, 0, 3, 1, 32, [][]byte{half, clear, {0xff, 0xff, 0xff, 0}}, [][]bool{{false, true, true}})))
	if err != nil {
		t.Fatal(err)
	}
	if got := rgbaAt(update.Shape, 0, 0); got != [4]byte{0x30, 0x20, 0x10, 0x80} {
		t.Fatalf("alpha pixel %v", got)
	}
	if got := rgbaAt(update.Shape, 1, 0); got != [4]byte{} || update.Shape.XOR[1] {
		t.Fatalf("clear pixel %v", got)
	}
	if !update.Shape.XOR[2] {
		t.Fatal("white under AND, without alpha, inverts the desktop even in a shape with alpha")
	}

	noAlpha, err := parseRDPPointerPDU(pointerPDU(rdpPointerMessageNew, newPointer(32,
		colorPointer(0, 0, 0, 2, 1, 32, [][]byte{{1, 2, 3, 0}, {0xff, 0xff, 0xff, 0}}, [][]bool{{false, true}}))))
	if err != nil {
		t.Fatal(err)
	}
	if got := rgbaAt(noAlpha.Shape, 0, 0); got != [4]byte{3, 2, 1, 0xff} || !noAlpha.Shape.XOR[1] {
		t.Fatalf("a shape without alpha is opaque where AND is clear (%v), inverting where set", got)
	}
}

func TestPointerUpdatesWithoutAShape(t *testing.T) {
	for _, c := range []struct {
		name string
		got  func() (RDPPointerUpdate, error)
		want RDPPointerUpdate
	}{
		{"fast-path hidden", func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(rdpFastPathPointerHidden, nil) },
			RDPPointerUpdate{Kind: RDPPointerHidden}},
		{"fast-path default", func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(rdpFastPathPointerDefault, nil) },
			RDPPointerUpdate{Kind: RDPPointerDefault}},
		{"fast-path position", func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerPosition, []byte{0x10, 0x02, 0x20, 0x01})
		}, RDPPointerUpdate{Kind: RDPPointerPosition, X: 0x210, Y: 0x120}},
		{"fast-path cached", func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerCached, []byte{24, 0})
		},
			RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: 24}},
		{"system null", func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessageSystem, []byte{0, 0, 0, 0}))
		}, RDPPointerUpdate{Kind: RDPPointerHidden}},
		{"system default", func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessageSystem, []byte{0, 0x7f, 0, 0}))
		}, RDPPointerUpdate{Kind: RDPPointerDefault}},
		{"slow-path position", func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessagePosition, []byte{1, 0, 2, 0}))
		}, RDPPointerUpdate{Kind: RDPPointerPosition, X: 1, Y: 2}},
		{"slow-path cached", func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessageCached, []byte{3, 0}))
		}, RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: 3}},
	} {
		got, err := c.got()
		if err != nil || got != c.want {
			t.Fatalf("%s: %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}
}

// Every byte a target sends is bounded: a shape larger than announced, lengths that do not match
// its size, a hot spot outside it, a cache entry that does not exist, an unknown message — each
// closes the session.
func TestPointerUpdatesOutsideTheProfileAreRefused(t *testing.T) {
	pixel := []byte{1, 2, 3}
	valid := colorPointer(0, 0, 0, 1, 1, 24, [][]byte{pixel}, [][]bool{{false}})
	set16 := func(b []byte, at int, v uint16) []byte {
		out := append([]byte(nil), b...)
		binary.LittleEndian.PutUint16(out[at:at+2], v)
		return out
	}
	big := make([][]byte, 33*1)
	for i := range big {
		big[i] = pixel
	}
	cases := map[string]func() (RDPPointerUpdate, error){
		"cache index 25": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 0, 25))
		},
		"hot spot x at 32": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 2, 32))
		},
		"hot spot y at 32": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 4, 32))
		},
		"AND length + 2": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 10, 4))
		},
		"AND length - 2": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 10, 0))
		},
		"XOR length + 2": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 12, 6))
		},
		"XOR length - 2": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 12, 2))
		},
		"width without height": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(valid, 8, 0))
		},
		"33 pixels wide": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, colorPointer(0, 0, 0, 33, 1, 24, big, [][]bool{make([]bool, 33)}))
		},
		"XOR length + 2, bytes present": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, append(set16(valid, 12, 6), 0, 0))
		},
		"AND length + 2, bytes present": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, append(set16(valid, 10, 4), 0, 0))
		},
		"height without width": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, set16(colorPointer(0, 0, 0, 0, 0, 24, nil, nil), 8, 1))
		},
		"new at 16 bpp, well formed": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerNew, newPointer(16, colorPointer(0, 0, 0, 1, 1, 16, [][]byte{{1, 2}}, [][]bool{{false}})))
		},
		"truncated masks": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, valid[:len(valid)-1])
		},
		"two bytes left over": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerColor, append(append([]byte(nil), valid...), 0, 0))
		},
		"short header": func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(rdpFastPathPointerColor, valid[:13]) },
		"new at 16 bpp": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerNew, newPointer(16, valid))
		},
		"new at 1 bpp, 24-bit lengths": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerNew, newPointer(1, valid))
		},
		"new without bpp":  func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(rdpFastPathPointerNew, []byte{24}) },
		"hidden with data": func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(rdpFastPathPointerHidden, []byte{0}) },
		"default with data": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerDefault, []byte{0})
		},
		"position short": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerPosition, []byte{0, 0, 0})
		},
		"position long": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerPosition, make([]byte, 5))
		},
		"cached index 25": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerCached, []byte{25, 0})
		},
		"cached long": func() (RDPPointerUpdate, error) {
			return parseRDPFastPathPointer(rdpFastPathPointerCached, []byte{1, 0, 0})
		},
		"fast-path code 7": func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(0x7, nil) },
		"system other": func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessageSystem, []byte{1, 0, 0, 0}))
		},
		"system long": func() (RDPPointerUpdate, error) {
			return parseRDPPointerPDU(pointerPDU(rdpPointerMessageSystem, make([]byte, 5)))
		},
		"slow-path type 2": func() (RDPPointerUpdate, error) { return parseRDPPointerPDU(pointerPDU(0x0002, nil)) },
		"slow-path short":  func() (RDPPointerUpdate, error) { return parseRDPPointerPDU([]byte{1, 0, 0}) },
	}
	for name, parse := range cases {
		if _, err := parse(); !errors.Is(err, ErrRDPPointer) || !errors.Is(err, ErrMCSConnection) {
			t.Errorf("%s: %v, want ErrRDPPointer", name, err)
		}
	}
	// The bound itself: 32 pixels is accepted.
	wide := make([][]byte, 32)
	for i := range wide {
		wide[i] = pixel
	}
	// A hot spot off the shape, within the bound: FreeRDP's shadow server sends a 1x2 shape whose
	// hot spot is (0,2), and an empty shape may have one too.
	for _, hot := range [][2]uint16{{0, 2}, {31, 31}} {
		offShape := set16(set16(colorPointer(0, 0, 0, 1, 2, 24, [][]byte{pixel, pixel}, [][]bool{{true}, {true}}), 2, hot[0]), 4, hot[1])
		if update, err := parseRDPFastPathPointer(rdpFastPathPointerColor, append(offShape, 0)); err != nil || update.Shape.HotY != int(hot[1]) {
			t.Fatalf("hot spot %v off a 1x2 shape: %+v, %v", hot, update, err)
		}
	}
	if _, err := parseRDPFastPathPointer(rdpFastPathPointerColor, set16(colorPointer(0, 0, 0, 0, 0, 24, nil, nil), 2, 5)); err != nil {
		t.Fatalf("an empty shape with a hot spot: %v", err)
	}
	if _, err := parseRDPFastPathPointer(rdpFastPathPointerColor, colorPointer(0, 31, 0, 32, 1, 24, wide, [][]bool{make([]bool, 32)})); err != nil {
		t.Fatalf("a 32-pixel shape is the bound, not beyond it: %v", err)
	}
	if update, err := parseRDPFastPathPointer(rdpFastPathPointerColor, colorPointer(0, 0, 0, 0, 0, 24, nil, nil)); err != nil ||
		update.Shape.Width != 0 {
		t.Fatalf("an empty shape is legal: %+v, %v", update, err)
	}
}

func TestPointerCacheKeepsWhatTheTargetSentAndNothingElse(t *testing.T) {
	p := NewRDPPointer()
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: 4}); !errors.Is(err, ErrRDPPointer) {
		t.Fatalf("an entry the target never filled: %v", err)
	}
	shape := &RDPPointerImage{Width: 1, Height: 1, RGBA: []byte{1, 2, 3, 0xff}, XOR: []bool{false}}
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerShape, CacheIndex: 4, Shape: shape}); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerDefault}); err != nil || p.shape != rdpDefaultPointer {
		t.Fatalf("default: %v", err)
	}
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: 4}); err != nil || p.shape != shape {
		t.Fatalf("cached: %v", err)
	}
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: rdpPointerCacheSize}); !errors.Is(err, ErrRDPPointer) {
		t.Fatalf("beyond the cache: %v", err)
	}
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerShape, CacheIndex: 1}); !errors.Is(err, ErrRDPPointer) {
		t.Fatalf("a shape without image: %v", err)
	}
	if err := p.Apply(RDPPointerUpdate{}); !errors.Is(err, ErrRDPPointer) {
		t.Fatalf("no kind: %v", err)
	}
	p.MoveTo(5, 6)
	p.Reset()
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: 4}); !errors.Is(err, ErrRDPPointer) {
		t.Fatalf("a reactivation forgets the cache: %v", err)
	}
	if !p.placed || p.x != 5 || p.y != 6 || p.shape != rdpDefaultPointer {
		t.Fatalf("a reactivation keeps the position and goes back to the arrow: %+v", p)
	}
}

func desktop(w, h int, gray byte) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = gray, gray, gray, 0xff
	}
	return img
}

func pixelAt(img *image.RGBA, x, y int) [4]byte {
	i := img.PixOffset(x, y)
	return [4]byte(img.Pix[i : i+4])
}

// The shape lands with its hot spot on the position, is clipped by the desktop, inverts where its
// masks say so, blends its alpha, and is not drawn while hidden or before any position is known.
func TestPointerIsDrawnAtItsHotSpot(t *testing.T) {
	shape := &RDPPointerImage{Width: 2, Height: 2, HotX: 1, HotY: 1,
		RGBA: []byte{0xff, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0xff, 0x80, 0, 0, 0, 0},
		XOR:  []bool{false, true, false, false}}
	p := NewRDPPointer()
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerShape, Shape: shape}); err != nil {
		t.Fatal(err)
	}
	img := desktop(4, 4, 0x40)
	p.DrawOn(img)
	if img.Pix[0] != 0x40 {
		t.Fatal("drawn before any position is known")
	}
	p.MoveTo(2, 2)
	p.DrawOn(img)
	if got := pixelAt(img, 1, 1); got != [4]byte{0xff, 0, 0, 0xff} {
		t.Fatalf("(1,1) %v, want the opaque red the hot spot offsets there", got)
	}
	if got := pixelAt(img, 2, 1); got != [4]byte{0xbf, 0xbf, 0xbf, 0xff} {
		t.Fatalf("(2,1) %v, want the desktop inverted", got)
	}
	if got := pixelAt(img, 1, 2); got != [4]byte{0x20, 0x20, 0xa0, 0xff} {
		t.Fatalf("(1,2) %v, want half blue over gray", got)
	}
	if got := pixelAt(img, 2, 2); got != [4]byte{0x40, 0x40, 0x40, 0xff} {
		t.Fatalf("(2,2) %v, want the desktop through a clear pixel", got)
	}

	// Clipped at the corner: only the bottom-right pixel of the shape falls on the desktop.
	img = desktop(4, 4, 0x40)
	p.MoveTo(0, 0)
	p.DrawOn(img)
	if got := pixelAt(img, 0, 0); got != [4]byte{0x40, 0x40, 0x40, 0xff} {
		t.Fatalf("clipped draw changed (0,0): %v", got)
	}
	p.MoveTo(4, 4) // past the desktop: only (3,3) can be touched, by the shape's top-left
	p.DrawOn(img)
	if got := pixelAt(img, 3, 3); got != [4]byte{0xff, 0, 0, 0xff} {
		t.Fatalf("(3,3) %v", got)
	}
	p.MoveTo(-100, 70000)
	p.DrawOn(img) // nothing to draw, nothing to panic about

	img = desktop(4, 4, 0x40)
	p.MoveTo(2, 2)
	if err := p.Apply(RDPPointerUpdate{Kind: RDPPointerHidden}); err != nil {
		t.Fatal(err)
	}
	p.DrawOn(img)
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			if pixelAt(img, x, y) != [4]byte{0x40, 0x40, 0x40, 0xff} {
				t.Fatalf("a hidden pointer is drawn at (%d,%d)", x, y)
			}
		}
	}
}

func TestDefaultArrowHasItsTipOnThePosition(t *testing.T) {
	p := NewRDPPointer()
	img := desktop(40, 40, 0x80)
	p.DrawOn(img)
	if pixelAt(img, 0, 0) != [4]byte{0x80, 0x80, 0x80, 0xff} {
		t.Fatal("the arrow is drawn before any position is known")
	}
	p.MoveTo(10, 10)
	p.DrawOn(img)
	if got := pixelAt(img, 10, 10); got != [4]byte{0, 0, 0, 0xff} {
		t.Fatalf("the tip is %v, want black", got)
	}
	if pixelAt(img, 9, 10) != [4]byte{0x80, 0x80, 0x80, 0xff} || pixelAt(img, 10, 9) != [4]byte{0x80, 0x80, 0x80, 0xff} {
		t.Fatal("the arrow reaches above or left of its tip")
	}
	if got := pixelAt(img, 11, 12); got != [4]byte{0xff, 0xff, 0xff, 0xff} {
		t.Fatalf("inside the arrow %v, want white", got)
	}
}

func FuzzParseRDPPointer(f *testing.F) {
	pixel := []byte{1, 2, 3, 4}
	f.Add(byte(rdpFastPathPointerColor), colorPointer(1, 0, 0, 1, 1, 24, [][]byte{pixel[:3]}, [][]bool{{true}}))
	f.Add(byte(rdpFastPathPointerNew), newPointer(32, colorPointer(2, 1, 0, 2, 1, 32, [][]byte{pixel, pixel}, [][]bool{{false, true}})))
	f.Add(byte(rdpFastPathPointerPosition), []byte{1, 0, 2, 0})
	f.Add(byte(rdpFastPathPointerCached), []byte{1, 0})
	f.Add(byte(rdpFastPathPointerNew), append(newPointer(1, []byte{0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 2, 0, 2, 0}), 0x80, 0, 0, 0))
	f.Add(byte(0), pointerPDU(rdpPointerMessageNew, newPointer(24, colorPointer(0, 0, 0, 1, 1, 24, [][]byte{pixel[:3]}, [][]bool{{false}}))))
	f.Fuzz(func(t *testing.T, code byte, payload []byte) {
		updates := []func() (RDPPointerUpdate, error){
			func() (RDPPointerUpdate, error) { return parseRDPFastPathPointer(code, payload) },
			func() (RDPPointerUpdate, error) { return parseRDPPointerPDU(payload) },
		}
		for _, parse := range updates {
			update, err := parse()
			if err != nil {
				if !errors.Is(err, ErrRDPPointer) {
					t.Fatalf("an error that is not ErrRDPPointer: %v", err)
				}
				continue
			}
			if shape := update.Shape; shape != nil {
				if shape.Width > rdpPointerMaxSide || shape.Height > rdpPointerMaxSide ||
					len(shape.RGBA) != shape.Width*shape.Height*4 || len(shape.XOR) != shape.Width*shape.Height ||
					update.CacheIndex >= rdpPointerCacheSize {
					t.Fatalf("an unbounded shape: %+v", update)
				}
			}
			p := NewRDPPointer()
			if update.Kind == RDPPointerCached {
				continue // nothing is in the cache: refused, tested above
			}
			if err := p.Apply(update); err != nil {
				t.Fatalf("a decoded update refused by the cache: %v", err)
			}
			p.MoveTo(int(code)-4, int(code)-4)
			p.DrawOn(desktop(8, 8, 0))
		}
	})
}

// A refusal says the header of the shape, never its pixels.
func TestDescribeRDPPointerHeaderSaysTheFieldsNotThePixels(t *testing.T) {
	attribute := colorPointer(2, 1, 0, 2, 1, 32, [][]byte{{0xde, 0xad, 0xbe, 0xef}, {0xde, 0xad, 0xbe, 0xef}}, [][]bool{{false, false}})
	got := describeRDPPointerHeader(rdpFastPathPointerNew, newPointer(32, attribute))
	want := "pointer code 11, 26 bytes, xorBpp 32, cache 2, hot spot 1,0, 2x1, AND 2 bytes, XOR 8 bytes, 10 byte(s) of masks"
	if got != want {
		t.Fatalf("%q\nwant %q", got, want)
	}
	if got := describeRDPPointerHeader(rdpFastPathPointerPosition, []byte{1, 2, 3}); got != "pointer code 8, 3 bytes" {
		t.Fatalf("%q", got)
	}
	if got := describeRDPPointerHeader(rdpFastPathPointerNew, []byte{1}); got != "pointer code 11, 1 bytes" {
		t.Fatalf("%q", got)
	}
}

// A monochrome shape, as Windows Server 2019 sends them: one bit of XOR, one of AND, both masks
// top-down (FreeRDP reads them so against Windows), white and black opaque, inverting, and clear.
func TestNewPointerAt1BitIsReadTopDown(t *testing.T) {
	attribute := make([]byte, 14)
	binary.LittleEndian.PutUint16(attribute[6:8], 2)   // width
	binary.LittleEndian.PutUint16(attribute[8:10], 2)  // height
	binary.LittleEndian.PutUint16(attribute[10:12], 4) // AND: 2 lines of 2 bytes
	binary.LittleEndian.PutUint16(attribute[12:14], 4) // XOR: 2 lines of 2 bytes
	attribute = append(attribute, 0x80, 0, 0x80, 0)    // XOR, top line first: set, clear; set, clear
	attribute = append(attribute, 0, 0, 0xc0, 0)       // AND: clear, clear; set, set
	update, err := parseRDPFastPathPointer(rdpFastPathPointerNew, newPointer(1, attribute))
	if err != nil {
		t.Fatal(err)
	}
	shape := update.Shape
	if rgbaAt(shape, 0, 0) != [4]byte{0xff, 0xff, 0xff, 0xff} || rgbaAt(shape, 1, 0) != [4]byte{0, 0, 0, 0xff} {
		t.Fatalf("top line %v %v, want opaque white then black", rgbaAt(shape, 0, 0), rgbaAt(shape, 1, 0))
	}
	if !shape.XOR[2] || shape.XOR[3] || rgbaAt(shape, 1, 1) != [4]byte{} {
		t.Fatalf("bottom line: inverting %v, then clear %v", shape.XOR[2], rgbaAt(shape, 1, 1))
	}
	if shape.XOR[0] || shape.XOR[1] {
		t.Fatal("the top line inverts: the masks were read bottom-up")
	}
}

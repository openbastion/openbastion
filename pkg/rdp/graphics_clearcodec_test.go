package rdp

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// ClearCodec of ADR-0101, increment 3 (MS-RDPEGFX 2.2.4.1): each layer drawn as the spec lays it
// out, the caches and the glyphs, the sequence, and what a target may not send.

// clearStream is a CLEARCODEC_BITMAP_STREAM: flags, seqNumber, then the glyph index or the payload.
func clearStream(flags, seq byte, rest ...[]byte) []byte {
	out := []byte{flags, seq}
	for _, r := range rest {
		out = append(out, r...)
	}
	return out
}

func composite(residual, bands, subcodecs []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(residual)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(bands)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(subcodecs)))
	return append(append(append(out, residual...), bands...), subcodecs...)
}

// run is a CLEARCODEC_RGB_RUN_SEGMENT, its length in the shortest form.
func run(b, g, r byte, n int) []byte {
	out := []byte{b, g, r}
	switch {
	case n < 0xff:
		return append(out, byte(n))
	case n < 0xffff:
		return binary.LittleEndian.AppendUint16(append(out, 0xff), uint16(n))
	}
	return binary.LittleEndian.AppendUint32(append(out, 0xff, 0xff, 0xff), uint32(n))
}

func band(xStart, xEnd, yStart, yEnd int, bkg [3]byte, vBars ...[]byte) []byte {
	out := (&gfx{}).u16(xStart, xEnd, yStart, yEnd).raw(bkg[:]...).b
	for _, v := range vBars {
		out = append(out, v...)
	}
	return out
}

func shortMiss(yOn, yOff int, bgr ...byte) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, uint16(yOn|yOff<<8)), bgr...)
}
func shortHit(index, yOn int) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, uint16(0x4000|index)), byte(yOn))
}
func vBarHit(index int) []byte { return binary.LittleEndian.AppendUint16(nil, uint16(0x8000|index)) }

func subcodec(x, y, w, h int, id byte, data []byte) []byte {
	return append((&gfx{}).u16(x, y, w, h).u32(uint32(len(data))).raw(id).b, data...)
}

// clearSurface is a compositor with surface 1 of w x h, the bitmaps drawn at its origin.
func clearSurface(t *testing.T, w, h int) *RDPGraphicsCompositor {
	t.Helper()
	c := NewRDPGraphicsCompositor()
	mustApply(t, c, createSurface(1, w, h, rdpGraphicsPixelXRGB))
	return c
}

func drawClear(t *testing.T, c *RDPGraphicsCompositor, w, h int, stream []byte) {
	t.Helper()
	mustApply(t, c, wireToSurface1(1, 0x0008, [4]int{0, 0, w, h}, stream))
}

// rgb is the surface's pixel at (x, y), red, green, blue.
func rgb(c *RDPGraphicsCompositor, x, y int) [3]byte {
	s := c.surfaces[1]
	i := (y*s.width + x) * 4
	return [3]byte(s.pix[i : i+3])
}

func TestClearCodec_TheResidualLayer(t *testing.T) {
	c := clearSurface(t, 4, 2)
	// Five red, then three blue: left to right, then top to bottom; colours as blue, green, red.
	drawClear(t, c, 4, 2, clearStream(0, 0, composite(append(run(0, 0, 0xff, 5), run(0xff, 0, 0, 3)...), nil, nil)))
	for i, want := range [][3]byte{{0xff, 0, 0}, {0xff, 0, 0}, {0xff, 0, 0}, {0xff, 0, 0}, {0xff, 0, 0}, {0, 0, 0xff}, {0, 0, 0xff}, {0, 0, 0xff}} {
		if got := rgb(c, i%4, i/4); got != want {
			t.Fatalf("pixel %d = % x, want % x", i, got, want)
		}
	}
	// The long forms of a run length: 255 then a uint16, 65,535 then a uint32.
	c = clearSurface(t, 300, 300)
	drawClear(t, c, 300, 300, clearStream(0, 0, composite(append(run(1, 2, 3, 300), run(4, 5, 6, 89700)...), nil, nil)))
	if rgb(c, 299, 0) != [3]byte{3, 2, 1} || rgb(c, 0, 1) != [3]byte{6, 5, 4} || rgb(c, 299, 299) != [3]byte{6, 5, 4} {
		t.Fatal("the long run lengths")
	}
}

func TestClearCodec_TheBandsAndTheirCaches(t *testing.T) {
	c := clearSurface(t, 4, 4)
	bkg := [3]byte{0x10, 0x20, 0x30} // blue, green, red
	// A band of rows 1 to 3, columns 0 to 2:
	//  - column 0: a short V-bar missed, one pixel (green) at yOn 1: background, green, background;
	//  - column 1: that short V-bar again, at yOn 0: green, background, background;
	//  - column 2: the V-bar of column 0, from the V-bar cache (index 0).
	stream := clearStream(0, 0, composite(nil, band(0, 2, 1, 3, bkg,
		shortMiss(1, 2, 0, 0xff, 0), shortHit(0, 0), vBarHit(0)), nil))
	drawClear(t, c, 4, 4, stream)
	bg, green, black := [3]byte{0x30, 0x20, 0x10}, [3]byte{0, 0xff, 0}, [3]byte{0, 0, 0}
	for _, check := range []struct {
		x, y int
		want [3]byte
	}{
		{0, 0, black}, {0, 1, bg}, {0, 2, green}, {0, 3, bg},
		{1, 1, green}, {1, 2, bg}, {1, 3, bg},
		{2, 1, bg}, {2, 2, green}, {2, 3, bg},
		{3, 1, black},
	} {
		if got := rgb(c, check.x, check.y); got != check.want {
			t.Errorf("(%d, %d) = % x, want % x", check.x, check.y, got, check.want)
		}
	}
	// The caches outlive a bitmap; CACHE_RESET resets the cursors, not what they hold: V-bar 1
	// (column 1's) is still there.
	drawClear(t, c, 4, 4, clearStream(clearFlagCacheReset, 1, composite(nil, band(3, 3, 1, 3, bkg, vBarHit(1)), nil)))
	if rgb(c, 3, 1) != green {
		t.Fatalf("V-bar 1 after the reset: % x", rgb(c, 3, 1))
	}
	if c.clear.vCursor != 0 || c.clear.shortCursor != 0 {
		t.Fatalf("cursors %d, %d after the reset", c.clear.vCursor, c.clear.shortCursor)
	}
	// The V-bar cursor wraps after 32,767.
	c.clear.vCursor = clearVBarSlots - 1
	drawClear(t, c, 4, 4, clearStream(0, 2, composite(nil, band(0, 0, 0, 0, bkg, shortHit(0, 0)), nil)))
	if c.clear.vCursor != 0 || len(c.clear.vBars[clearVBarSlots-1]) != 3 {
		t.Fatalf("the V-bar cursor after 32,767: %d", c.clear.vCursor)
	}
}

func TestClearCodec_TheSubcodecs(t *testing.T) {
	c := clearSurface(t, 4, 4)
	// Raw pixels at (1, 1), 2 x 1: blue then red.
	raw := subcodec(1, 1, 2, 1, clearSubcodecRaw, []byte{0xff, 0, 0, 0, 0, 0xff})
	// RLEX at (0, 2), 4 x 2: a palette of three (black, red, blue); 2 bits of stop index.
	//  - stop 1, depth 1, run 2: two of index 0, then the suite 0, 1: black, black, black, red;
	//  - stop 2, depth 0, run 3: three of index 2, then index 2: blue, blue, blue, blue.
	rlex := []byte{3, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1 | 1<<2, 2, 2 | 0<<2, 3}
	drawClear(t, c, 4, 4, clearStream(0, 0, composite(nil, nil, append(raw, subcodec(0, 2, 4, 2, clearSubcodecRLEX, rlex)...))))
	red, blue, black := [3]byte{0xff, 0, 0}, [3]byte{0, 0, 0xff}, [3]byte{}
	for _, check := range []struct {
		x, y int
		want [3]byte
	}{
		{1, 1, blue}, {2, 1, red}, {0, 1, black},
		{0, 2, black}, {1, 2, black}, {2, 2, black}, {3, 2, red},
		{0, 3, blue}, {3, 3, blue},
	} {
		if got := rgb(c, check.x, check.y); got != check.want {
			t.Errorf("(%d, %d) = % x, want % x", check.x, check.y, got, check.want)
		}
	}
	// A palette of two colours: one bit of stop index, so 0b11 is stop 1, depth 1: a run of two of
	// index 0, then the suite 0, 1.
	c = clearSurface(t, 4, 1)
	drawClear(t, c, 4, 1, clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 4, 1, clearSubcodecRLEX, []byte{2, 0, 0, 0xff, 0xff, 0, 0, 3, 2}))))
	if rgb(c, 2, 0) != [3]byte{0xff, 0, 0} || rgb(c, 3, 0) != [3]byte{0, 0, 0xff} {
		t.Fatalf("a palette of two: % x % x", rgb(c, 2, 0), rgb(c, 3, 0))
	}
	// A palette of one colour: one bit of stop index.
	c = clearSurface(t, 2, 1)
	drawClear(t, c, 2, 1, clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 2, 1, clearSubcodecRLEX, []byte{1, 0, 0xff, 0, 0, 1}))))
	if rgb(c, 1, 0) != [3]byte{0, 0xff, 0} {
		t.Fatalf("a palette of one: % x", rgb(c, 1, 0))
	}
}

func TestClearCodec_TheLayersInOrderAndTheGlyphs(t *testing.T) {
	c := clearSurface(t, 8, 8)
	// Residual red everywhere, a band over column 0, a raw pixel over (0, 0): the last one wins.
	bkg := [3]byte{0xff, 0, 0} // blue
	stream := clearStream(clearFlagGlyphIndex, 0, binary.LittleEndian.AppendUint16(nil, 7),
		composite(run(0, 0, 0xff, 4), band(0, 0, 0, 1, bkg, shortMiss(0, 0)), subcodec(0, 0, 1, 1, clearSubcodecRaw, []byte{0, 0xff, 0})))
	mustApply(t, c, wireToSurface1(1, 0x0008, [4]int{2, 2, 4, 4}, stream))
	green, blue, red := [3]byte{0, 0xff, 0}, [3]byte{0, 0, 0xff}, [3]byte{0xff, 0, 0}
	if rgb(c, 2, 2) != green || rgb(c, 2, 3) != blue || rgb(c, 3, 2) != red || rgb(c, 3, 3) != red {
		t.Fatalf("the layers: % x % x % x % x", rgb(c, 2, 2), rgb(c, 2, 3), rgb(c, 3, 2), rgb(c, 3, 3))
	}
	// Glyph 7 kept: drawn again elsewhere by its index alone.
	hit := clearStream(clearFlagGlyphIndex|clearFlagGlyphHit, 1, binary.LittleEndian.AppendUint16(nil, 7))
	mustApply(t, c, wireToSurface1(1, 0x0008, [4]int{5, 5, 7, 7}, hit))
	if rgb(c, 5, 5) != green || rgb(c, 5, 6) != blue || rgb(c, 6, 6) != red {
		t.Fatal("the glyph drawn again")
	}
	// The sequence wraps after 0xFF.
	c.clear.seq = 0xff
	drawClear(t, c, 1, 1, clearStream(0, 0, composite(run(0, 0, 0, 1), nil, nil)))
}

func TestClearCodec_RefusesWhatATargetMayNotSend(t *testing.T) {
	bkg := [3]byte{}
	for name, stream := range map[string][]byte{
		"a first sequence of 1":       clearStream(0, 1, composite(run(0, 0, 0, 1), nil, nil)),
		"unknown flags":               clearStream(0x08, 0, composite(run(0, 0, 0, 1), nil, nil)),
		"a glyph hit with no index":   clearStream(clearFlagGlyphHit, 0),
		"a glyph index of 4000":       clearStream(clearFlagGlyphIndex, 0, binary.LittleEndian.AppendUint16(nil, 4000)),
		"a glyph hit, empty":          clearStream(clearFlagGlyphIndex|clearFlagGlyphHit, 0, binary.LittleEndian.AppendUint16(nil, 3)),
		"layers past the payload":     clearStream(0, 0, composite(run(0, 0, 0, 1), nil, nil)[:15]),
		"layers short of the payload": clearStream(0, 0, append(composite(run(0, 0, 0, 1), nil, nil), 0)),
		"a run of 0":                  clearStream(0, 0, composite(run(0, 0, 0, 0), nil, nil)),
		"a run past the bitmap":       clearStream(0, 0, composite(run(0, 0, 0, 17), nil, nil)),
		"a run cut short":             clearStream(0, 0, composite([]byte{0, 0, 0, 0xff, 1}, nil, nil)),
		"a band past the bitmap":      clearStream(0, 0, composite(nil, band(0, 4, 0, 0, bkg, shortMiss(0, 0), shortMiss(0, 0), shortMiss(0, 0), shortMiss(0, 0), shortMiss(0, 0)), nil)),
		"a band upside down":          clearStream(0, 0, composite(nil, band(0, 0, 2, 1, bkg, shortMiss(0, 0)), nil)),
		"a band short of V-bars":      clearStream(0, 0, composite(nil, band(0, 1, 0, 0, bkg, shortMiss(0, 0)), nil)),
		"an empty V-bar hit":          clearStream(0, 0, composite(nil, band(0, 0, 0, 0, bkg, vBarHit(5)), nil)),
		"an empty short V-bar hit":    clearStream(0, 0, composite(nil, band(0, 0, 0, 0, bkg, shortHit(5, 0)), nil)),
		"a short V-bar past its band": clearStream(0, 0, composite(nil, band(0, 0, 0, 1, bkg, shortMiss(1, 3, 1, 1, 1, 2, 2, 2)), nil)),
		"a short V-bar yOff < yOn":    clearStream(0, 0, composite(nil, band(0, 0, 0, 1, bkg, shortMiss(2, 1)), nil)),
		"short V-bar pixels cut":      clearStream(0, 0, composite(nil, band(0, 0, 0, 1, bkg, shortMiss(0, 2, 1, 1, 1)), nil)),
		"a subcodec past the bitmap":  clearStream(0, 0, composite(nil, nil, subcodec(3, 0, 2, 1, clearSubcodecRaw, make([]byte, 6)))),
		"raw pixels short":            clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 2, 1, clearSubcodecRaw, make([]byte, 5)))),
		"a subcodec 0x03":             clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 1, 1, 0x03, make([]byte, 3)))),
		"a subcodec of 0 x 1":         clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 0, 1, clearSubcodecRaw, nil))),
		"an RLEX palette of 0":        clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 1, 1, clearSubcodecRLEX, []byte{0, 0}))),
		"an RLEX stop past the palette": clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 2, 2, clearSubcodecRLEX,
			[]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0}))), // 2 bits for three colours: stop 3
		"an RLEX start below 0":    clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 2, 1, clearSubcodecRLEX, []byte{2, 0, 0, 0, 0, 0, 0, 0 | 1<<1, 0}))),
		"RLEX short of its pixels": clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 4, 1, clearSubcodecRLEX, []byte{1, 0, 0, 0, 0, 1}))),
		"RLEX past its pixels":     clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 1, 1, clearSubcodecRLEX, []byte{1, 0, 0, 0, 0, 1}))),
	} {
		c := clearSurface(t, 4, 4)
		_, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 4, 4}, stream))
		if !errors.Is(err, ErrRDPGraphics) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A band of 53 rows; a V-bar hit of another band's height; layers that leave a byte out.
	c := clearSurface(t, 4, 60)
	tall := make([][]byte, 1)
	tall[0] = shortMiss(0, 0)
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 4, 60}, clearStream(0, 0, composite(nil, band(0, 0, 0, 52, bkg, tall...), nil)))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a band of 53 rows: %v", err)
	}
	c = clearSurface(t, 4, 4)
	drawClear(t, c, 4, 4, clearStream(0, 0, composite(nil, band(0, 0, 0, 2, bkg, shortMiss(0, 0)), nil)))
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 4, 4}, clearStream(0, 1, composite(nil, band(1, 1, 0, 0, bkg, vBarHit(0)), nil)))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a V-bar of 3 rows in a band of 1: %v", err)
	}
	c = clearSurface(t, 4, 4)
	payload := composite(run(0, 0, 0, 1), nil, nil)
	binary.LittleEndian.PutUint32(payload[0:4], 4)
	binary.LittleEndian.PutUint32(payload[8:12], 0) // the counts are 4 + 0 + 0 for 4 bytes...
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 4, 4}, clearStream(0, 0, append(payload, 0xff)))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a byte past the three layers: %v", err) // ...and one more is in no layer
	}
	// A subcodec of more bytes than three a pixel, refused by its bound and not by what follows.
	c = clearSurface(t, 4, 4)
	_, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 4, 4}, clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 1, 1, clearSubcodecRLEX, []byte{1, 0, 0, 0, 0, 0})))))
	if err == nil || !strings.Contains(err.Error(), "a subcodec of 1 x 1") {
		t.Errorf("a subcodec of 5 bytes for 1 pixel: %v", err)
	}
	// A palette of 128 colours, past the 127 allowed, though its data is all there.
	c = clearSurface(t, 16, 16)
	palette128 := append(append([]byte{0x80}, make([]byte, 3*128)...), 15, 0xff, 255, 0)
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 16, 16}, clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 16, 16, clearSubcodecRLEX, palette128))))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a palette of 128: %v", err)
	}
	// A glyph kept as 2 x 4 is not one of 3 x 4, nor of 4 x 2.
	c = clearSurface(t, 8, 8)
	mustApply(t, c, wireToSurface1(1, 0x0008, [4]int{0, 0, 2, 4}, clearStream(clearFlagGlyphIndex, 0, []byte{9, 0}, composite(run(0, 0, 0, 8), nil, nil))))
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 4, 2}, clearStream(clearFlagGlyphIndex|clearFlagGlyphHit, 1, []byte{9, 0}))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a 2 x 4 glyph hit as 4 x 2: %v", err)
	}
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 3, 4}, clearStream(clearFlagGlyphIndex|clearFlagGlyphHit, 2, []byte{9, 0}))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a 2 x 4 glyph hit as 3 x 4: %v", err)
	}
	// A glyph larger than 1024 pixels; a sequence that skips one; NSCodec named.
	c = clearSurface(t, 64, 64)
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 33, 32}, clearStream(clearFlagGlyphIndex, 0, []byte{1, 0}))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a glyph of 33 x 32: %v", err)
	}
	c = clearSurface(t, 4, 4)
	drawClear(t, c, 1, 1, clearStream(0, 0, composite(run(0, 0, 0, 1), nil, nil)))
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 1, 1}, clearStream(0, 2, composite(run(0, 0, 0, 1), nil, nil)))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a sequence that skips one: %v", err)
	}
	c = clearSurface(t, 4, 4)
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 1, 1}, clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 1, 1, clearSubcodecNSC, []byte{0}))))); !errors.Is(err, ErrRDPGraphicsCodec) {
		t.Errorf("NSCodec: %v", err)
	}
	// The WireToSurface1 around it: a rectangle past its surface, a length that is not the data's.
	c = clearSurface(t, 4, 4)
	if _, _, err := c.Apply(wireToSurface1(1, 0x0008, [4]int{0, 0, 5, 1}, clearStream(0, 0))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a rectangle past the surface: %v", err)
	}
	long := wireToSurface1(1, 0x0008, [4]int{0, 0, 1, 1}, clearStream(0, 0))
	long.Body = append(long.Body, 0)
	if _, _, err := c.Apply(long); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a length not the data's: %v", err)
	}
}

func TestClearCodec_Uncompressed(t *testing.T) {
	c := clearSurface(t, 2, 1)
	mustApply(t, c, wireToSurface1(1, 0x0000, [4]int{0, 0, 2, 1}, []byte{0xff, 0, 0, 0, 0, 0, 0xff, 0}))
	if rgb(c, 0, 0) != [3]byte{0, 0, 0xff} || rgb(c, 1, 0) != [3]byte{0xff, 0, 0} {
		t.Fatal("uncompressed: blue, green, red, alpha")
	}
	if _, _, err := c.Apply(wireToSurface1(1, 0x0000, [4]int{0, 0, 2, 1}, make([]byte, 7))); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("7 bytes for 2 pixels: %v", err)
	}
}

func FuzzClearCodec(f *testing.F) {
	bkg := [3]byte{1, 2, 3}
	f.Add(clearStream(0, 0, composite(run(0, 0, 0xff, 5), band(0, 2, 1, 3, bkg, shortMiss(1, 2, 0, 0xff, 0), shortHit(0, 0), vBarHit(0)),
		subcodec(0, 2, 4, 2, clearSubcodecRLEX, []byte{3, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1 | 1<<2, 2, 2, 3}))))
	f.Add(clearStream(clearFlagGlyphIndex, 0, []byte{7, 0}, composite(run(0, 0, 0, 4), nil, nil)))
	f.Fuzz(func(t *testing.T, stream []byte) {
		c := NewRDPGraphicsCompositor()
		if _, _, err := c.Apply(createSurface(1, 16, 16, rdpGraphicsPixelXRGB)); err != nil {
			t.Fatal(err)
		}
		for _, rect := range [][4]int{{0, 0, 16, 16}, {2, 3, 7, 6}} {
			if _, _, err := c.Apply(wireToSurface1(1, 0x0008, rect, stream)); err != nil && !errors.Is(err, ErrRDPGraphics) {
				t.Fatalf("an error outside ErrRDPGraphics: %v", err)
			}
			if c.clear != nil {
				c.clear.seq-- // the same stream twice: the second one keeps the sequence
			}
		}
	})
}

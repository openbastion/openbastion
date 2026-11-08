package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// Vectors for each Interleaved RLE order, built from MS-RDPBCGR 3.1.9 (ADR-0083). Pixels are
// 16 bpp; rows are in stream order, the first row of the stream first (the bottom of the bitmap).

func px(values ...uint16) []byte {
	out := make([]byte, 0, len(values)*2)
	for _, v := range values {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestInterleavedRLEOrders(t *testing.T) {
	const a, b, c, f = 0x1234, 0x0f0f, 0xabcd, 0x00ff
	cases := []struct {
		name          string
		width, height int
		stream        []byte
		want          []uint16
	}{
		{"color image", 3, 1, cat([]byte{0x83}, px(a, b, c)), []uint16{a, b, c}},
		{"color run", 4, 1, cat([]byte{0x64}, px(a)), []uint16{a, a, a, a}},
		{"color run, extended length (0 then +32)", 33, 1, cat([]byte{0x60, 1}, px(a)), repeat(a, 33)},
		{"mega mega color run", 2, 2, cat([]byte{0xf3, 4, 0}, px(c)), []uint16{c, c, c, c}},
		{"mega mega color image", 2, 1, cat([]byte{0xf4, 2, 0}, px(a, b)), []uint16{a, b}},
		// The first line has no line above: a background run is black, a foreground run is fg.
		{"background run, first line", 3, 1, []byte{0x03}, []uint16{0, 0, 0}},
		{"foreground run, first line, fg starts white", 2, 1, []byte{0x22}, []uint16{0xffff, 0xffff}},
		// Past the first line, background copies the pixel above, foreground XORs it with fg.
		{"background run, second line", 2, 2, cat([]byte{0x82}, px(a, b), []byte{0x02}), []uint16{a, b, a, b}},
		{"set fg run then fg run on the second line", 2, 2,
			cat([]byte{0x82}, px(a, b), []byte{0xc2}, px(f)), []uint16{a, b, a ^ f, b ^ f}},
		// Two background runs in a row: the second starts with a foreground pixel.
		{"background run after background run, first line", 4, 1, []byte{0x02, 0x02}, []uint16{0, 0, 0xffff, 0}},
		{"background run after background run, second line", 2, 3,
			cat([]byte{0x82}, px(a, b), []byte{0x02, 0x02}), []uint16{a, b, a, b, a ^ 0xffff, b}},
		// A foreground run ends the "after a background run" state.
		{"background, color, background", 3, 1, cat([]byte{0x01, 0x61}, px(c), []byte{0x01}), []uint16{0, c, 0}},
		{"lite set fg run, extended length (0 then +16)", 17, 1, cat([]byte{0xc0, 1}, px(f)), repeat(f, 17)},
		{"mega mega set fg run", 3, 1, cat([]byte{0xf6, 3, 0}, px(f)), []uint16{f, f, f}},
		{"dithered run counts pairs", 4, 1, cat([]byte{0xe2}, px(a, b)), []uint16{a, b, a, b}},
		{"mega mega dithered run", 2, 1, cat([]byte{0xf8, 1, 0}, px(a, b)), []uint16{a, b}},
		// FG/BG image, regular, run length 1 meaning 8 pixels: bits low first; set = fg.
		{"fgbg image, first line", 8, 1, []byte{0x41, 0b00000101}, []uint16{0xffff, 0, 0xffff, 0, 0, 0, 0, 0}},
		{"fgbg image, extended length (0 then +1)", 3, 1, []byte{0x40, 2, 0b011}, []uint16{0xffff, 0xffff, 0}},
		{"set fg fgbg image on the second line", 2, 2,
			cat([]byte{0x82}, px(a, b), []byte{0xd0, 1}, px(f), []byte{0b10}), []uint16{a, b, a, b ^ f}},
		{"mega mega fgbg image", 9, 1, []byte{0xf2, 9, 0, 0xff, 0x00}, append(repeat(0xffff, 8), 0)},
		{"mega mega set fgbg image", 2, 1, cat([]byte{0xf7, 2, 0}, px(f), []byte{0b01}), []uint16{f, 0}},
		{"special fgbg 1 (mask 0x03)", 8, 1, []byte{0xf9}, []uint16{0xffff, 0xffff, 0, 0, 0, 0, 0, 0}},
		{"special fgbg 2 (mask 0x05)", 8, 1, []byte{0xfa}, []uint16{0xffff, 0, 0xffff, 0, 0, 0, 0, 0}},
		{"white and black", 2, 1, []byte{0xfd, 0xfe}, []uint16{0xffff, 0}},
	}
	for _, c := range cases {
		got, err := decodeInterleavedRLE16(c.stream, c.width, c.height, 16)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !equalUint16(got, c.want) {
			t.Errorf("%s: %04x, want %04x", c.name, got, c.want)
		}
	}
	// At 15 bpp, white is 0x7fff.
	if got, err := decodeInterleavedRLE16([]byte{0xfd, 0x21}, 2, 1, 15); err != nil || !equalUint16(got, []uint16{0x7fff, 0x7fff}) {
		t.Errorf("15 bpp white: %04x, %v", got, err)
	}
}

// What a hostile or broken stream cannot do: write past the bitmap, read past itself, stop short,
// or use a code the specification does not define.
func TestInterleavedRLERefusesWhatItCannotBound(t *testing.T) {
	cases := map[string]struct {
		width, height int
		stream        []byte
	}{
		"run longer than the bitmap":           {2, 1, cat([]byte{0x63}, px(1))},
		"mega mega run longer than the bitmap": {2, 1, []byte{0xf0, 0xff, 0xff}},
		"dithered pairs past the bitmap":       {3, 1, cat([]byte{0xe2}, px(1, 2))},
		"color image without its pixels":       {3, 1, cat([]byte{0x83}, px(1, 2))},
		"color run without its pixel":          {1, 1, []byte{0x61, 0x00}},
		"missing extended length byte":         {40, 1, []byte{0x60}},
		"missing mega mega length":             {2, 1, []byte{0xf3, 2}},
		"fgbg image without its mask":          {8, 1, []byte{0x41}},
		"set fg without its pixel":             {2, 1, []byte{0xc2, 0x01}},
		"special order past the bitmap":        {4, 1, []byte{0xf9}},
		"white past the bitmap":                {1, 1, []byte{0xfd, 0xfd}},
		"stream ends before the bitmap":        {4, 1, cat([]byte{0x62}, px(1))},
		"empty stream":                         {1, 1, nil},
		"undefined code 0xf5":                  {1, 1, []byte{0xf5}},
		"undefined code 0xfb":                  {1, 1, []byte{0xfb}},
		"undefined code 0xfc":                  {1, 1, []byte{0xfc}},
		"undefined code 0xff":                  {1, 1, []byte{0xff}},
		"undefined lite code 0xa0":             {1, 1, []byte{0xa1}},
	}
	for name, c := range cases {
		if got, err := decodeInterleavedRLE16(c.stream, c.width, c.height, 16); !errors.Is(err, ErrMCSConnection) || got != nil {
			t.Errorf("%s: %04x, %v", name, got, err)
		}
	}
	for _, bpp := range []uint16{0, 8, 24, 32} {
		if _, err := decodeInterleavedRLE16([]byte{0xfd}, 1, 1, bpp); err == nil {
			t.Errorf("%d bpp accepted", bpp)
		}
	}
	if _, err := decodeInterleavedRLE16([]byte{0xfd}, 0, 1, 16); err == nil {
		t.Error("zero width accepted")
	}
}

func TestRGB16Conversion(t *testing.T) {
	for _, c := range []struct {
		p       uint16
		bpp     uint16
		r, g, b byte
	}{
		{0xffff, 16, 255, 255, 255}, {0x0000, 16, 0, 0, 0}, {0xf800, 16, 255, 0, 0}, {0x07e0, 16, 0, 255, 0},
		{0x001f, 16, 0, 0, 255}, {0x8410, 16, 132, 130, 132},
		{0x7fff, 15, 255, 255, 255}, {0x7c00, 15, 255, 0, 0}, {0x03e0, 15, 0, 255, 0}, {0x001f, 15, 0, 0, 255},
	} {
		if r, g, b := rgbaFrom16(c.p, c.bpp); r != c.r || g != c.g || b != c.b {
			t.Errorf("%#04x at %d bpp: %d,%d,%d, want %d,%d,%d", c.p, c.bpp, r, g, b, c.r, c.g, c.b)
		}
	}
}

func TestRaw16BitmapIsBottomUpWithPaddedRows(t *testing.T) {
	// 3 x 2 at 16 bpp: rows of 6 bytes padded to 8; the first row sent is the bottom one.
	src := cat(px(0xf800, 0x07e0, 0x001f), []byte{0xee, 0xee}, px(0xffff, 0, 0xffff), []byte{0xee, 0xee})
	got, err := decodeRDPBitmapRaw16(src, 3, 2, 16)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255, // top: the second row sent
		255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	for _, n := range []int{len(src) - 1, len(src) + 1, 12} {
		if _, err := decodeRDPBitmapRaw16(append(src, 0)[:n], 3, 2, 16); err == nil {
			t.Errorf("%d bytes accepted for 3 x 2 (16 expected)", n)
		}
	}
}

func TestRLE16BitmapHeaderAndWidth(t *testing.T) {
	stream := cat([]byte{0x62}, px(0xffff))
	if _, err := decodeRDPBitmapRLE16(stream, 2, 1, 16, false); err != nil {
		t.Fatal(err)
	}
	header := cat(px(0, uint16(len(stream)), 4, 4), stream)
	if _, err := decodeRDPBitmapRLE16(header, 2, 1, 16, true); err != nil {
		t.Fatalf("TS_CD_HEADER: %v", err)
	}
	for name, bad := range map[string][]byte{
		"first row size":    cat(px(1, uint16(len(stream)), 4, 4), stream),
		"main body size":    cat(px(0, uint16(len(stream)+1), 4, 4), stream),
		"scan width":        cat(px(0, uint16(len(stream)), 8, 4), stream),
		"uncompressed size": cat(px(0, uint16(len(stream)), 4, 8), stream),
	} {
		if _, err := decodeRDPBitmapRLE16(bad, 2, 1, 16, true); err == nil {
			t.Errorf("TS_CD_HEADER with a wrong %s accepted", name)
		}
	}
	// cbScanWidth must be divisible by 4: an odd width is refused before decoding.
	if _, err := decodeRDPBitmapRLE16([]byte{0x61, 0, 0}, 1, 1, 16, false); err == nil {
		t.Error("odd width accepted")
	}
}

// TS_BITMAP_DATA at the session's depth: a rectangle at another depth is refused, a padded bitmap
// is cropped to its destination, a destination larger than the bitmap is refused.
func TestBitmapUpdateAtSessionDepth(t *testing.T) {
	rect := func(left, top, right, bottom, width, height, bpp, flags uint16, data []byte) []byte {
		out := binary.LittleEndian.AppendUint16(nil, 1)
		for _, v := range []uint16{left, top, right, bottom, width, height, bpp, flags, uint16(len(data))} {
			out = binary.LittleEndian.AppendUint16(out, v)
		}
		return append(out, data...)
	}
	// 4 x 1 at 16 bpp, compressed without header, destination 3 x 1: the fourth pixel is padding.
	stream := cat([]byte{0x84}, px(0xf800, 0x07e0, 0x001f, 0x1234))
	update, err := parseRDPBitmapUpdateDataAt(rect(10, 20, 12, 20, 4, 1, 16, rdpBitmapCompressed|rdpBitmapNoCompHdr, stream), 100, 100, 16)
	if err != nil || len(update.Rectangles) != 1 {
		t.Fatalf("%+v, %v", update, err)
	}
	got := update.Rectangles[0]
	if got.X != 10 || got.Y != 20 || got.Width != 3 || got.Height != 1 ||
		!bytes.Equal(got.Pixels, []byte{255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255}) {
		t.Fatalf("%+v", got)
	}
	raw := cat(px(0xffff, 0xffff))
	if _, err := parseRDPBitmapUpdateDataAt(rect(0, 0, 1, 0, 2, 1, 16, 0, raw), 10, 10, 16); err != nil {
		t.Fatalf("raw 16 bpp: %v", err)
	}
	for name, payload := range map[string][]byte{
		"32-bpp rectangle in a 16-bpp session": rect(0, 0, 1, 0, 2, 1, 32, 0, make([]byte, 8)),
		"15-bpp rectangle in a 16-bpp session": rect(0, 0, 1, 0, 2, 1, 15, 0, raw),
		"destination wider than the bitmap":    rect(0, 0, 2, 0, 2, 1, 16, 0, raw),
		"destination taller than the bitmap":   rect(0, 0, 1, 1, 2, 1, 16, 0, raw),
		// Padding is to four pixels of width only: a bitmap larger than that would let a server make
		// the client decode far more than it shows.
		"bitmap wider than padding to four":  rect(0, 0, 0, 0, 8, 1, 16, 0, make([]byte, 16)),
		"bitmap taller than its destination": rect(0, 0, 1, 0, 2, 2, 16, 0, make([]byte, 8)),
		"destination past the desktop":       rect(9, 0, 10, 0, 2, 1, 16, 0, raw),
		"right before left":                  rect(1, 0, 0, 0, 2, 1, 16, 0, raw),
	} {
		if _, err := parseRDPBitmapUpdateDataAt(payload, 10, 10, 16); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := parseRDPBitmapUpdateDataAt(rect(0, 0, 1, 0, 2, 1, 24, 0, make([]byte, 8)), 10, 10, 24); err == nil {
		t.Error("a 24-bpp session accepted")
	}
}

// Run #36: Windows' first update is the whole screen, 260 tiles of 64 x 64 in one Fast-Path PDU.
func TestBitmapUpdateCarriesAWholeScreenOfTiles(t *testing.T) {
	const tiles = 260
	payload := binary.LittleEndian.AppendUint16(nil, tiles)
	tile := cat([]byte{0xf3, 0x00, 0x10}, px(0x1234)) // mega mega color run of 64 x 64 pixels
	for i := 0; i < tiles; i++ {
		left, top := uint16(i%20*64), uint16(i/20*64)
		for _, v := range []uint16{left, top, left + 63, top + 63, 64, 64, 16, rdpBitmapCompressed | rdpBitmapNoCompHdr, uint16(len(tile))} {
			payload = binary.LittleEndian.AppendUint16(payload, v)
		}
		payload = append(payload, tile...)
	}
	update, err := parseRDPBitmapUpdateDataAt(payload, 1280, 832, 16)
	if err != nil || len(update.Rectangles) != tiles {
		t.Fatalf("%d rectangles, %v", len(update.Rectangles), err)
	}
	fb, err := NewRDPFramebuffer(1280, 832)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fb.Apply(update, time.Now()); err != nil {
		t.Fatalf("framebuffer: %v", err)
	}
	// Beyond the bound, refused.
	over := binary.LittleEndian.AppendUint16(nil, maxRDPBitmapUpdateRects+1)
	if _, err := parseRDPBitmapUpdateDataAt(over, 1280, 832, 16); err == nil {
		t.Fatal("more rectangles than the bound accepted")
	}
}

func TestOrdersAreRefusedOutsideThirtyTwoBPP(t *testing.T) {
	share := make([]byte, 18+2+4)
	binary.LittleEndian.PutUint16(share[0:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint32(share[6:10], 0x000103ea)
	share[14] = rdpPDU2Update
	binary.LittleEndian.PutUint16(share[18:20], rdpUpdateOrders)
	if _, _, err := parseRDPBitmapShareDataAt(share, 0x000103ea, 100, 100, 16, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("orders at 16 bpp: %v", err)
	}
}

func FuzzDecodeInterleavedRLE16(f *testing.F) {
	f.Add([]byte{0x83, 1, 2, 3, 4, 5, 6}, uint8(3), uint8(1), true)
	f.Add([]byte{0x02, 0x02, 0xf9, 0xfd, 0xfe}, uint8(12), uint8(1), false)
	f.Add([]byte{0xf2, 9, 0, 0xff, 0x00}, uint8(9), uint8(1), true)
	f.Fuzz(func(t *testing.T, stream []byte, width, height uint8, sixteen bool) {
		bpp := uint16(15)
		if sixteen {
			bpp = 16
		}
		got, err := decodeInterleavedRLE16(stream, int(width), int(height), bpp)
		if err == nil && len(got) != int(width)*int(height) {
			t.Fatalf("%d pixels for %d x %d", len(got), width, height)
		}
	})
}

func repeat(v uint16, n int) []uint16 {
	out := make([]uint16, n)
	for i := range out {
		out[i] = v
	}
	return out
}

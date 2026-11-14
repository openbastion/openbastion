package rdp

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// NSCodec of ADR-0101, increment 3b (MS-RDPNSC): the planes raw and run-length encoded, the chroma
// subsampled on padded planes, the colour transform, and what a target may not send.

// nscStream is an NSCODEC_BITMAP_STREAM: the four counts, ColorLossLevel, ChromaSubsamplingLevel,
// two reserved bytes, the planes.
func nscStream(loss, subsampling byte, planes ...[]byte) []byte {
	out := []byte{}
	for i := range 4 {
		var n int
		if i < len(planes) {
			n = len(planes[i])
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(n))
	}
	out = append(out, loss, subsampling, 0, 0)
	for _, p := range planes {
		out = append(out, p...)
	}
	return out
}

// nscDraw decodes stream onto surface 1 of a compositor, directly: ClearCodec bounds a subcodec to
// three bytes a pixel, which raw planes always pass (TestNSCodec_ThroughClearCodec goes through it).
func nscDraw(t *testing.T, w, h int, stream []byte) *RDPGraphicsCompositor {
	t.Helper()
	c := clearSurface(t, w, h)
	if err := decodeNSCodec(stream, clearTarget{s: c.surfaces[1], w: w, h: h}); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNSCodec_ThroughClearCodec(t *testing.T) {
	// 8 x 8 subsampled: 64 + 16 + 16 bytes of planes, 116 with the header, under 3 x 64.
	co := make([]byte, 16)
	co[0] = 0x10
	c := clearSurface(t, 8, 8)
	drawClear(t, c, 8, 8, clearStream(0, 0, composite(nil, nil, subcodec(0, 0, 8, 8, clearSubcodecNSC,
		nscStream(1, 1, repeatByte(100, 64), co, make([]byte, 16))))))
	if rgb(c, 1, 1) != [3]byte{116, 100, 84} || rgb(c, 2, 2) != [3]byte{100, 100, 100} {
		t.Fatalf("NSCodec in ClearCodec: %v %v", rgb(c, 1, 1), rgb(c, 2, 2))
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestNSCodec_RawPlanesAndTheColours(t *testing.T) {
	// 2 x 2 at ColorLossLevel 1: luma 100 everywhere; chroma per pixel, shifted by 0 bits: co 0x10 is
	// +16 on red and -16 on blue (R = Y + Co - Cg, B = Y - Co - Cg).
	luma := repeatByte(100, 4)
	co := []byte{0x10, 0, 0xf0, 0}
	cg := []byte{0, 0x10, 0, 0}
	c := nscDraw(t, 2, 2, nscStream(1, 0, luma, co, cg))
	for _, check := range []struct {
		x, y int
		want [3]byte
	}{
		{0, 0, [3]byte{116, 100, 84}}, // co +16: red +16, blue -16
		{1, 0, [3]byte{84, 116, 84}},  // cg +16: green +16, red and blue -16
		{0, 1, [3]byte{84, 100, 116}}, // co -16
		{1, 1, [3]byte{100, 100, 100}},
	} {
		if got := rgb(c, check.x, check.y); got != check.want {
			t.Errorf("(%d, %d) = %v, want %v", check.x, check.y, got, check.want)
		}
	}
	// An alpha plane is read, and the surface's alpha left as it is.
	c = nscDraw(t, 2, 2, nscStream(1, 0, luma, co, cg, repeatByte(0x20, 4)))
	if c.surfaces[1].pix[3] != 0xff {
		t.Fatalf("the alpha drawn: %d", c.surfaces[1].pix[3])
	}
}

// A pixel of the CI's Windows Server 2022 wallpaper (PR #199, message 8 of the session): Y 107,
// Co 37, Cg 63 at ColorLossLevel 3. Shifted by two bits, then signed: Co -108, Cg -4: blue.
func TestNSCodec_AWindowsWallpaperPixel(t *testing.T) {
	c := nscDraw(t, 1, 1, nscStream(3, 0, []byte{107}, []byte{37}, []byte{63}))
	if got := rgb(c, 0, 0); got != [3]byte{3, 103, 219} {
		t.Fatalf("Windows' wallpaper: %v, want 3, 103, 219", got)
	}
}

func TestNSCodec_SubsampledChromaOnPaddedPlanes(t *testing.T) {
	// 3 x 3 subsampled: luma 8 x 3 (padded to 8), chroma 4 x 2 (8 / 2, then 4 / 2 rows).
	luma := repeatByte(100, 8*3)
	co := make([]byte, 4*2)
	co[0], co[1], co[4] = 0x10, 0xf0, 0x08 // (0,0)-(1,1): +32; (2,0)-(2,1): -32; (0,2)-(1,2): +16
	cg := make([]byte, 4*2)
	c := nscDraw(t, 3, 3, nscStream(1, 1, luma, co, cg))
	for _, check := range []struct {
		x, y int
		want [3]byte
	}{
		{0, 0, [3]byte{116, 100, 84}}, {1, 1, [3]byte{116, 100, 84}},
		{2, 0, [3]byte{84, 100, 116}}, {2, 1, [3]byte{84, 100, 116}},
		{0, 2, [3]byte{108, 100, 92}}, {2, 2, [3]byte{100, 100, 100}},
	} {
		if got := rgb(c, check.x, check.y); got != check.want {
			t.Errorf("(%d, %d) = %v, want %v", check.x, check.y, got, check.want)
		}
	}
}

func TestNSCodec_RunLengthEncodedPlanes(t *testing.T) {
	// A plane of 300 bytes: a literal 7, a run of 9 (factor 7), a run of 286 (factor 0xFF, then
	// the uint32), and EndData's four bytes. The chroma planes are raw.
	plane := []byte{7, 50, 50, 7}
	plane = append(plane, 60, 60, 0xff)
	plane = binary.LittleEndian.AppendUint32(plane, 286)
	plane = append(plane, 1, 2, 3, 4)
	got, err := nscPlane(plane, 300)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 7 || got[1] != 50 || got[9] != 50 || got[10] != 60 || got[295] != 60 || got[296] != 1 || got[299] != 4 {
		t.Fatalf("the plane: % x ... % x", got[:12], got[290:])
	}
	// The byte just before EndData is a literal, even when EndData starts with it: five 5, a 9,
	// then EndData 9, 1, 2, 3.
	got, err = nscPlane([]byte{5, 5, 3, 9, 9, 1, 2, 3}, 10)
	if err != nil || string(got) != string([]byte{5, 5, 5, 5, 5, 9, 9, 1, 2, 3}) {
		t.Fatalf("a literal before EndData: % x, %v", got, err)
	}
	// Drawn: luma run-length encoded, 20 x 1.
	luma := []byte{100, 100, 14, 1, 2, 3, 4}
	c := nscDraw(t, 20, 1, nscStream(1, 0, luma, make([]byte, 20), make([]byte, 20)))
	if rgb(c, 15, 0) != [3]byte{100, 100, 100} || rgb(c, 19, 0) != [3]byte{4, 4, 4} {
		t.Fatalf("an RLE luma plane: %v %v", rgb(c, 15, 0), rgb(c, 19, 0))
	}
}

func TestNSCodec_RefusesWhatATargetMayNotSend(t *testing.T) {
	raw := func(n int) []byte { return make([]byte, n) }
	for name, stream := range map[string][]byte{
		"a header cut short":          nscStream(1, 0)[:19],
		"ColorLossLevel 0":            nscStream(0, 0, raw(4), raw(4), raw(4)),
		"ColorLossLevel 8":            nscStream(8, 0, raw(4), raw(4), raw(4)),
		"ChromaSubsamplingLevel 2":    nscStream(1, 2, raw(4), raw(4), raw(4)),
		"an empty luma plane":         nscStream(1, 0, nil, raw(4), raw(4)),
		"an empty chroma plane":       nscStream(1, 0, raw(4), nil, raw(4)),
		"a plane larger than its own": nscStream(1, 0, raw(5), raw(4), raw(4)),
		"counts past the stream":      append(nscStream(1, 0, raw(4), raw(4), raw(4)), 0)[:31],
		"counts short of the stream":  append(nscStream(1, 0, raw(4), raw(4), raw(4)), 0),
		"an alpha plane too large":    nscStream(1, 0, raw(4), raw(4), raw(4), raw(5)),
		"a run past the plane":        nscStream(1, 0, []byte{1, 1, 3, 0, 0, 0, 0}, raw(4), raw(4)),
		"a run cut short":             nscStream(1, 0, []byte{1, 1}, raw(4), raw(4)),
		"EndData cut short":           nscStream(1, 0, []byte{1, 2, 3}, raw(4), raw(4)),
	} {
		c := clearSurface(t, 2, 2)
		err := decodeNSCodec(stream, clearTarget{s: c.surfaces[1], w: 2, h: 2})
		if !errors.Is(err, ErrRDPGraphics) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A run past the plane; EndData of five bytes; an empty luma plane, refused by its count.
	if _, err := nscPlane([]byte{1, 1, 8, 1, 2, 3, 4}, 10); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a run of 10 in a plane of 10: %v", err)
	}
	if _, err := nscPlane([]byte{1, 1, 4, 7, 7, 7, 7, 0}, 10); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("EndData of five bytes: %v", err)
	}
	c := clearSurface(t, 2, 2)
	if err := decodeNSCodec(nscStream(1, 0, nil, make([]byte, 4), make([]byte, 4)), clearTarget{s: c.surfaces[1], w: 2, h: 2}); err == nil || !strings.Contains(err.Error(), "planes of") {
		t.Errorf("an empty luma plane: %v", err)
	}
	// An RLE plane of a bitmap under four pixels has no room for EndData.
	if _, err := nscPlane([]byte{1, 1}, 3); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("an RLE plane of 3: %v", err)
	}
	// A long run (factor 0xFF) cut short of its uint32.
	if _, err := nscPlane([]byte{1, 1, 0xff, 0, 0, 1, 2, 3, 4}, 300); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a long run cut short: %v", err)
	}
}

func FuzzNSCodec(f *testing.F) {
	f.Add(nscStream(1, 0, repeatByte(100, 16), repeatByte(0x10, 16), repeatByte(0, 16)), uint8(4), uint8(4))
	f.Add(nscStream(3, 1, []byte{100, 100, 14, 1, 2, 3, 4}, repeatByte(0, 8), repeatByte(0, 8), repeatByte(9, 9)), uint8(3), uint8(3))
	f.Fuzz(func(t *testing.T, stream []byte, w, h uint8) {
		if w == 0 || h == 0 || w > 64 || h > 64 {
			return
		}
		s := &graphicsSurface{width: int(w), height: int(h), pix: make([]byte, int(w)*int(h)*4)}
		if err := decodeNSCodec(stream, clearTarget{s: s, w: int(w), h: int(h)}); err != nil && !errors.Is(err, ErrRDPGraphics) {
			t.Fatalf("an error outside ErrRDPGraphics: %v", err)
		}
	})
}

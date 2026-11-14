package rdp

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// RemoteFX Progressive of ADR-0101, increment 4: RLGR1 and Simplified-RL on bit streams worked out by
// hand from their rules, the inverse DWTs and the colour conversion on values whose result is known,
// the blocks and the passes, and what a target may not send. The end-to-end image is FreeRDP's
// (TestRDPInterop_GraphicsPipeline) and the CI's Windows' (graphics-pipeline.png).

// bitsOf packs a string of 0 and 1, spaces ignored, most significant bit first.
func bitsOf(s string) []byte {
	var w zgfxWriter
	w.pattern(s)
	return w.data
}

func TestProgressive_RLGR1(t *testing.T) {
	for name, c := range map[string]struct {
		bits string
		want map[int]int16
	}{
		// k = 1, kp = 8, kr = 1, krp = 8. Run-length mode: no zero ("1"), a remainder of 0 ("0"),
		// sign + ("0"), then a code 0 ("0" ones, "0" for kr's bit): magnitude 1. kp drops to 2.
		"one":       {"1 0 0 0 0", map[int]int16{0: 1}},
		"minus one": {"1 0 1 0 0", map[int]int16{0: -1}},
		// One zero bit: a run of 1 << k = 2, k stays 1 (kp 12); remainder 1: a run of 3, then +1.
		"a run of three": {"0 1 1 0 0 0", map[int]int16{3: 1}},
		// After the first symbol k is 0: Golomb-Rice. "10": one 1 then 0, kr 0: code 1, odd: -1.
		"then Golomb-Rice": {"1 0 0 0 0 1 0", map[int]int16{0: 1, 1: -1}},
	} {
		out := make([]int16, progCoefficients)
		if err := rlgr1Decode(bitsOf(c.bits), out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, v := range out {
			if v != c.want[i] {
				t.Fatalf("%s: coefficient %d = %d, want %d", name, i, v, c.want[i])
			}
		}
	}
	if err := rlgr1Decode(nil, make([]int16, progCoefficients)); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("an empty stream: %v", err)
	}
	// A run past the 4,096 coefficients is cut there, as FreeRDP cuts it.
	long := strings.Repeat("0", 40) + " 1"
	out := make([]int16, progCoefficients)
	if err := rlgr1Decode(bitsOf(long), out); err != nil {
		t.Fatal(err)
	}
}

func TestProgressive_SimplifiedRL(t *testing.T) {
	// kp 8, k 1: "0" is a run of two zeros (kp 12); then k 1 again: "1", a count "0", then the
	// value: sign "1", magnitude "01" (2) on 3 bits: -2.
	s := progSRL{bits: bitReader{data: bitsOf("0 1 0 1 0 1")}, kp: 8}
	var got []int16
	for range 3 {
		v, err := s.read(3)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if got[0] != 0 || got[1] != 0 || got[2] != -2 || s.kp != 6 {
		t.Fatalf("SRL %v, kp %d", got, s.kp)
	}
	// One bit: the sign alone. The largest magnitude has no terminating bit.
	s = progSRL{bits: bitReader{data: bitsOf("1 0 0")}, kp: 0}
	if v, err := s.read(1); err != nil || v != 1 {
		t.Fatalf("one bit: %d, %v", v, err)
	}
	s = progSRL{bits: bitReader{data: bitsOf("1 0 0 0")}, kp: 0}
	if v, err := s.read(2); err != nil || v != 3 {
		t.Fatalf("magnitude 3 of 2 bits: %d, %v", v, err)
	}
	s = progSRL{bits: bitReader{data: nil}, kp: 8}
	if _, err := s.read(3); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("cut short: %v", err)
	}
}

func TestProgressive_InverseDWTsKeepAFlatImage(t *testing.T) {
	// LL3 alone, all 100: every pixel of the 64 x 64 tile is 100, with either DWT.
	for _, extrapolate := range []bool{true, false} {
		tile := &progTile{extrapolate: extrapolate}
		ll := progBands(extrapolate)[9]
		for c := range 3 {
			for i := ll[0]; i < ll[0]+ll[1]; i++ {
				tile.components[c].current[i] = 0
			}
		}
		for i := ll[0]; i < ll[0]+ll[1]; i++ {
			tile.components[0].current[i] = 100 << 5
		}
		tile.toPixels()
		// Y 100 << 5 is 228 once level-shifted by 128: grey 228 everywhere.
		for i := 0; i < len(tile.pixels); i += 3 {
			if tile.pixels[i] != 228 || tile.pixels[i+1] != 228 || tile.pixels[i+2] != 228 {
				t.Fatalf("extrapolate %v: pixel %d = %v", extrapolate, i/3, tile.pixels[i:i+3])
			}
		}
	}
}

func TestProgressive_TheColourConversion(t *testing.T) {
	tile := &progTile{extrapolate: false}
	ll := progBandsOriginal[9]
	// Cr +1024 (32 in 11.5 fixed point): red 128 + 1.402525 x 32, floored: 172; green 128 - 0.714401
	// x 32: 105; blue 128.
	for i := ll[0]; i < ll[0]+ll[1]; i++ {
		tile.components[2].current[i] = 1024
	}
	tile.toPixels()
	if got := tile.pixels[0:3]; got[0] != 128 || got[1] != 105 || got[2] != 172 {
		t.Fatalf("Cr +32: blue, green, red %v", got)
	}
}

// progStream builds a WireToSurface2's bitmap data: blocks of (type, body).
func progBlock(kind uint16, body []byte) []byte {
	out := binary.LittleEndian.AppendUint16(nil, kind)
	out = binary.LittleEndian.AppendUint32(out, uint32(6+len(body)))
	return append(out, body...)
}

// progRegionBlock is a region of one rectangle, the quantizations given, and the tiles.
func progRegionBlock(flags byte, rect [4]int, quants [][5]byte, progQuants [][16]byte, tiles ...[]byte) []byte {
	var tileData []byte
	for _, t := range tiles {
		tileData = append(tileData, t...)
	}
	b := []byte{progTileSize}
	b = binary.LittleEndian.AppendUint16(b, 1)
	b = append(b, byte(len(quants)), byte(len(progQuants)), flags)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(tiles)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(tileData)))
	b = (&gfx{b: b}).u16(rect[0], rect[1], rect[2], rect[3]).b
	for _, q := range quants {
		b = append(b, q[:]...)
	}
	for _, q := range progQuants {
		b = append(b, q[:]...)
	}
	return progBlock(progBlockRegion, append(b, tileData...))
}

// simpleTile is a TILE_SIMPLE at (x, y) whose three components are the RLGR1 streams given.
func simpleTile(x, y int, flags byte, y_, cb, cr []byte) []byte {
	b := []byte{0, 0, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(x))
	b = binary.LittleEndian.AppendUint16(b, uint16(y))
	b = append(b, flags)
	for _, n := range []int{len(y_), len(cb), len(cr), 0} {
		b = binary.LittleEndian.AppendUint16(b, uint16(n))
	}
	return progBlock(progBlockSimple, append(append(append(b, y_...), cb...), cr...))
}

func firstTile(x, y int, quality byte, y_, cb, cr []byte) []byte {
	b := []byte{0, 0, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(x))
	b = binary.LittleEndian.AppendUint16(b, uint16(y))
	b = append(b, 0, quality)
	for _, n := range []int{len(y_), len(cb), len(cr), 0} {
		b = binary.LittleEndian.AppendUint16(b, uint16(n))
	}
	return progBlock(progBlockFirst, append(append(append(b, y_...), cb...), cr...))
}

func upgradeTile(x, y int, quality byte, streams [6][]byte) []byte {
	b := []byte{0, 0, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(x))
	b = binary.LittleEndian.AppendUint16(b, uint16(y))
	b = append(b, quality)
	for _, s := range streams {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	}
	for _, s := range streams {
		b = append(b, s...)
	}
	return progBlock(progBlockUpgrade, b)
}

// quant6 is a RFX_COMPONENT_CODEC_QUANT of 6 for every band: a shift of 5, FreeRDP's "-6 + 5".
var quant6 = [5]byte{0x66, 0x66, 0x66, 0x66, 0x66}

func progApply(t *testing.T, c *RDPGraphicsCompositor, data []byte) error {
	t.Helper()
	g := (&gfx{}).u16(1, int(rdpGraphicsCodecProgressive)).u32(7).raw(rdpGraphicsPixelXRGB).u32(uint32(len(data))).raw(data...)
	_, _, err := c.Apply(pdu(RDPGraphicsWireToSurface2, g))
	return err
}

func TestProgressive_ASimpleTileDrawnInItsRegion(t *testing.T) {
	c := clearSurface(t, 100, 70)
	// Each component one byte of zero bits: RLGR1 finds no end to its run, and every coefficient is
	// zero: grey 128. Only the region's rectangle (10, 5)-(30, 25) is drawn.
	zero := bitsOf("0")
	data := append(progBlock(progBlockSync, []byte{0xca, 0xac, 0xcc, 0xca, 0, 1}),
		progBlock(progBlockContext, []byte{0, progTileSize, 0, 0})...)
	data = append(data, progBlock(progBlockBegin, []byte{1, 0, 0, 0, 1, 0})...)
	data = append(data, progRegionBlock(0, [4]int{10, 5, 20, 20}, [][5]byte{quant6}, nil,
		simpleTile(0, 0, 0, zero, zero, zero))...)
	data = append(data, progBlock(progBlockEnd, nil)...)
	if err := progApply(t, c, data); err != nil {
		t.Fatal(err)
	}
	if rgb(c, 15, 15) != [3]byte{128, 128, 128} || rgb(c, 9, 15) != [3]byte{} || rgb(c, 30, 15) != [3]byte{} {
		t.Fatalf("inside %v, left of it %v, right of it %v", rgb(c, 15, 15), rgb(c, 9, 15), rgb(c, 30, 15))
	}
	if c.surfaces[1].dirty.Empty() {
		t.Fatal("the surface not marked changed")
	}
	// The tile at (1, 1) is past the 100 x 70 surface's bottom edge in part: drawn to the edge.
	data = progRegionBlock(0, [4]int{64, 64, 36, 6}, [][5]byte{quant6}, nil, simpleTile(1, 1, 0, zero, zero, zero))
	if err := progApply(t, c, data); err != nil {
		t.Fatal(err)
	}
	if rgb(c, 99, 69) != [3]byte{128, 128, 128} {
		t.Fatalf("the corner %v", rgb(c, 99, 69))
	}
}

func TestProgressive_AFirstPassThenAnUpgrade(t *testing.T) {
	c := clearSurface(t, 64, 64)
	// A progressive quantization of 1 on LL3 for Y only: the first pass sends LL3 at bit position
	// 6 + 1, the upgrade brings it to 6 + 0, one raw bit for each of the 81 LL3 coefficients.
	var pq [16]byte
	pq[0] = 50
	pq[1] = 0x01 // Y: LL3 1
	zero := bitsOf("0")
	data := progRegionBlock(progFlagExtrapol, [4]int{0, 0, 64, 64}, [][5]byte{quant6}, [][16]byte{pq},
		firstTile(0, 0, 0, zero, zero, zero))
	if err := progApply(t, c, data); err != nil {
		t.Fatal(err)
	}
	tile := c.progressive.surfaces[1].tiles[0]
	if tile.components[0].bitPos[9] != 7 || tile.passes != 1 {
		t.Fatalf("after the first pass: bit position %d, %d pass(es)", tile.components[0].bitPos[9], tile.passes)
	}
	// The upgrade: Y's raw stream is 81 one-bits (each LL3 coefficient + 1 << 5), padded; its SRL
	// stream and Cb's and Cr's streams are empty (no bit to send).
	raw := make([]byte, 11)
	for i := range 81 {
		raw[i/8] |= 0x80 >> (i % 8)
	}
	data = progRegionBlock(progFlagExtrapol, [4]int{0, 0, 64, 64}, [][5]byte{quant6}, nil,
		upgradeTile(0, 0, progQualityFull, [6][]byte{nil, raw, nil, nil, nil, nil}))
	if err := progApply(t, c, data); err != nil {
		t.Fatal(err)
	}
	for i := 4015; i < 4096; i++ {
		if tile.components[0].current[i] != 1<<5 {
			t.Fatalf("LL3 coefficient %d = %d after the upgrade", i, tile.components[0].current[i])
		}
	}
	if tile.passes != 2 || tile.components[0].bitPos[9] != 6 {
		t.Fatalf("after the upgrade: %d passes, bit position %d", tile.passes, tile.components[0].bitPos[9])
	}
	// One raw byte too many is refused: the streams must be read to their end.
	c2 := clearSurface(t, 64, 64)
	if err := progApply(t, c2, progRegionBlock(progFlagExtrapol, [4]int{0, 0, 64, 64}, [][5]byte{quant6}, [][16]byte{pq},
		firstTile(0, 0, 0, zero, zero, zero))); err != nil {
		t.Fatal(err)
	}
	if err := progApply(t, c2, progRegionBlock(progFlagExtrapol, [4]int{0, 0, 64, 64}, [][5]byte{quant6}, nil,
		upgradeTile(0, 0, progQualityFull, [6][]byte{nil, append(raw, 0), nil, nil, nil, nil}))); !errors.Is(err, ErrRDPGraphics) {
		t.Fatalf("a raw byte too many: %v", err)
	}
}

func TestProgressive_RefusesWhatATargetMayNotSend(t *testing.T) {
	zero := bitsOf("0")
	q := [][5]byte{quant6}
	region := func(tiles ...[]byte) []byte { return progRegionBlock(0, [4]int{0, 0, 64, 64}, q, nil, tiles...) }
	badQuality := firstTile(0, 0, 3, zero, zero, zero)
	shortTile := simpleTile(0, 0, 0, zero, zero, zero)
	binary.LittleEndian.PutUint16(shortTile[6+8:], 9) // yLen past the block
	for name, data := range map[string][]byte{
		"an unknown block":              progBlock(0xccc8, nil),
		"a block header cut short":      {0xc0, 0xcc, 12},
		"a block past the data":         progBlock(progBlockSync, make([]byte, 6))[:10],
		"a SYNC of 11 bytes":            progBlock(progBlockSync, make([]byte, 5)),
		"a FRAME_END with a body":       progBlock(progBlockEnd, []byte{0}),
		"a CONTEXT of tile size 32":     progBlock(progBlockContext, []byte{0, 32, 0, 0}),
		"a region of no rectangle":      progBlock(progBlockRegion, append([]byte{progTileSize, 0, 0, 1, 0, 0, 0, 0}, make([]byte, 4)...)),
		"a region of tile size 32":      append([]byte{}, func() []byte { r := region(); r[6] = 32; return r }()...),
		"a tile past the grid":          region(simpleTile(1, 0, 0, zero, zero, zero)),
		"a tile count not the tiles'":   func() []byte { r := region(); r[6+6] = 1; return r }(),
		"a quantization index past":     func() []byte { t := simpleTile(0, 0, 0, zero, zero, zero); t[6] = 1; return region(t) }(),
		"a quality past the tables":     region(badQuality),
		"a tile's lengths past it":      region(shortTile),
		"an upgrade never first-passed": region(upgradeTile(0, 0, progQualityFull, [6][]byte{})),
		"an empty RLGR1 stream":         region(simpleTile(0, 0, 0, nil, zero, zero)),
		"an unknown tile block":         region(progBlock(0xccc4, make([]byte, 16))),
	} {
		c := clearSurface(t, 64, 64)
		if err := progApply(t, c, data); !errors.Is(err, ErrRDPGraphics) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Eight quantization tables, one past the seven allowed.
	c := clearSurface(t, 64, 64)
	eight := [][5]byte{quant6, quant6, quant6, quant6, quant6, quant6, quant6, quant6}
	if err := progApply(t, c, progRegionBlock(0, [4]int{0, 0, 64, 64}, eight, nil, simpleTile(0, 0, 0, zero, zero, zero))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("eight quantization tables: %v", err)
	}
	// A progressive quantization above 8; more than 1,024 tiles kept; a WireToSurface2 of another codec.
	var pq [16]byte
	pq[1] = 0x09
	c = clearSurface(t, 64, 64)
	if err := progApply(t, c, progRegionBlock(0, [4]int{0, 0, 64, 64}, q, [][16]byte{pq}, firstTile(0, 0, 0, zero, zero, zero))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a progressive quantization of 9: %v", err)
	}
	c = clearSurface(t, 64, 64)
	c.progressive = &progressiveCodec{surfaces: map[uint16]*progSurface{}, tiles: maxProgressiveTiles}
	if err := progApply(t, c, region(simpleTile(0, 0, 0, zero, zero, zero))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("a tile past %d: %v", maxProgressiveTiles, err)
	}
	// An upgrade of a tile first sent with the other DWT.
	c = clearSurface(t, 64, 64)
	if err := progApply(t, c, region(simpleTile(0, 0, 0, zero, zero, zero))); err != nil {
		t.Fatal(err)
	}
	if err := progApply(t, c, progRegionBlock(progFlagExtrapol, [4]int{0, 0, 64, 64}, q, nil, upgradeTile(0, 0, progQualityFull, [6][]byte{}))); !errors.Is(err, ErrRDPGraphics) {
		t.Errorf("an upgrade of another DWT: %v", err)
	}
	// Deleting the surface forgets its tiles.
	mustApply(t, c, pdu(RDPGraphicsDeleteSurface, (&gfx{}).u16(1)))
	if c.progressive.tiles != 0 || c.progressive.surfaces[1] != nil {
		t.Fatalf("after the delete: %d tile(s)", c.progressive.tiles)
	}
}

func FuzzRDPGraphicsProgressive(f *testing.F) {
	zero := bitsOf("0")
	f.Add(progRegionBlock(0, [4]int{0, 0, 64, 64}, [][5]byte{quant6}, nil, simpleTile(0, 0, 0, zero, zero, zero)))
	var pq [16]byte
	pq[1] = 0x01
	f.Add(progRegionBlock(progFlagExtrapol, [4]int{0, 0, 64, 64}, [][5]byte{quant6}, [][16]byte{pq}, firstTile(0, 0, 0, zero, zero, zero),
		upgradeTile(0, 0, progQualityFull, [6][]byte{nil, make([]byte, 11), nil, nil, nil, nil})))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := NewRDPGraphicsCompositor()
		if _, _, err := c.Apply(createSurface(1, 100, 70, rdpGraphicsPixelXRGB)); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := progApply(t, c, data); err != nil && !errors.Is(err, ErrRDPGraphics) {
				t.Fatalf("an error outside ErrRDPGraphics: %v", err)
			}
		}
	})
}

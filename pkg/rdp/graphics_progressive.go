package rdp

import (
	"encoding/binary"
	"fmt"
	"image"
)

// RemoteFX Progressive (MS-RDPEGFX 2.2.4.2, 3.3.8.2), ADR-0101 increment 4: the codec the CI's
// Windows send one to five bitmaps a session with, and FreeRDP all its frames. It is lossy; the
// decoded image is what the operator sees and what is recorded (ADR-0101, decision of 14 November
// 2026). A WireToSurface2 holds blocks: a region of 64 x 64 tiles, each tile three components (Y,
// Cb, Cr) of 4,096 DWT coefficients, entropy coded (RLGR1), quantized per sub-band, sent at once
// (simple), or as a first pass refined by upgrade passes (raw bits and Simplified-RL).
//
// The spec gives the structures in text and the algorithms as figures (RLGR adaptation, DWT
// lifting, colour matrix): these follow FreeRDP 3.15 (libfreerdp/codec/progressive.c, rfx_rlgr.c,
// primitives/prim_colors.c), read as a reference and written anew here, with the same integer
// arithmetic, so that the image is the one FreeRDP shows. Both inverse DWTs are decoded: the
// Reduce-Extrapolate one (RFX_DWT_REDUCE_EXTRAPOLATE, 3.2.8.1.2.2) and RemoteFX's original one
// (MS-RDPRFX 3.1.8.2.4), which FreeRDP's own server uses.

const (
	progBlockSync      = uint16(0xccc0)
	progBlockBegin     = uint16(0xccc1)
	progBlockEnd       = uint16(0xccc2)
	progBlockContext   = uint16(0xccc3)
	progBlockRegion    = uint16(0xccc4)
	progBlockSimple    = uint16(0xccc5)
	progBlockFirst     = uint16(0xccc6)
	progBlockUpgrade   = uint16(0xccc7)
	progTileSize       = 64
	progCoefficients   = 4096
	progFlagExtrapol   = byte(0x01) // RFX_DWT_REDUCE_EXTRAPOLATE, in a region
	progFlagDifference = byte(0x01) // RFX_TILE_DIFFERENCE, in a tile
	progQualityFull    = byte(0xff)
	// maxProgressiveTiles bounds the tiles a channel keeps the state of (48 KiB each): a desktop of
	// 1280 x 800 has 260.
	maxProgressiveTiles         = 1024
	rdpGraphicsCodecProgressive = uint16(0x0009)
)

// The sub-bands of a tile in the order they are coded, offset and length: Reduce-Extrapolate, then
// the original layout.
var progBandsExtrapolate = [10][2]int{
	{0, 1023}, {1023, 1023}, {2046, 961}, // HL1, LH1, HH1
	{3007, 272}, {3279, 272}, {3551, 256}, // HL2, LH2, HH2
	{3807, 72}, {3879, 72}, {3951, 64}, // HL3, LH3, HH3
	{4015, 81}, // LL3
}

var progBandsOriginal = [10][2]int{
	{0, 1024}, {1024, 1024}, {2048, 1024}, // HL1, LH1, HH1
	{3072, 256}, {3328, 256}, {3584, 256}, // HL2, LH2, HH2
	{3840, 64}, {3904, 64}, {3968, 64}, // HL3, LH3, HH3
	{4032, 64}, // LL3
}

func progBands(extrapolate bool) *[10][2]int {
	if extrapolate {
		return &progBandsExtrapolate
	}
	return &progBandsOriginal
}

// progQuant is a RFX_COMPONENT_CODEC_QUANT in the order of progBands.
type progQuant [10]int

// readProgQuant reads the five bytes of a RFX_COMPONENT_CODEC_QUANT (2.2.4.2.1.5.1): LL3, HL3, LH3,
// HH3, HL2, LH2, HH2, HL1, LH1, HH1, four bits each, low nibble first.
func readProgQuant(b []byte) progQuant {
	ll3, hl3, lh3, hh3 := int(b[0]&0x0f), int(b[0]>>4), int(b[1]&0x0f), int(b[1]>>4)
	hl2, lh2, hh2, hl1 := int(b[2]&0x0f), int(b[2]>>4), int(b[3]&0x0f), int(b[3]>>4)
	lh1, hh1 := int(b[4]&0x0f), int(b[4]>>4)
	return progQuant{hl1, lh1, hh1, hl2, lh2, hh2, hl3, lh3, hh3, ll3}
}

type progComponent struct {
	current [progCoefficients]int16 // the coefficients received so far, dequantized
	sign    [progCoefficients]int16 // the persistent progressive state: what each coefficient sums to
	bitPos  progQuant
}

type progTile struct {
	components  [3]progComponent
	extrapolate bool // the DWT of its first pass, which its upgrades keep
	passes      int
	pixels      [progTileSize * progTileSize * 3]byte // BGR, the tile as last decoded
}

type progSurface struct {
	gridWidth, gridHeight int
	tiles                 map[int]*progTile
	updated               map[int]bool // tiles decoded in the current RDPGFX frame
	frame                 uint32
}

// progressiveCodec is the decoder state of one graphics channel, by surface.
type progressiveCodec struct {
	surfaces map[uint16]*progSurface
	tiles    int
}

func progRefused(format string, args ...any) error {
	return fmt.Errorf("%w: RemoteFX Progressive: "+format, append([]any{ErrRDPGraphics}, args...)...)
}

// decode draws the RFX_PROGRESSIVE_BITMAP_STREAM of a WireToSurface2 onto s, the surface of id.
func (p *progressiveCodec) decode(data []byte, id uint16, s *graphicsSurface, frame uint32) error {
	ps := p.surfaces[id]
	if ps == nil {
		ps = &progSurface{gridWidth: (s.width + progTileSize - 1) / progTileSize, gridHeight: (s.height + progTileSize - 1) / progTileSize,
			tiles: map[int]*progTile{}, updated: map[int]bool{}, frame: frame}
		p.surfaces[id] = ps
	}
	if ps.frame != frame {
		ps.frame, ps.updated = frame, map[int]bool{}
	}
	for len(data) > 0 {
		if len(data) < 6 {
			return progRefused("a block header cut short")
		}
		kind, n := binary.LittleEndian.Uint16(data[0:2]), binary.LittleEndian.Uint32(data[2:6])
		if n < 6 || uint64(n) > uint64(len(data)) {
			return progRefused("block 0x%04x of %d bytes, %d left", kind, n, len(data))
		}
		body := data[6:n]
		data = data[n:]
		switch kind {
		case progBlockSync:
			if len(body) != 6 {
				return progRefused("a SYNC of %d bytes", n)
			}
		case progBlockBegin:
			if len(body) != 6 {
				return progRefused("a FRAME_BEGIN of %d bytes", n)
			}
		case progBlockEnd:
			if len(body) != 0 {
				return progRefused("a FRAME_END of %d bytes", n)
			}
		case progBlockContext:
			if len(body) != 4 || binary.LittleEndian.Uint16(body[1:3]) != progTileSize {
				return progRefused("a CONTEXT of %d bytes", n)
			}
		case progBlockRegion:
			if err := p.region(body, ps, s); err != nil {
				return err
			}
		default:
			return progRefused("block 0x%04x", kind)
		}
	}
	return nil
}

type progRegion struct {
	rects       []image.Rectangle
	quants      []progQuant
	progQuants  [][3]progQuant
	extrapolate bool
}

// region decodes a RFX_PROGRESSIVE_REGION (2.2.4.2.1.4) and draws its tiles.
func (p *progressiveCodec) region(b []byte, ps *progSurface, s *graphicsSurface) error {
	if len(b) < 12 {
		return progRefused("a REGION cut short")
	}
	numRects, numQuant, numProg := int(binary.LittleEndian.Uint16(b[1:3])), int(b[3]), int(b[4])
	flags, numTiles, tileBytes := b[5], int(binary.LittleEndian.Uint16(b[6:8])), uint64(binary.LittleEndian.Uint32(b[8:12]))
	if b[0] != progTileSize || numRects == 0 || numQuant > 7 {
		return progRefused("a region of tile size %d, %d rect(s), %d quant(s)", b[0], numRects, numQuant)
	}
	b = b[12:]
	fixed := 8*numRects + 5*numQuant + 16*numProg
	if uint64(len(b)) != uint64(fixed)+tileBytes {
		return progRefused("a region of %d bytes for %d + %d", len(b), fixed, tileBytes)
	}
	r := progRegion{extrapolate: flags&progFlagExtrapol != 0}
	for i := range numRects {
		x, y := int(binary.LittleEndian.Uint16(b[8*i:])), int(binary.LittleEndian.Uint16(b[8*i+2:]))
		w, h := int(binary.LittleEndian.Uint16(b[8*i+4:])), int(binary.LittleEndian.Uint16(b[8*i+6:]))
		r.rects = append(r.rects, image.Rect(x, y, x+w, y+h))
	}
	b = b[8*numRects:]
	for range numQuant {
		r.quants = append(r.quants, readProgQuant(b))
		b = b[5:]
	}
	for range numProg {
		// quality, then Y, Cb and Cr: each value 0 to 8 (2.2.4.2.1.5.2).
		var q [3]progQuant
		for c := range 3 {
			q[c] = readProgQuant(b[1+5*c:])
			for _, v := range q[c] {
				if v > 8 {
					return progRefused("a progressive quantization of %d", v)
				}
			}
		}
		r.progQuants = append(r.progQuants, q)
		b = b[16:]
	}
	decoded := 0
	for len(b) > 0 {
		if len(b) < 6 {
			return progRefused("a tile header cut short")
		}
		kind, n := binary.LittleEndian.Uint16(b[0:2]), binary.LittleEndian.Uint32(b[2:6])
		if n < 6 || uint64(n) > uint64(len(b)) {
			return progRefused("tile block 0x%04x of %d bytes", kind, n)
		}
		if err := p.tile(kind, b[6:n], &r, ps); err != nil {
			return err
		}
		b = b[n:]
		decoded++
	}
	if decoded != numTiles {
		return progRefused("%d tile(s) for %d announced", decoded, numTiles)
	}
	// Every tile decoded in this frame, clipped to the region's rectangles and the surface (FreeRDP
	// draws the last region's; the spec has a region covered by its tiles and earlier ones).
	bounds := image.Rect(0, 0, s.width, s.height)
	for index := range ps.updated {
		t := ps.tiles[index]
		origin := image.Pt(index%ps.gridWidth*progTileSize, index/ps.gridWidth*progTileSize)
		tileRect := image.Rectangle{Min: origin, Max: origin.Add(image.Pt(progTileSize, progTileSize))}
		for _, rect := range r.rects {
			at := rect.Intersect(tileRect).Intersect(bounds)
			for y := at.Min.Y; y < at.Max.Y; y++ {
				for x := at.Min.X; x < at.Max.X; x++ {
					src := ((y-origin.Y)*progTileSize + x - origin.X) * 3
					dst := (y*s.width + x) * 4
					s.pix[dst], s.pix[dst+1], s.pix[dst+2] = t.pixels[src+2], t.pixels[src+1], t.pixels[src]
				}
			}
			s.dirty = s.dirty.Union(at)
		}
	}
	return nil
}

// tile decodes one tile block of a region: simple, first pass, or upgrade.
func (p *progressiveCodec) tile(kind uint16, b []byte, r *progRegion, ps *progSurface) error {
	var fixed int
	switch kind {
	case progBlockSimple:
		fixed = 16
	case progBlockFirst:
		fixed = 17
	case progBlockUpgrade:
		fixed = 20
	default:
		return progRefused("tile block 0x%04x", kind)
	}
	if len(b) < fixed {
		return progRefused("a tile of %d bytes", len(b))
	}
	qY, qCb, qCr := int(b[0]), int(b[1]), int(b[2])
	x, y := int(binary.LittleEndian.Uint16(b[3:5])), int(binary.LittleEndian.Uint16(b[5:7]))
	if qY >= len(r.quants) || qCb >= len(r.quants) || qCr >= len(r.quants) || x >= ps.gridWidth || y >= ps.gridHeight {
		return progRefused("a tile at (%d, %d) with quantizations %d, %d, %d", x, y, qY, qCb, qCr)
	}
	quants := [3]progQuant{r.quants[qY], r.quants[qCb], r.quants[qCr]}
	var flags, quality byte
	var lengths []int
	switch kind {
	case progBlockSimple:
		flags, quality = b[7], progQualityFull
		lengths = []int{int(binary.LittleEndian.Uint16(b[8:])), int(binary.LittleEndian.Uint16(b[10:])), int(binary.LittleEndian.Uint16(b[12:])), int(binary.LittleEndian.Uint16(b[14:]))}
	case progBlockFirst:
		flags, quality = b[7], b[8]
		lengths = []int{int(binary.LittleEndian.Uint16(b[9:])), int(binary.LittleEndian.Uint16(b[11:])), int(binary.LittleEndian.Uint16(b[13:])), int(binary.LittleEndian.Uint16(b[15:]))}
	case progBlockUpgrade:
		quality = b[7]
		for i := range 6 {
			lengths = append(lengths, int(binary.LittleEndian.Uint16(b[8+2*i:])))
		}
	}
	var prog [3]progQuant // the full quality: all zero
	if quality != progQualityFull {
		if int(quality) >= len(r.progQuants) {
			return progRefused("progressive quality %d of %d", quality, len(r.progQuants))
		}
		prog = r.progQuants[quality]
	}
	total := fixed
	for _, n := range lengths {
		total += n
	}
	if total != len(b) {
		return progRefused("a tile of %d bytes for %d", len(b), total)
	}
	index := y*ps.gridWidth + x
	t := ps.tiles[index]
	data := b[fixed:]
	if kind == progBlockUpgrade {
		if t == nil || t.passes == 0 || t.extrapolate != r.extrapolate {
			return progRefused("an upgrade of tile (%d, %d), never decoded or of another DWT", x, y)
		}
		for c := range 3 {
			srl, raw := data[:lengths[2*c]], data[lengths[2*c]:lengths[2*c]+lengths[2*c+1]]
			data = data[lengths[2*c]+lengths[2*c+1]:]
			if err := t.components[c].upgrade(srl, raw, quants[c], prog[c], progBands(t.extrapolate)); err != nil {
				return err
			}
		}
	} else {
		if t == nil {
			if p.tiles >= maxProgressiveTiles {
				return progRefused("more than %d tiles", maxProgressiveTiles)
			}
			t = &progTile{}
			ps.tiles[index] = t
			p.tiles++
		}
		t.passes, t.extrapolate = 0, r.extrapolate
		for c := range 3 {
			if err := t.components[c].first(data[:lengths[c]], quants[c], prog[c], flags&progFlagDifference != 0, progBands(t.extrapolate)); err != nil {
				return err
			}
			data = data[lengths[c]:]
		}
	}
	t.passes++
	t.toPixels()
	ps.updated[index] = true
	return nil
}

// first decodes the first pass, or the whole, of one component (3.3.8.2.1.1): RLGR1, the LL3
// deltas summed, each band shifted left by its quantization plus its progressive quantization
// minus one (FreeRDP: "-6 + 5"), then kept, or added to what was kept for a difference tile.
func (c *progComponent) first(data []byte, quant, prog progQuant, difference bool, bands *[10][2]int) error {
	var buffer [progCoefficients]int16
	if err := rlgr1Decode(data, buffer[:]); err != nil {
		return err
	}
	c.sign = buffer
	ll := buffer[bands[9][0] : bands[9][0]+bands[9][1]]
	for i := 1; i < len(ll); i++ {
		ll[i] += ll[i-1]
	}
	for band, span := range bands {
		shift := quant[band] + prog[band] - 1
		c.bitPos[band] = quant[band] + prog[band]
		if shift <= 0 {
			continue
		}
		for i := span[0]; i < span[0]+span[1]; i++ {
			buffer[i] <<= shift
		}
	}
	if difference {
		for i := range buffer {
			c.current[i] += buffer[i]
		}
		return nil
	}
	c.current = buffer
	return nil
}

// upgrade adds one upgrade pass (3.3.8.2.1.2): for each band, the bits between the previous bit
// position and this one, read raw where the coefficient's sign is known, by Simplified-RL where it
// is zero; LL3 always raw. Both streams must be read to their end.
func (c *progComponent) upgrade(srlData, rawData []byte, quant, prog progQuant, bands *[10][2]int) error {
	srl := progSRL{bits: bitReader{data: srlData}, kp: 8}
	raw := bitReader{data: rawData}
	for band, span := range bands {
		pos := quant[band] + prog[band]
		numBits, shift := c.bitPos[band]-pos, pos-1
		c.bitPos[band] = pos
		if numBits < 0 || numBits > 15 {
			return progRefused("an upgrade of %d bits", numBits)
		}
		if numBits == 0 {
			continue
		}
		for i := span[0]; i < span[0]+span[1]; i++ {
			var input int32
			switch {
			case band == 9 || c.sign[i] != 0:
				v, ok := raw.read(numBits)
				if !ok {
					return progRefused("raw bits cut short")
				}
				input = int32(v)
				if band != 9 && c.sign[i] < 0 {
					input = -input
				}
			default:
				v, err := srl.read(numBits)
				if err != nil {
					return err
				}
				input, c.sign[i] = int32(v), v
			}
			value := int32(c.current[i]) + input<<max(shift, 0)
			if value < -32768 || value > 32767 {
				return progRefused("a coefficient of %d", value)
			}
			c.current[i] = int16(value)
		}
	}
	// Both streams end on a byte; SRL may end with one more zero byte (3.1.8.1.5).
	rawUsed, srlUsed := (raw.at+7)/8, (srl.bits.at+7)/8
	if len(srlData)-srlUsed == 1 && srlData[len(srlData)-1] == 0 {
		srlUsed++
	}
	if rawUsed != len(rawData) || srlUsed != len(srlData) {
		return progRefused("an upgrade reading %d of %d raw and %d of %d SRL bytes", rawUsed, len(rawData), srlUsed, len(srlData))
	}
	return nil
}

// bitReader reads bits most significant first.
type bitReader struct {
	data []byte
	at   int
}

func (r *bitReader) read(n int) (uint32, bool) {
	if n < 0 || n > 32 || len(r.data)*8-r.at < n {
		return 0, false
	}
	var v uint32
	for range n {
		v = v<<1 | uint32(r.data[r.at>>3]>>(7-uint(r.at&7))&1)
		r.at++
	}
	return v, true
}

func (r *bitReader) bit() (uint32, bool) { return r.read(1) }

// progSRL is the Simplified-RL decoder of an upgrade pass (3.1.8.1.5): runs of zeros as in RLGR,
// non-zero values in unary.
type progSRL struct {
	bits bitReader
	kp   int
	nz   int
	mode bool // the unary value is next
}

func (s *progSRL) read(numBits int) (int16, error) {
	if s.nz > 0 {
		s.nz--
		return 0, nil
	}
	k := s.kp / 8
	if !s.mode {
		bit, ok := s.bits.bit()
		if !ok {
			return 0, progRefused("Simplified-RL cut short")
		}
		if bit == 0 {
			// A run of 1 << k zeros, this one the first.
			s.nz = 1<<k - 1
			s.kp = min(s.kp+4, 80)
			return 0, nil
		}
		s.mode = true
		count, ok := s.bits.read(k)
		if !ok {
			return 0, progRefused("Simplified-RL cut short")
		}
		if count > 0 {
			s.nz = int(count) - 1
			return 0, nil
		}
	}
	s.mode = false
	sign, ok := s.bits.bit()
	if !ok {
		return 0, progRefused("Simplified-RL cut short")
	}
	s.kp = max(s.kp-6, 0)
	magnitude := 1
	if numBits > 1 {
		for limit := 1<<numBits - 1; magnitude < limit; magnitude++ {
			bit, ok := s.bits.bit()
			if !ok {
				return 0, progRefused("Simplified-RL cut short")
			}
			if bit == 1 {
				break
			}
		}
	}
	if sign == 1 {
		return int16(-magnitude), nil
	}
	return int16(magnitude), nil
}

// rlgr1Decode decodes the RLGR1 stream of one component into out, its 4,096 coefficients
// (MS-RDPRFX 3.1.8.1.7.1; FreeRDP's rfx_rlgr_decode): adaptive run-length of zeros and Golomb-Rice
// codes, the parameters kp and krp from 8, steps 4, 6 and 3, bounded at 80. A stream that ends
// before 4,096 coefficients leaves zeros; what would go past them is dropped; an empty one is
// refused, as FreeRDP does.
func rlgr1Decode(data []byte, out []int16) error {
	if len(data) == 0 {
		return progRefused("an empty RLGR1 stream")
	}
	const kpMax, lsgr, upGR, dnGR, uqGR, dqGR = 80, 3, 4, 6, 3, 3
	bits := bitReader{data: data}
	remaining := func() int { return len(data)*8 - bits.at }
	k, kp, kr, krp := 1, 1<<lsgr, 1, 1<<lsgr
	n := 0
	countRun := func(want uint32) (int, bool) { // bits equal to want, then consumes the other one
		count := 0
		for {
			b, ok := bits.bit()
			if !ok {
				return 0, false
			}
			if b != want {
				return count, true
			}
			count++
		}
	}
	readGR := func() (int, bool) {
		vk, ok := countRun(1)
		if !ok || remaining() < kr {
			return 0, false
		}
		rest, _ := bits.read(kr)
		code := int(uint16(int(rest) | vk<<kr))
		switch {
		case vk == 0:
			krp = max(krp-2, 0)
		case vk != 1:
			krp = min(krp+vk, kpMax)
		}
		kr = krp >> lsgr
		return code, true
	}
	for remaining() > 0 && n < len(out) {
		if k > 0 {
			// Run-length mode: zeros, each adding 1 << k, then k bits, a sign, then a code.
			vk, ok := countRun(0)
			if !ok {
				break
			}
			run := 0
			for range vk {
				run += 1 << k
				kp = min(kp+upGR, kpMax)
				k = kp >> lsgr
			}
			if remaining() < k {
				break
			}
			rest, _ := bits.read(k)
			run += int(rest)
			sign, ok := bits.bit()
			if !ok {
				break
			}
			code, ok := readGR()
			if !ok {
				break
			}
			kp = max(kp-dnGR, 0)
			k = kp >> lsgr
			magnitude := int16(code + 1)
			if sign == 1 {
				magnitude = -magnitude
			}
			run = min(run, len(out)-n) // a run past the end is cut there, as FreeRDP does
			for range run {
				out[n] = 0
				n++
			}
			if n < len(out) {
				out[n] = magnitude
				n++
			}
			continue
		}
		// Golomb-Rice mode.
		code, ok := readGR()
		if !ok {
			break
		}
		var magnitude int16
		if code == 0 {
			kp = min(kp+uqGR, kpMax)
		} else {
			kp = max(kp-dqGR, 0)
			if code&1 == 1 {
				magnitude = -int16((code + 1) >> 1)
			} else {
				magnitude = int16(code >> 1)
			}
		}
		k = kp >> lsgr
		out[n] = magnitude
		n++
	}
	for ; n < len(out); n++ {
		out[n] = 0
	}
	return nil
}

func clampInt16(v int) int16 {
	return int16(max(-32768, min(32767, v)))
}

// progIDWT is the inverse transform of one level in one direction (FreeRDP's progressive_rfx_idwt_x
// and _y, the same but for their steps): count lines of nLow low and nHigh high coefficients into
// lines of nLow + nHigh.
func progIDWT(low []int16, lowStep, lowStride int, high []int16, highStep, highStride int, dst []int16, dstStep, dstStride int, nLow, nHigh, count int) {
	for i := range count {
		l, h, x := i*lowStride, i*highStride, i*dstStride
		at := func(buf []int16, base, step, j int) int { return int(buf[base+j*step]) }
		h0 := at(high, h, highStep, 0)
		l0 := at(low, l, lowStep, 0)
		x0 := int(clampInt16(l0 - h0))
		x2 := x0
		li, hi, xi := 1, 1, 0
		put := func(v int) { dst[x+xi*dstStep] = int16(v); xi++ }
		for range nHigh - 1 {
			h1 := at(high, h, highStep, hi)
			hi++
			l0 = at(low, l, lowStep, li)
			li++
			x2 = int(clampInt16(l0 - (h0+h1)/2))
			x1 := int(clampInt16((x0+x2)/2 + 2*h0))
			put(x0)
			put(x1)
			x0, h0 = x2, h1
		}
		switch {
		case nLow <= nHigh:
			put(x2)
			put(int(clampInt16(x2 + 2*h0)))
		case nLow == nHigh+1:
			l0 = at(low, l, lowStep, li)
			x0 = int(clampInt16(l0 - h0))
			put(x2)
			put(int(clampInt16((x0+x2)/2 + 2*h0)))
			put(x0)
		default:
			l0 = at(low, l, lowStep, li)
			li++
			x0 = int(clampInt16(l0 - h0/2))
			put(x2)
			put(int(clampInt16((x0+x2)/2 + 2*h0)))
			put(x0)
			l0 = at(low, l, lowStep, li)
			put(int(clampInt16((x0 + l0) / 2)))
		}
	}
}

// progIDWTLevel inverts one level of the Reduce-Extrapolate DWT on block (FreeRDP's
// progressive_rfx_dwt_2d_decode_block): HL, LH, HH then LL, into an image of nL + nH square at the
// block's start.
func progIDWTLevel(block []int16, level int) {
	nL := progTileSize>>level + 1
	nH := (progTileSize + 1<<(level-1)) >> level
	if level == 1 {
		nH = progTileSize/2 - 1
	}
	hl := block[0:]
	lh := block[nH*nL:]
	hh := block[2*nH*nL:]
	ll := block[2*nH*nL+nH*nH:]
	stride := nL + nH
	temp := make([]int16, stride*stride)
	lo, hiBuf := temp[:nL*stride], temp[nL*stride:]
	// Horizontal: LL and HL into L (nL rows), LH and HH into H (nH rows).
	progIDWT(ll, 1, nL, hl, 1, nH, lo, 1, stride, nL, nH, nL)
	progIDWT(lh, 1, nL, hh, 1, nH, hiBuf, 1, stride, nL, nH, nH)
	// Vertical: L and H into the block, column by column.
	out := make([]int16, stride*stride)
	progIDWT(lo, stride, 1, hiBuf, stride, 1, out, stride, 1, nL, nH, stride)
	copy(block, out)
}

// toPixels runs the inverse DWT of each component on a copy of its coefficients, then converts
// YCbCr to BGR with FreeRDP's fixed point (general_yCbCrToRGB_16s8u_P3AC4R).
func (t *progTile) toPixels() {
	var planes [3][progCoefficients]int16
	for c := range 3 {
		planes[c] = t.components[c].current
		if t.extrapolate {
			progIDWTLevel(planes[c][3807:], 3)
			progIDWTLevel(planes[c][3007:], 2)
			progIDWTLevel(planes[c][0:], 1)
			continue
		}
		rfxIDWTLevel(planes[c][3840:], 8)
		rfxIDWTLevel(planes[c][3072:], 16)
		rfxIDWTLevel(planes[c][0:], 32)
	}
	clip := func(v int) byte { return byte(max(0, min(255, v))) }
	for i := range progCoefficients {
		y := (int(planes[0][i]) + 4096) << 16
		cb, cr := int(planes[1][i]), int(planes[2][i])
		r := ((cr*91916 + y) >> 16) >> 5
		g := ((y - cb*22527 - cr*46819) >> 16) >> 5
		b := ((cb*115992 + y) >> 16) >> 5
		t.pixels[3*i], t.pixels[3*i+1], t.pixels[3*i+2] = clip(b), clip(g), clip(r)
	}
}

// rfxIDWTLevel inverts one level of RemoteFX's original DWT (MS-RDPRFX 3.1.8.2.4; FreeRDP's
// rfx_dwt_2d_decode_block): four w x w sub-bands, HL, LH, HH then LL, into a 2w x 2w image at the
// block's start; mirroring at the edges.
func rfxIDWTLevel(block []int16, w int) {
	stride := 2 * w
	temp := make([]int, 2*w*stride)
	lo, hi := temp[:w*stride], temp[w*stride:]
	at := func(band, y, x int) int { return int(block[band*w*w+y*w+x]) }
	const hlBand, lhBand, hhBand, llBand = 0, 1, 2, 3
	// Horizontal: LL and HL into L, LH and HH into H, row by row.
	for y := range w {
		for _, pass := range [2]struct {
			dst       []int
			low, high int
		}{{lo, llBand, hlBand}, {hi, lhBand, hhBand}} {
			row := pass.dst[y*stride:]
			row[0] = at(pass.low, y, 0) - ((at(pass.high, y, 0) + at(pass.high, y, 0) + 1) >> 1)
			for n := 1; n < w; n++ {
				row[2*n] = at(pass.low, y, n) - ((at(pass.high, y, n-1) + at(pass.high, y, n) + 1) >> 1)
			}
			for n := 0; n < w-1; n++ {
				row[2*n+1] = at(pass.high, y, n)<<1 + (row[2*n]+row[2*n+2])>>1
			}
			row[2*w-1] = at(pass.high, y, w-1)<<1 + row[2*w-2]
		}
	}
	// Vertical: L and H into the block, column by column.
	out := make([]int16, stride*stride)
	dst := make([]int, stride)
	for x := range stride {
		l := func(n int) int { return lo[n*stride+x] }
		h := func(n int) int { return hi[n*stride+x] }
		dst[0] = l(0) - ((h(0)*2 + 1) >> 1)
		for n := 1; n < w; n++ {
			dst[2*n] = l(n) - ((h(n-1) + h(n) + 1) >> 1)
			dst[2*n-1] = h(n-1)<<1 + (dst[2*n-2]+dst[2*n])>>1
		}
		dst[2*w-1] = h(w-1)<<1 + (dst[2*w-2]*2)>>1
		for y, v := range dst {
			out[y*stride+x] = clampInt16(v)
		}
	}
	copy(block, out)
}

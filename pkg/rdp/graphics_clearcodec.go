package rdp

import (
	"encoding/binary"
	"fmt"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// ClearCodec (MS-RDPEGFX 2.2.4.1, 3.3.8.1), ADR-0101 increment 3: the lossless codec Windows draws
// most of its screen with (CI of PR #194). A bitmap is up to three layers drawn in order onto its
// rectangle of the surface: residual (runs of one colour), bands (columns of pixels, "V-bars", kept
// in two caches), and subcodecs (raw pixels, or RLEX: runs and suites of a small palette). A bitmap
// of 1024 pixels at most may be kept as a glyph and drawn again by its index. Pixels are blue,
// green, red; the surface's alpha is left as it is (3.3.5.1: "only the red, green, and blue channels
// SHOULD be copied").
//
// Where the spec says nothing, this follows FreeRDP's reading, each marked here: a suite of RLEX
// runs from its start index to its stop index included; a palette of one colour has one-bit
// indexes; the short V-bar cursor wraps at 16,384 as the V-bar cursor does at 32,768. A wrong
// reading shows on the screen of the CI's Windows, or breaks the exact count of pixels each layer
// must fill. The NSCodec subcodec (0x01) is not decoded: it is refused by name (ErrRDPGraphicsCodec).

const (
	clearFlagGlyphIndex = byte(0x01)
	clearFlagGlyphHit   = byte(0x02)
	clearFlagCacheReset = byte(0x04)

	clearGlyphSlots     = 4000
	clearGlyphMaxPixels = 1024
	clearVBarSlots      = 32768
	clearShortVBarSlots = 16384
	clearMaxBandHeight  = 52

	clearSubcodecRaw  = byte(0x00)
	clearSubcodecNSC  = byte(0x01)
	clearSubcodecRLEX = byte(0x02)
)

type clearGlyph struct {
	width, height int
	bgr           []byte
}

// clearCodec is the decoder state of one graphics channel: the sequence, the glyphs and the V-bars.
type clearCodec struct {
	started     bool
	seq         byte
	glyphs      [clearGlyphSlots]*clearGlyph
	vBars       [clearVBarSlots][]byte // BGR, top to bottom, one band's height
	shortVBars  [clearShortVBarSlots][]byte
	vCursor     int
	shortCursor int
}

// clearTarget is where a bitmap is drawn: a w x h rectangle of a surface at (x, y).
type clearTarget struct {
	s    *graphicsSurface
	x, y int
	w, h int
}

func (t clearTarget) set(px, py int, b, g, r byte) {
	i := ((t.y+py)*t.s.width + t.x + px) * 4
	t.s.pix[i], t.s.pix[i+1], t.s.pix[i+2] = r, g, b
}

func clearRefused(format string, args ...any) error {
	return fmt.Errorf("%w: ClearCodec: "+format, append([]any{ErrRDPGraphics}, args...)...)
}

// clearRunLength reads runLengthFactor1, then 2, then 3 (2.2.4.1.1.1.1): one byte under 255, else a
// uint16 under 65,535, else a uint32. positive says each factor used must be above zero.
func clearRunLength(b []byte, positive bool) (int, []byte, error) {
	if len(b) < 1 {
		return 0, nil, clearRefused("a run length cut short")
	}
	n, b := uint32(b[0]), b[1:]
	if n == 0xff {
		if len(b) < 2 {
			return 0, nil, clearRefused("a run length cut short")
		}
		n, b = uint32(binary.LittleEndian.Uint16(b)), b[2:]
		if n == 0xffff {
			if len(b) < 4 {
				return 0, nil, clearRefused("a run length cut short")
			}
			n, b = binary.LittleEndian.Uint32(b), b[4:]
		}
	}
	if positive && n == 0 {
		return 0, nil, clearRefused("a run of length 0")
	}
	if n > uint32(screenstream.MaxPixels) {
		return 0, nil, clearRefused("a run of %d pixels", n)
	}
	return int(n), b, nil
}

// decode draws one CLEARCODEC_BITMAP_STREAM onto t.
func (c *clearCodec) decode(data []byte, t clearTarget) error {
	if len(data) < 2 {
		return clearRefused("a %d-byte stream", len(data))
	}
	flags, seq := data[0], data[1]
	if flags&^(clearFlagGlyphIndex|clearFlagGlyphHit|clearFlagCacheReset) != 0 {
		return clearRefused("flags 0x%02x", flags)
	}
	// The sequence starts at 0 and goes up by one, wrapping after 0xFF (2.2.4.1).
	if (!c.started && seq != 0) || (c.started && seq != c.seq+1) {
		return clearRefused("sequence %d after %d", seq, c.seq)
	}
	c.started, c.seq = true, seq
	data = data[2:]
	if flags&clearFlagCacheReset != 0 {
		c.vCursor, c.shortCursor = 0, 0
	}
	glyph := -1
	if flags&clearFlagGlyphIndex != 0 {
		if len(data) < 2 || t.w*t.h > clearGlyphMaxPixels {
			return clearRefused("a glyph of %d x %d", t.w, t.h)
		}
		glyph = int(binary.LittleEndian.Uint16(data))
		data = data[2:]
		if glyph >= clearGlyphSlots {
			return clearRefused("glyph %d", glyph)
		}
	} else if flags&clearFlagGlyphHit != 0 {
		return clearRefused("a glyph hit without an index")
	}
	if flags&clearFlagGlyphHit != 0 {
		g := c.glyphs[glyph]
		if len(data) != 0 || g == nil || g.width != t.w || g.height != t.h {
			return clearRefused("glyph %d hit: %d byte(s) after it, a %d x %d target", glyph, len(data), t.w, t.h)
		}
		for i := range t.w * t.h {
			t.set(i%t.w, i/t.w, g.bgr[3*i], g.bgr[3*i+1], g.bgr[3*i+2])
		}
		return nil
	}
	if len(data) > 0 {
		if err := c.composite(data, t); err != nil {
			return err
		}
	}
	if glyph >= 0 {
		g := &clearGlyph{width: t.w, height: t.h, bgr: make([]byte, 0, 3*t.w*t.h)}
		for py := range t.h {
			for px := range t.w {
				i := ((t.y+py)*t.s.width + t.x + px) * 4
				g.bgr = append(g.bgr, t.s.pix[i+2], t.s.pix[i+1], t.s.pix[i])
			}
		}
		c.glyphs[glyph] = g
	}
	return nil
}

// composite reads the CLEARCODEC_COMPOSITE_PAYLOAD (2.2.4.1.1): three counts that are the rest.
func (c *clearCodec) composite(data []byte, t clearTarget) error {
	if len(data) < 12 {
		return clearRefused("a composite payload of %d bytes", len(data))
	}
	residual := uint64(binary.LittleEndian.Uint32(data[0:4]))
	bands := uint64(binary.LittleEndian.Uint32(data[4:8]))
	subcodecs := uint64(binary.LittleEndian.Uint32(data[8:12]))
	data = data[12:]
	if residual+bands+subcodecs != uint64(len(data)) {
		return clearRefused("layers of %d, %d and %d bytes in %d", residual, bands, subcodecs, len(data))
	}
	if err := clearResidual(data[:residual], t); err != nil {
		return err
	}
	if err := c.bands(data[residual:residual+bands], t); err != nil {
		return err
	}
	return clearSubcodecs(data[residual+bands:residual+bands+subcodecs], t)
}

// clearResidual draws the first layer (2.2.4.1.1.1): runs of one colour, left to right then top to
// bottom, no more than the bitmap holds.
func clearResidual(data []byte, t clearTarget) error {
	at, total := 0, t.w*t.h
	for len(data) > 0 {
		if len(data) < 4 {
			return clearRefused("a residual run cut short")
		}
		b, g, r := data[0], data[1], data[2]
		n, rest, err := clearRunLength(data[3:], true)
		if err != nil {
			return err
		}
		data = rest
		if n > total-at {
			return clearRefused("residual runs past the %d pixels", total)
		}
		for range n {
			t.set(at%t.w, at/t.w, b, g, r)
			at++
		}
	}
	return nil
}

// bands draws the second layer (2.2.4.1.1.2): bands of V-bars, each from a cache or built.
func (c *clearCodec) bands(data []byte, t clearTarget) error {
	for len(data) > 0 {
		if len(data) < 11 {
			return clearRefused("a band cut short")
		}
		xStart, xEnd := int(binary.LittleEndian.Uint16(data[0:2])), int(binary.LittleEndian.Uint16(data[2:4]))
		yStart, yEnd := int(binary.LittleEndian.Uint16(data[4:6])), int(binary.LittleEndian.Uint16(data[6:8]))
		bkg := [3]byte{data[8], data[9], data[10]}
		data = data[11:]
		height := yEnd - yStart + 1
		if xEnd < xStart || yEnd < yStart || xEnd >= t.w || yEnd >= t.h || height > clearMaxBandHeight {
			return clearRefused("a band of (%d, %d)-(%d, %d) in %d x %d", xStart, yStart, xEnd, yEnd, t.w, t.h)
		}
		for x := xStart; x <= xEnd; x++ {
			if len(data) < 2 {
				return clearRefused("a V-bar cut short")
			}
			header := binary.LittleEndian.Uint16(data)
			data = data[2:]
			var vBar []byte
			switch {
			case header&0x8000 != 0: // VBAR_CACHE_HIT: 15 bits of index
				vBar = c.vBars[header&0x7fff]
				if len(vBar) != 3*height {
					return clearRefused("V-bar %d of %d bytes for a band of %d", header&0x7fff, len(vBar), height)
				}
			case header&0x4000 != 0: // SHORT_VBAR_CACHE_HIT: 14 bits of index, then yOn
				if len(data) < 1 {
					return clearRefused("a short V-bar hit cut short")
				}
				short, yOn := c.shortVBars[header&0x3fff], int(data[0])
				data = data[1:]
				if short == nil {
					return clearRefused("short V-bar %d is empty", header&0x3fff)
				}
				var err error
				if vBar, err = c.buildVBar(short, yOn, height, bkg); err != nil {
					return err
				}
			default: // SHORT_VBAR_CACHE_MISS: yOn (8 bits), yOff (6 bits), then the pixels
				yOn, yOff := int(header&0xff), int(header>>8&0x3f)
				if yOff < yOn || len(data) < 3*(yOff-yOn) {
					return clearRefused("a short V-bar of %d to %d, %d byte(s) left", yOn, yOff, len(data))
				}
				// A short V-bar of no pixel is one (yOn == yOff), cached as any other: never nil,
				// which says an empty slot (CI of PR #197: Windows sends them, then hits them).
				short := make([]byte, 3*(yOff-yOn))
				copy(short, data)
				data = data[3*(yOff-yOn):]
				c.shortVBars[c.shortCursor] = short
				c.shortCursor = (c.shortCursor + 1) % clearShortVBarSlots // FreeRDP's reading
				var err error
				if vBar, err = c.buildVBar(short, yOn, height, bkg); err != nil {
					return err
				}
			}
			for y := range height {
				t.set(x, yStart+y, vBar[3*y], vBar[3*y+1], vBar[3*y+2])
			}
		}
	}
	return nil
}

// buildVBar makes a V-bar of height from a short one at yOn, the background around it, and stores
// it at the V-bar cursor (2.2.4.1.1.2.1.1.2, .3).
func (c *clearCodec) buildVBar(short []byte, yOn, height int, bkg [3]byte) ([]byte, error) {
	count := len(short) / 3
	if yOn+count > height {
		return nil, clearRefused("a short V-bar of %d at %d in a band of %d", count, yOn, height)
	}
	vBar := make([]byte, 3*height)
	for y := range height {
		if y >= yOn && y < yOn+count {
			copy(vBar[3*y:3*y+3], short[3*(y-yOn):])
		} else {
			copy(vBar[3*y:3*y+3], bkg[:])
		}
	}
	c.vBars[c.vCursor] = vBar
	c.vCursor = (c.vCursor + 1) % clearVBarSlots
	return vBar, nil
}

// clearSubcodecs draws the third layer (2.2.4.1.1.3): rectangles of raw pixels or RLEX.
func clearSubcodecs(data []byte, t clearTarget) error {
	for len(data) > 0 {
		if len(data) < 13 {
			return clearRefused("a subcodec cut short")
		}
		x, y := int(binary.LittleEndian.Uint16(data[0:2])), int(binary.LittleEndian.Uint16(data[2:4]))
		w, h := int(binary.LittleEndian.Uint16(data[4:6])), int(binary.LittleEndian.Uint16(data[6:8]))
		n := uint64(binary.LittleEndian.Uint32(data[8:12]))
		id := data[12]
		data = data[13:]
		if w == 0 || h == 0 || x+w > t.w || y+h > t.h || n > uint64(3*w*h) || n > uint64(len(data)) {
			return clearRefused("a subcodec of %d x %d at (%d, %d), %d bytes, in %d x %d", w, h, x, y, n, t.w, t.h)
		}
		sub := clearTarget{s: t.s, x: t.x + x, y: t.y + y, w: w, h: h}
		body := data[:n]
		data = data[n:]
		switch id {
		case clearSubcodecRaw:
			if n != uint64(3*w*h) {
				return clearRefused("raw pixels of %d bytes for %d x %d", n, w, h)
			}
			for i := range w * h {
				sub.set(i%w, i/w, body[3*i], body[3*i+1], body[3*i+2])
			}
		case clearSubcodecRLEX:
			if err := clearRLEX(body, sub); err != nil {
				return err
			}
		case clearSubcodecNSC:
			return fmt.Errorf("%w: ClearCodec's NSCodec subcodec", ErrRDPGraphicsCodec)
		default:
			return clearRefused("subcodec 0x%02x", id)
		}
	}
	return nil
}

// clearRLEX draws a CLEARCODEC_SUBCODEC_RLEX (2.2.4.1.1.3.1.1): a palette, then segments, each a run
// of its start colour and a suite from its start index to its stop index; exactly w x h pixels.
func clearRLEX(data []byte, t clearTarget) error {
	if len(data) < 1 || data[0] == 0 || data[0] > 0x7f || len(data) < 1+3*int(data[0]) {
		return clearRefused("an RLEX palette")
	}
	count := int(data[0])
	palette := data[1 : 1+3*count]
	data = data[1+3*count:]
	// floor(log2(count - 1)) + 1 bits; one for a palette of one colour (FreeRDP's reading).
	bits := 1
	for 1<<bits < count {
		bits++
	}
	at, total := 0, t.w*t.h
	put := func(index int) {
		t.set(at%t.w, at/t.w, palette[3*index], palette[3*index+1], palette[3*index+2])
		at++
	}
	for len(data) > 0 {
		stop, depth := int(data[0])&(1<<bits-1), int(data[0])>>bits
		n, rest, err := clearRunLength(data[1:], false)
		if err != nil {
			return err
		}
		data = rest
		start := stop - depth
		if stop >= count || start < 0 || n+depth+1 > total-at {
			return clearRefused("an RLEX segment of stop %d, depth %d, run %d at pixel %d of %d", stop, depth, n, at, total)
		}
		for range n {
			put(start)
		}
		for index := start; index <= stop; index++ {
			put(index)
		}
	}
	if at != total {
		return clearRefused("RLEX of %d pixels for %d", at, total)
	}
	return nil
}

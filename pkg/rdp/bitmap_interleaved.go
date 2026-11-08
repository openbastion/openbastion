package rdp

import "encoding/binary"

// Interleaved RLE (MS-RDPBCGR 2.2.9.1.1.3.1.2.4, decoding in 3.1.9) at 15 and 16 bpp: the
// compression Windows uses for a session it caps at 16 bpp (ADR-0086). Written from the
// specification alone (ADR-0081). Every order is bounded before it writes: the output has exactly
// the size the bitmap announces, and a stream that overruns it, stops short of it, or reads past
// its own end is refused.

const (
	rleRegularBGRun         = byte(0x00)
	rleRegularFGRun         = byte(0x01)
	rleRegularFGBGImage     = byte(0x02)
	rleRegularColorRun      = byte(0x03)
	rleRegularColorImage    = byte(0x04)
	rleLiteSetFGFGRun       = byte(0x0c)
	rleLiteSetFGFGBGImage   = byte(0x0d)
	rleLiteDitheredRun      = byte(0x0e)
	rleMegaMegaBGRun        = byte(0xf0)
	rleMegaMegaFGRun        = byte(0xf1)
	rleMegaMegaFGBGImage    = byte(0xf2)
	rleMegaMegaColorRun     = byte(0xf3)
	rleMegaMegaColorImage   = byte(0xf4)
	rleMegaMegaSetFGRun     = byte(0xf6)
	rleMegaMegaSetFGBGImage = byte(0xf7)
	rleMegaMegaDitheredRun  = byte(0xf8)
	rleSpecialFGBG1         = byte(0xf9)
	rleSpecialFGBG2         = byte(0xfa)
	rleWhite                = byte(0xfd)
	rleBlack                = byte(0xfe)

	rleMaskSpecialFGBG1 = byte(0x03)
	rleMaskSpecialFGBG2 = byte(0x05)
)

// rleCode returns the order code of an order header byte, or false when it names none.
func rleCode(header byte) (byte, bool) {
	switch header {
	case rleMegaMegaBGRun, rleMegaMegaFGRun, rleMegaMegaFGBGImage, rleMegaMegaColorRun, rleMegaMegaColorImage,
		rleMegaMegaSetFGRun, rleMegaMegaSetFGBGImage, rleMegaMegaDitheredRun, rleSpecialFGBG1, rleSpecialFGBG2,
		rleWhite, rleBlack:
		return header, true
	}
	if code := header >> 5; code <= rleRegularColorImage {
		return code, true
	}
	switch code := header >> 4; code {
	case rleLiteSetFGFGRun, rleLiteSetFGFGBGImage, rleLiteDitheredRun:
		return code, true
	}
	return 0, false
}

// rleRunLength returns the run length of an order and how many bytes its header takes.
func rleRunLength(code byte, src []byte) (int, int, bool) {
	header := src[0]
	switch code {
	case rleRegularFGBGImage, rleLiteSetFGFGBGImage:
		mask := byte(0x1f)
		if code == rleLiteSetFGFGBGImage {
			mask = 0x0f
		}
		if n := int(header & mask); n != 0 {
			return n * 8, 1, true
		}
		if len(src) < 2 {
			return 0, 0, false
		}
		return int(src[1]) + 1, 2, true
	case rleRegularBGRun, rleRegularFGRun, rleRegularColorRun, rleRegularColorImage:
		if n := int(header & 0x1f); n != 0 {
			return n, 1, true
		}
		if len(src) < 2 {
			return 0, 0, false
		}
		return int(src[1]) + 32, 2, true
	case rleLiteSetFGFGRun, rleLiteDitheredRun:
		if n := int(header & 0x0f); n != 0 {
			return n, 1, true
		}
		if len(src) < 2 {
			return 0, 0, false
		}
		return int(src[1]) + 16, 2, true
	case rleMegaMegaBGRun, rleMegaMegaFGRun, rleMegaMegaFGBGImage, rleMegaMegaColorRun, rleMegaMegaColorImage,
		rleMegaMegaSetFGRun, rleMegaMegaSetFGBGImage, rleMegaMegaDitheredRun:
		if len(src) < 3 {
			return 0, 0, false
		}
		return int(binary.LittleEndian.Uint16(src[1:3])), 3, true
	}
	return 0, 1, true // special orders, white and black: no run length
}

// decodeInterleavedRLE16 decodes a 15- or 16-bpp Interleaved RLE stream into width*height pixels,
// in the stream's own row order (bottom-up, as the bitmap is sent).
func decodeInterleavedRLE16(src []byte, width, height int, bpp uint16) ([]uint16, error) {
	if width <= 0 || height <= 0 || (bpp != 15 && bpp != 16) || len(src) == 0 ||
		uint64(width)*uint64(height) > maxRDPDesktopArea {
		return nil, ErrMCSConnection
	}
	white := uint16(0xffff)
	if bpp == 15 {
		white = 0x7fff
	}
	out := make([]uint16, width*height)
	d := 0
	fg := white
	insertFG := false
	firstLine := true
	put := func(pixel uint16) bool {
		if d >= len(out) {
			return false
		}
		out[d] = pixel
		d++
		return true
	}
	above := func() uint16 { return out[d-width] } // only called past the first line
	pixel := func() (uint16, bool) {
		if len(src) < 2 {
			return 0, false
		}
		p := binary.LittleEndian.Uint16(src[:2])
		src = src[2:]
		return p, true
	}
	fgbg := func(mask byte, bits int) bool {
		for i := 0; i < bits; i++ {
			set := mask&(1<<i) != 0
			var p uint16
			switch {
			case firstLine && set:
				p = fg
			case firstLine:
				p = 0
			case set:
				p = above() ^ fg
			default:
				p = above()
			}
			if !put(p) {
				return false
			}
		}
		return true
	}

	for len(src) > 0 {
		if firstLine && d >= width {
			firstLine, insertFG = false, false
		}
		code, ok := rleCode(src[0])
		if !ok {
			return nil, ErrMCSConnection
		}
		run, advance, ok := rleRunLength(code, src)
		if !ok {
			return nil, ErrMCSConnection
		}
		// A run never asks for more pixels than remain: checked once, before the order writes.
		need := run
		if code == rleLiteDitheredRun || code == rleMegaMegaDitheredRun {
			need = run * 2
		}
		if need > len(out)-d {
			return nil, ErrMCSConnection
		}
		src = src[advance:]

		if code == rleRegularBGRun || code == rleMegaMegaBGRun {
			if insertFG && run > 0 {
				if firstLine {
					put(fg)
				} else {
					put(above() ^ fg)
				}
				run--
			}
			for ; run > 0; run-- {
				if firstLine {
					put(0)
				} else {
					put(above())
				}
			}
			// A background run that follows another needs a foreground pixel between them.
			insertFG = true
			continue
		}
		insertFG = false

		switch code {
		case rleRegularFGRun, rleMegaMegaFGRun, rleLiteSetFGFGRun, rleMegaMegaSetFGRun:
			if code == rleLiteSetFGFGRun || code == rleMegaMegaSetFGRun {
				if fg, ok = pixel(); !ok {
					return nil, ErrMCSConnection
				}
			}
			for ; run > 0; run-- {
				if firstLine {
					put(fg)
				} else {
					put(above() ^ fg)
				}
			}
		case rleLiteDitheredRun, rleMegaMegaDitheredRun:
			a, okA := pixel()
			b, okB := pixel()
			if !okA || !okB {
				return nil, ErrMCSConnection
			}
			for ; run > 0; run-- {
				put(a)
				put(b)
			}
		case rleRegularColorRun, rleMegaMegaColorRun:
			c, ok := pixel()
			if !ok {
				return nil, ErrMCSConnection
			}
			for ; run > 0; run-- {
				put(c)
			}
		case rleRegularFGBGImage, rleMegaMegaFGBGImage, rleLiteSetFGFGBGImage, rleMegaMegaSetFGBGImage:
			if code == rleLiteSetFGFGBGImage || code == rleMegaMegaSetFGBGImage {
				if fg, ok = pixel(); !ok {
					return nil, ErrMCSConnection
				}
			}
			for run > 0 {
				if len(src) == 0 {
					return nil, ErrMCSConnection
				}
				bits := min(run, 8)
				mask := src[0]
				src = src[1:]
				if !fgbg(mask, bits) {
					return nil, ErrMCSConnection
				}
				run -= bits
			}
		case rleRegularColorImage, rleMegaMegaColorImage:
			if len(src) < run*2 {
				return nil, ErrMCSConnection
			}
			for ; run > 0; run-- {
				c, _ := pixel()
				put(c)
			}
		case rleSpecialFGBG1, rleSpecialFGBG2:
			mask := rleMaskSpecialFGBG1
			if code == rleSpecialFGBG2 {
				mask = rleMaskSpecialFGBG2
			}
			if len(out)-d < 8 || !fgbg(mask, 8) {
				return nil, ErrMCSConnection
			}
		case rleWhite, rleBlack:
			p := white
			if code == rleBlack {
				p = 0
			}
			if !put(p) {
				return nil, ErrMCSConnection
			}
		default:
			return nil, ErrMCSConnection
		}
	}
	if d != len(out) {
		return nil, ErrMCSConnection
	}
	return out, nil
}

// rgbaFrom16 converts one 15- or 16-bpp pixel to RGBA, widening each channel by bit replication.
func rgbaFrom16(p uint16, bpp uint16) (r, g, b byte) {
	if bpp == 15 {
		r5, g5, b5 := byte(p>>10)&0x1f, byte(p>>5)&0x1f, byte(p)&0x1f
		return r5<<3 | r5>>2, g5<<3 | g5>>2, b5<<3 | b5>>2
	}
	r5, g6, b5 := byte(p>>11)&0x1f, byte(p>>5)&0x3f, byte(p)&0x1f
	return r5<<3 | r5>>2, g6<<2 | g6>>4, b5<<3 | b5>>2
}

// rgbaFromBottomUp16 turns bottom-up 15/16-bpp pixels into top-down RGBA.
func rgbaFromBottomUp16(pixels []uint16, width, height int, bpp uint16) []byte {
	dst := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		src := pixels[(height-1-y)*width : (height-y)*width]
		row := dst[y*width*4 : (y+1)*width*4]
		for x, p := range src {
			r, g, b := rgbaFrom16(p, bpp)
			row[x*4], row[x*4+1], row[x*4+2], row[x*4+3] = r, g, b, 0xff
		}
	}
	return dst
}

// decodeRDPBitmapRaw16 reads an uncompressed 15/16-bpp bitmap: bottom-up rows of little-endian
// pixels, each row padded to four bytes (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
func decodeRDPBitmapRaw16(src []byte, width, height int, bpp uint16) ([]byte, error) {
	rowBytes := (width*2 + 3) &^ 3
	if width <= 0 || height <= 0 || len(src) != rowBytes*height {
		return nil, ErrMCSConnection
	}
	pixels := make([]uint16, width*height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixels[y*width+x] = binary.LittleEndian.Uint16(src[y*rowBytes+x*2:])
		}
	}
	return rgbaFromBottomUp16(pixels, width, height, bpp), nil
}

// decodeRDPBitmapRLE16 decodes a compressed 15/16-bpp bitmap, with or without TS_CD_HEADER.
func decodeRDPBitmapRLE16(data []byte, width, height int, bpp uint16, header bool) ([]byte, error) {
	// cbScanWidth "MUST be divisible by 4": a compressed 15/16-bpp row is an even number of pixels.
	if width <= 0 || width%2 != 0 {
		return nil, ErrMCSConnection
	}
	if header {
		// TS_CD_HEADER: cbCompFirstRowSize 0, cbCompMainBodySize, cbScanWidth, cbUncompressedSize.
		rowBytes := (width*2 + 3) &^ 3
		if len(data) < 9 || binary.LittleEndian.Uint16(data[0:2]) != 0 ||
			int(binary.LittleEndian.Uint16(data[2:4])) != len(data)-8 ||
			int(binary.LittleEndian.Uint16(data[4:6])) != rowBytes ||
			int(binary.LittleEndian.Uint16(data[6:8])) != rowBytes*height {
			return nil, ErrMCSConnection
		}
		data = data[8:]
	}
	pixels, err := decodeInterleavedRLE16(data, width, height, bpp)
	if err != nil {
		return nil, err
	}
	return rgbaFromBottomUp16(pixels, width, height, bpp), nil
}

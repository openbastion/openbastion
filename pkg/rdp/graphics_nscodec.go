package rdp

import (
	"encoding/binary"
	"fmt"
)

// NSCodec (MS-RDPNSC), the subcodec 0x01 of ClearCodec, ADR-0101 increment 3b: the CI's Windows use it
// one to four times a session (CI of PR #197). Four planes, luma, orange chroma, green chroma and
// alpha, each raw or run-length encoded; the chroma reduced by ColorLossLevel bits and, with
// subsampling, kept at half resolution on padded planes. The colour transform is the one of RDP 6.0
// (MS-RDPEGDI 3.1.9.1.2, decodeRDP6AYCoCg), then red and blue swapped, as the spec says a decoder
// MUST ("Microsoft RDP servers incorrectly convert 24 bpp RGB bitmaps to the YCoCg color space"):
// without the swap, the blue wallpaper of the CI's Windows Server 2022 came out orange (CI of PR
// #198). The alpha plane is read and bounded, not drawn: ClearCodec draws red, green and blue.

const nscHeaderSize = 20

func nscRefused(format string, args ...any) error {
	return fmt.Errorf("%w: NSCodec: "+format, append([]any{ErrRDPGraphics}, args...)...)
}

// nscPlane returns a plane of size bytes from count bytes of data: raw when count is size, run-length
// encoded when smaller (MS-RDPNSC 2.2.2).
func nscPlane(data []byte, size int) ([]byte, error) {
	if len(data) == size {
		return data, nil
	}
	if len(data) > size {
		return nil, nscRefused("a plane of %d bytes for %d", len(data), size)
	}
	// NSCODEC_RLE_SEGMENTS (2.2.2.1): runs (a value, the same value again, a length) and literals,
	// up to the last four bytes, which follow raw (EndData).
	out := make([]byte, 0, size)
	in := data
	for len(out) < size-4 {
		if len(in) < 1 {
			return nil, nscRefused("a plane cut short")
		}
		value := in[0]
		in = in[1:]
		// The last byte before EndData is a literal: the next one is EndData's (FreeRDP's reading).
		if len(out) == size-5 || len(in) == 0 || in[0] != value {
			out = append(out, value)
			continue
		}
		if len(in) < 2 {
			return nil, nscRefused("a run cut short")
		}
		n := int(in[1]) + 2
		in = in[2:]
		if n == 0xff+2 {
			if len(in) < 4 {
				return nil, nscRefused("a run cut short")
			}
			n, in = int(binary.LittleEndian.Uint32(in)), in[4:]
		}
		if n > size-4-len(out) {
			return nil, nscRefused("a run of %d past the plane", n)
		}
		for range n {
			out = append(out, value)
		}
	}
	if len(in) != 4 {
		return nil, nscRefused("%d bytes of EndData", len(in))
	}
	return append(out, in...), nil
}

// decodeNSCodec decodes an NSCODEC_BITMAP_STREAM of w x h onto t.
func decodeNSCodec(data []byte, t clearTarget) error {
	if len(data) < nscHeaderSize {
		return nscRefused("a stream of %d bytes", len(data))
	}
	counts := [4]uint64{}
	for i := range counts {
		counts[i] = uint64(binary.LittleEndian.Uint32(data[4*i:]))
	}
	loss, subsampling := int(data[16]), data[17]
	if loss < 1 || loss > 7 || subsampling > 1 {
		return nscRefused("ColorLossLevel %d, ChromaSubsamplingLevel %d", loss, subsampling)
	}
	w, h := t.w, t.h
	lumaWidth, chromaWidth, chromaHeight := w, w, h
	if subsampling == 1 {
		lumaWidth = (w + 7) &^ 7
		chromaWidth, chromaHeight = lumaWidth/2, (h+1)/2
	}
	sizes := [4]int{lumaWidth * h, chromaWidth * chromaHeight, chromaWidth * chromaHeight, w * h}
	if counts[0] == 0 || counts[1] == 0 || counts[2] == 0 ||
		counts[0]+counts[1]+counts[2]+counts[3] != uint64(len(data)-nscHeaderSize) {
		return nscRefused("planes of %v bytes in %d", counts, len(data)-nscHeaderSize)
	}
	var planes [4][]byte
	at := nscHeaderSize
	for i, count := range counts {
		raw := data[at : at+int(count)]
		at += int(count)
		if i == 3 && count == 0 {
			break // no alpha plane
		}
		plane, err := nscPlane(raw, sizes[i])
		if err != nil {
			return err
		}
		planes[i] = plane
	}
	shift := 0
	if subsampling == 1 {
		shift = 1
	}
	for y := range h {
		for x := range w {
			chroma := (y>>shift)*chromaWidth + x>>shift
			r, g, b := decodeRDP6AYCoCg(planes[0][y*lumaWidth+x], planes[1][chroma], planes[2][chroma], loss)
			t.set(x, y, r, g, b) // red and blue swapped: t.set takes blue first
		}
	}
	return nil
}

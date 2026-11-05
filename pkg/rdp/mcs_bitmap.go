package rdp

import (
	"context"
	"encoding/binary"
	"time"
)

const (
	rdpPDU2Update       = byte(2)
	rdpUpdateBitmap     = uint16(1)
	rdpBitmapCompressed = uint16(0x0001)
	rdpBitmapNoCompHdr  = uint16(0x0400)
	maxRDPBitmapRects   = 64
	// Keep each fragment below the conservative MCS/TPKT bound. A complete
	// Share Data PDU has a 16-bit totalLength, so reassembly cannot exceed it.
	maxRDPBitmapTPKTPacket      = 16_383
	maxRDPBitmapReassemblyBytes = int(^uint16(0))
	maxRDPBitmapFragments       = 5
)

// RDPBitmapRectangle is one decoded, top-down RGBA rectangle from a server
// Bitmap Update PDU. Pixels is tightly packed (four bytes per pixel).
type RDPBitmapRectangle struct {
	X      uint16
	Y      uint16
	Width  uint16
	Height uint16
	Pixels []byte
}

// RDPBitmapUpdate contains the rectangles from one complete Bitmap Update PDU.
type RDPBitmapUpdate struct {
	Rectangles []RDPBitmapRectangle
}

// parseRDPBitmapMCSFragment validates one TPKT/X.224/MCS envelope and returns
// its userData and the two-bit MCS segmentation value (begin=2, end=1).
func parseRDPBitmapMCSFragment(packet []byte, expectedChannelID uint16) ([]byte, byte, error) {
	if len(packet) < 7+7 || len(packet) > maxRDPBitmapTPKTPacket || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || !equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) ||
		expectedChannelID != mcsGlobalChannelID {
		return nil, 0, ErrMCSConnection
	}
	mcs := packet[7:]
	// Priority must remain HIGH and the four reserved padding bits must be 0.
	// Bits 5..4 carry the MCS begin/end segmentation flags.
	if mcs[0] != mcsSendDataIndication || binary.BigEndian.Uint16(mcs[1:3]) != rdpServerChannelID-mcsUserIDBase ||
		binary.BigEndian.Uint16(mcs[3:5]) != expectedChannelID || mcs[5]&0xcf != 0x40 {
		return nil, 0, ErrMCSConnection
	}
	length, userData, err := readPERLength(mcs[6:])
	if err != nil || length == 0 || length != len(userData) {
		return nil, 0, ErrMCSConnection
	}
	return userData, (mcs[5] >> 4) & 0x03, nil
}

// parseRDPBitmapShareData decodes one fully reassembled Share Data PDU.
func parseRDPBitmapShareData(userData []byte, shareID uint32, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	var result RDPBitmapUpdate
	if len(userData) < 18+4 || len(userData) > maxRDPBitmapReassemblyBytes || shareID == 0 ||
		desktopWidth == 0 || desktopHeight == 0 || uint64(desktopWidth)*uint64(desktopHeight) > maxRDPDesktopArea {
		return result, ErrMCSConnection
	}
	if int(binary.LittleEndian.Uint16(userData[0:2])) != len(userData) ||
		binary.LittleEndian.Uint16(userData[2:4]) != rdpShareDataPDU ||
		binary.LittleEndian.Uint16(userData[4:6]) != rdpServerChannelID ||
		binary.LittleEndian.Uint32(userData[6:10]) != shareID || userData[10] != 0 || userData[11] != 2 ||
		int(binary.LittleEndian.Uint16(userData[12:14])) != len(userData) || userData[14] != rdpPDU2Update ||
		userData[15] != 0 || binary.LittleEndian.Uint16(userData[16:18]) != 0 {
		return result, ErrMCSConnection
	}
	payload := userData[18:]
	if binary.LittleEndian.Uint16(payload[:2]) != rdpUpdateBitmap {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	count := int(binary.LittleEndian.Uint16(payload[2:4]))
	if count == 0 || count > maxRDPBitmapRects {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	payload = payload[4:]
	result.Rectangles = make([]RDPBitmapRectangle, 0, count)
	var totalPixels uint64
	for i := 0; i < count; i++ {
		if len(payload) < 18 {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		left := binary.LittleEndian.Uint16(payload[0:2])
		top := binary.LittleEndian.Uint16(payload[2:4])
		right := binary.LittleEndian.Uint16(payload[4:6])
		bottom := binary.LittleEndian.Uint16(payload[6:8])
		width := binary.LittleEndian.Uint16(payload[8:10])
		height := binary.LittleEndian.Uint16(payload[10:12])
		bpp := binary.LittleEndian.Uint16(payload[12:14])
		flags := binary.LittleEndian.Uint16(payload[14:16])
		bitmapLength := int(binary.LittleEndian.Uint16(payload[16:18]))
		payload = payload[18:]
		if width == 0 || height == 0 || bpp != 32 || (flags != 0 && flags != rdpBitmapCompressed) || bitmapLength == 0 || bitmapLength > len(payload) ||
			uint32(left)+uint32(width) > uint32(desktopWidth) || uint32(top)+uint32(height) > uint32(desktopHeight) ||
			right != left+width-1 || bottom != top+height-1 {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		pixels := uint64(width) * uint64(height)
		if pixels > maxRDPDesktopArea || totalPixels > maxRDPDesktopArea-pixels {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		totalPixels += pixels
		var decoded []byte
		if flags == 0 {
			if pixels*4 != uint64(bitmapLength) {
				return RDPBitmapUpdate{}, ErrMCSConnection
			}
			decoded = decodeRDPBitmapRaw(payload, int(width), int(height))
		} else {
			var decodeErr error
			decoded, decodeErr = decodeRDP6BitmapWithHeader(payload, int(width), int(height))
			if decodeErr != nil {
				return RDPBitmapUpdate{}, ErrMCSConnection
			}
		}
		result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{X: left, Y: top, Width: width, Height: height, Pixels: decoded})
		payload = payload[bitmapLength:]
	}
	if len(payload) != 0 {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	return result, nil
}

// decodeRDPBitmapRaw converts bottom-up BGRX wire pixels to top-down RGBA.
func decodeRDPBitmapRaw(src []byte, width, height int) []byte {
	rowBytes := width * 4 // 32-bpp rows are already DWORD aligned.
	dst := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		srcRow := (height - 1 - y) * rowBytes
		dstRow := y * rowBytes
		for x := 0; x < width; x++ {
			s, d := srcRow+x*4, dstRow+x*4
			dst[d], dst[d+1], dst[d+2], dst[d+3] = src[s+2], src[s+1], src[s], 0xff
		}
	}
	return dst
}

// decodeRDP6BitmapWithHeader validates TS_CD_HEADER and decodes the bounded
// RDP 6.0 ARGB profile: no color loss or chroma subsampling. Planes may be raw
// or independently scan-line RLE encoded. Plane bytes are ordered A (optional),
// R, G, B in bottom-up row order; output pixels are top-down RGBA.
func decodeRDP6BitmapWithHeader(data []byte, width, height int) ([]byte, error) {
	if width <= 0 || height <= 0 || width%4 != 0 || len(data) < 9 {
		return nil, ErrMCSConnection
	}
	pixels := uint64(width) * uint64(height)
	decodedBytes := pixels * 4
	if pixels > maxRDPDesktopArea || decodedBytes > uint64(^uint16(0)) ||
		binary.LittleEndian.Uint16(data[0:2]) != 0 ||
		int(binary.LittleEndian.Uint16(data[2:4])) != len(data)-8 ||
		int(binary.LittleEndian.Uint16(data[4:6])) != width ||
		uint64(binary.LittleEndian.Uint16(data[6:8])) != decodedBytes {
		return nil, ErrMCSConnection
	}
	stream := data[8:]
	format := stream[0]
	// CLL=0 (ARGB), CS=0, reserved=0. RLE and no-alpha are independent flags.
	if format&0xf3 != 0 {
		return nil, ErrMCSConnection
	}
	noAlpha := format&0x04 != 0
	rle := format&0x08 != 0
	planeCount := 4
	if noAlpha {
		planeCount = 3
	}
	planeBytes := int(pixels)
	planes := make([][]byte, planeCount)
	offset := 1
	for i := range planes {
		if rle {
			decoded, consumed, err := decodeRDP6RLEPlane(stream[offset:], width, height)
			if err != nil || consumed <= 0 || consumed > len(stream)-offset {
				return nil, ErrMCSConnection
			}
			planes[i] = decoded
			offset += consumed
			continue
		}
		if planeBytes > len(stream)-offset {
			return nil, ErrMCSConnection
		}
		planes[i] = stream[offset : offset+planeBytes]
		offset += planeBytes
	}
	// The uncompressed stream optionally carries one ignored alignment byte.
	// RLE streams end exactly after the final plane; arbitrary trailing bytes
	// would make the plane boundaries ambiguous.
	if (!rle && len(stream)-offset > 1) || (rle && offset != len(stream)) {
		return nil, ErrMCSConnection
	}
	decoded := make([]byte, int(decodedBytes))
	for i := 0; i < planeBytes; i++ {
		x, wireY := i%width, i/width
		dst := ((height-1-wireY)*width + x) * 4
		plane := 0
		if !noAlpha {
			decoded[dst+3] = planes[0][i]
			plane = 1
		} else {
			decoded[dst+3] = 0xff
		}
		decoded[dst], decoded[dst+1], decoded[dst+2] = planes[plane][i], planes[plane+1][i], planes[plane+2][i]
	}
	return decoded, nil
}

// decodeRDP6RLEPlane decodes one independently encoded ARGB color plane.
// Each scanline is a sequence of RAW/RUN segments. Rows after the first contain
// zig-zag encoded deltas from the preceding decoded row, with byte arithmetic.
// The returned consumed count lets the caller locate the next plane safely.
func decodeRDP6RLEPlane(src []byte, width, height int) ([]byte, int, error) {
	if width <= 0 || height <= 0 || uint64(width) > maxRDPDesktopArea/uint64(height) {
		return nil, 0, ErrMCSConnection
	}
	plane := make([]byte, width*height)
	offset := 0
	for y := 0; y < height; y++ {
		rowStart := y * width
		column := 0
		for column < width {
			if offset >= len(src) {
				return nil, 0, ErrMCSConnection
			}
			control := src[offset]
			offset++
			if control == 0 {
				return nil, 0, ErrMCSConnection
			}
			rawCount, runNibble := int(control>>4), int(control&0x0f)
			runCount := runNibble
			switch runNibble {
			case 1:
				runCount, rawCount = 16+rawCount, 0
			case 2:
				runCount, rawCount = 32+rawCount, 0
			}
			if rawCount > width-column || rawCount > len(src)-offset {
				return nil, 0, ErrMCSConnection
			}
			if rawCount > 0 {
				copy(plane[rowStart+column:rowStart+column+rawCount], src[offset:offset+rawCount])
				offset += rawCount
				column += rawCount
			}
			if runCount > width-column {
				return nil, 0, ErrMCSConnection
			}
			if runCount > 0 {
				var value byte
				if rawCount > 0 {
					value = plane[rowStart+column-1]
				}
				for n := 0; n < runCount; n++ {
					plane[rowStart+column+n] = value
				}
				column += runCount
			}
			if rawCount == 0 && runCount == 0 {
				return nil, 0, ErrMCSConnection
			}
		}
		if y == 0 {
			continue
		}
		previous := plane[rowStart-width : rowStart]
		current := plane[rowStart : rowStart+width]
		for x, encoded := range current {
			var delta int
			if encoded&1 != 0 {
				delta = -(int(encoded) + 1) / 2
			} else {
				delta = int(encoded) / 2
			}
			current[x] = byte(int(previous[x]) + delta)
		}
	}
	return plane, offset, nil
}

// parseRDPBitmapUpdate validates and decodes one unsegmented MCS bitmap PDU.
// The 32-bpp compressed path supports bounded RDP 6.0 ARGB planes in raw or
// scan-line RLE form; AYCoCg and chroma subsampling are rejected.
// Network callers use the reassembling ReadBitmapUpdate path below.
func parseRDPBitmapUpdate(packet []byte, expectedChannelID uint16, shareID uint32, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	userData, segmentation, err := parseRDPBitmapMCSFragment(packet, expectedChannelID)
	if err != nil || segmentation != 3 {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	return parseRDPBitmapShareData(userData, shareID, desktopWidth, desktopHeight)
}

// ReadBitmapUpdate reads and decodes one complete server Bitmap Update after
// connection finalization. It accepts a larger, but still protocol-bounded,
// TPKT than the handshake path. Any malformed or unexpected packet makes the
// stream terminal because its framing can no longer be trusted.
func (s *CredSSPClientSession) ReadBitmapUpdate(ctx context.Context, timeout time.Duration) (update RDPBitmapUpdate, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return update, ErrMCSConnection
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.mu.Lock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.connectionFinalized ||
		!s.capabilitiesExchanged || s.serverCapabilities.ShareID == 0 ||
		!s.transport.Conn.ConnectionState().HandshakeComplete {
		s.mu.Unlock()
		return update, ErrMCSConnection
	}
	conn := s.transport.Conn
	ioChannelID := s.mcsResponse.IOChannelID
	shareID := s.serverCapabilities.ShareID
	desktopWidth, desktopHeight := s.serverCapabilities.DesktopWidth, s.serverCapabilities.DesktopHeight
	s.mu.Unlock()
	if timeout == 0 {
		timeout = defaultCredSSPTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		s.mu.Lock()
		s.closeTransportLocked()
		s.mu.Unlock()
		return update, ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.mu.Lock()
			s.closeTransportLocked()
			s.mu.Unlock()
			err = ErrMCSConnection
			update = RDPBitmapUpdate{}
			return
		}
		if setErr := conn.SetReadDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.mu.Lock()
			s.closeTransportLocked()
			s.mu.Unlock()
			err = ErrMCSConnection
			update = RDPBitmapUpdate{}
		}
	}()

	var assembled []byte
	for fragmentCount := 0; ; fragmentCount++ {
		if fragmentCount >= maxRDPBitmapFragments || ctx.Err() != nil {
			clear(assembled)
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		packet, readErr := readTPKTPacket(conn, maxRDPBitmapTPKTPacket)
		if readErr != nil {
			clear(assembled)
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		fragment, segmentation, fragmentErr := parseRDPBitmapMCSFragment(packet, ioChannelID)
		if fragmentErr != nil {
			clear(packet)
			clear(assembled)
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		if fragmentCount == 0 && segmentation == 3 {
			assembled = append(assembled, fragment...)
			clear(packet)
			break
		}
		if fragmentCount == 0 && segmentation != 2 || fragmentCount > 0 && segmentation == 2 ||
			fragmentCount > 0 && segmentation == 3 || fragmentCount > 0 && segmentation != 0 && segmentation != 1 {
			clear(packet)
			clear(assembled)
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		if len(fragment) > maxRDPBitmapReassemblyBytes-len(assembled) {
			clear(packet)
			clear(assembled)
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		assembled = append(assembled, fragment...)
		clear(packet)
		if segmentation == 1 {
			break
		}
	}
	defer clear(assembled)
	update, err = parseRDPBitmapShareData(assembled, shareID, desktopWidth, desktopHeight)
	if err != nil || ctx.Err() != nil {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	return update, nil
}

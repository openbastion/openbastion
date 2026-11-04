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
		if width == 0 || height == 0 || bpp != 32 || flags != 0 || bitmapLength == 0 || bitmapLength > len(payload) ||
			uint32(left)+uint32(width) > uint32(desktopWidth) || uint32(top)+uint32(height) > uint32(desktopHeight) ||
			right != left+width-1 || bottom != top+height-1 {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		pixels := uint64(width) * uint64(height)
		if pixels > maxRDPDesktopArea || totalPixels > maxRDPDesktopArea-pixels || pixels*4 != uint64(bitmapLength) {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		totalPixels += pixels
		decoded := make([]byte, int(pixels)*4)
		rowBytes := int(width) * 4 // 32-bpp rows are already DWORD aligned.
		for y := 0; y < int(height); y++ {
			srcRow := (int(height) - 1 - y) * rowBytes // TS_BITMAP_DATA is bottom-up.
			dstRow := y * rowBytes
			for x := 0; x < int(width); x++ {
				src := srcRow + x*4
				dst := dstRow + x*4
				decoded[dst], decoded[dst+1], decoded[dst+2], decoded[dst+3] = payload[src+2], payload[src+1], payload[src], 0xff
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

// parseRDPBitmapUpdate validates and decodes one unsegmented MCS bitmap PDU.
// Compressed bitmaps and other pixel formats remain deliberately unsupported.
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.connectionFinalized ||
		!s.capabilitiesExchanged || s.serverCapabilities.ShareID == 0 ||
		!s.transport.Conn.ConnectionState().HandshakeComplete {
		return update, ErrMCSConnection
	}
	if timeout == 0 {
		timeout = defaultCredSSPTimeout
	}
	conn := s.transport.Conn
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		s.closeTransportLocked()
		return update, ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.closeTransportLocked()
			err = ErrMCSConnection
			update = RDPBitmapUpdate{}
			return
		}
		if setErr := conn.SetDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.closeTransportLocked()
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
		fragment, segmentation, fragmentErr := parseRDPBitmapMCSFragment(packet, s.mcsResponse.IOChannelID)
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
	update, err = parseRDPBitmapShareData(assembled, s.serverCapabilities.ShareID,
		s.serverCapabilities.DesktopWidth, s.serverCapabilities.DesktopHeight)
	if err != nil || ctx.Err() != nil {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	return update, nil
}

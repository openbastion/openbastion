package rdp

import (
	"context"
	"encoding/binary"
	"time"
)

const (
	rdpPDU2Update          = byte(2)
	rdpUpdateOrders        = uint16(0)
	rdpUpdateBitmap        = uint16(1)
	rdpOrderStandard       = byte(0x01)
	rdpOrderTypeChange     = byte(0x08)
	rdpOrderOpaqueRect     = byte(0x0a)
	rdpOrderDstBlt         = byte(0x00)
	rdpOrderPatBlt         = byte(0x01)
	rdpOpaqueRectFieldMask = byte(0x7f)     // Four coordinates plus three RGB bytes.
	rdpPatBltFieldMask     = uint16(0x027f) // Four coordinates, ROP, colors, and solid BrushStyle.
	rdpPatBltPatCopy       = byte(0xf0)
	rdpPatBltPatInvert     = byte(0x5a)
	rdpPatBltPatAnd        = byte(0xa0)
	rdpPatBltPatOr         = byte(0xfa)
	rdpPatBltSolidBrush    = byte(0x00)
	rdpDstBltFieldMask     = byte(0x1f) // Four coordinates and bRop.
	rdpDstBltBlackness     = byte(0x00)
	rdpDstBltWhiteness     = byte(0xff)
	rdpDstBltInvert        = byte(0x55)
	maxRDPPrimaryOrders    = 1024
	rdpBitmapCompressed    = uint16(0x0001)
	rdpBitmapNoCompHdr     = uint16(0x0400)
	maxRDPBitmapRects      = 64
	// Keep each fragment below the conservative MCS/TPKT bound. A complete
	// Share Data PDU has a 16-bit totalLength, so reassembly cannot exceed it.
	maxRDPBitmapTPKTPacket      = 16_383
	maxRDPBitmapReassemblyBytes = int(^uint16(0))
	maxRDPBitmapFragments       = 5
)

// rdpBitmapRectangleOperation describes how a decoded rectangle affects the
// existing framebuffer. The zero value replaces pixels from the RGBA payload.
type rdpBitmapRectangleOperation uint8

const (
	rdpBitmapRectangleReplace rdpBitmapRectangleOperation = iota
	rdpBitmapRectangleDstInvert
	rdpBitmapRectanglePatInvert
	rdpBitmapRectanglePatAnd
	rdpBitmapRectanglePatOr
)

// RDPBitmapRectangle is one decoded, top-down rectangle from a server graphics
// update. Pixels is tightly packed RGBA for replacement and solid-brush pattern
// operations; destination-only operations such as DSTINVERT carry no pixel buffer.
type RDPBitmapRectangle struct {
	X         uint16
	Y         uint16
	Width     uint16
	Height    uint16
	Pixels    []byte
	operation rdpBitmapRectangleOperation
}

// RDPBitmapUpdate contains the raster rectangles from one complete graphics update.
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

// parseRDPBitmapShareData decodes one fully reassembled bitmap or orders Share Data PDU.
func parseRDPBitmapShareData(userData []byte, shareID uint32, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	update, _, err := parseRDPBitmapShareDataWithOrderState(userData, shareID, desktopWidth, desktopHeight, rdpPrimaryOrderState{})
	return update, err
}

// rdpPrimaryOrderState retains the connection-scoped primary order type and
// records which negotiated order families appeared so the session can enforce
// their independent indices. Supported profiles require every data field, so
// no per-order field cache is needed.
type rdpPrimaryOrderState struct {
	orderType            byte
	hasOrderType         bool
	dstBltUsed           bool
	patBltOpaqueRectUsed bool
}

func parseRDPBitmapShareDataWithOrderState(userData []byte, shareID uint32, desktopWidth, desktopHeight uint16, state rdpPrimaryOrderState) (RDPBitmapUpdate, rdpPrimaryOrderState, error) {
	var result RDPBitmapUpdate
	if len(userData) < 18+4 || len(userData) > maxRDPBitmapReassemblyBytes || shareID == 0 ||
		desktopWidth == 0 || desktopHeight == 0 || uint64(desktopWidth)*uint64(desktopHeight) > maxRDPDesktopArea {
		return result, state, ErrMCSConnection
	}
	if int(binary.LittleEndian.Uint16(userData[0:2])) != len(userData) ||
		binary.LittleEndian.Uint16(userData[2:4]) != rdpShareDataPDU ||
		binary.LittleEndian.Uint16(userData[4:6]) != rdpServerChannelID ||
		binary.LittleEndian.Uint32(userData[6:10]) != shareID || userData[10] != 0 || userData[11] != 2 ||
		int(binary.LittleEndian.Uint16(userData[12:14])) != len(userData) || userData[14] != rdpPDU2Update ||
		userData[15] != 0 || binary.LittleEndian.Uint16(userData[16:18]) != 0 {
		return result, state, ErrMCSConnection
	}
	payload := userData[18:]
	if len(payload) < 2 {
		return RDPBitmapUpdate{}, state, ErrMCSConnection
	}
	switch binary.LittleEndian.Uint16(payload[:2]) {
	case rdpUpdateBitmap:
		update, err := parseRDPBitmapUpdateData(payload[2:], desktopWidth, desktopHeight)
		return update, state, err
	case rdpUpdateOrders:
		return parseRDPOrdersUpdateData(payload[2:], desktopWidth, desktopHeight, state)
	default:
		return RDPBitmapUpdate{}, state, ErrMCSConnection
	}
}

// parseRDPOrdersUpdateData accepts deliberately narrow primary-order profiles:
// DstBlt BLACKNESS/WHITENESS/DSTINVERT, OpaqueRect, and solid-brush PATCOPY,
// PATINVERT, PATAND, and PATOR PatBlt, all with absolute coordinates and no
// clipping bounds or omitted fields.
func parseRDPOrdersUpdateData(data []byte, desktopWidth, desktopHeight uint16, state rdpPrimaryOrderState) (RDPBitmapUpdate, rdpPrimaryOrderState, error) {
	var result RDPBitmapUpdate
	initialState := state
	if len(data) < 6 || desktopWidth == 0 || desktopHeight == 0 ||
		uint64(desktopWidth)*uint64(desktopHeight) > maxRDPDesktopArea {
		return result, initialState, ErrMCSConnection
	}
	orderCount := int(binary.LittleEndian.Uint16(data[2:4]))
	if orderCount == 0 || orderCount > maxRDPPrimaryOrders {
		return result, initialState, ErrMCSConnection
	}
	data = data[6:] // Both padding fields are ignored by the protocol.
	result.Rectangles = make([]RDPBitmapRectangle, 0, orderCount)
	var totalPixels uint64
	for i := 0; i < orderCount; i++ {
		if len(data) < 1 {
			return RDPBitmapUpdate{}, initialState, ErrMCSConnection
		}
		control := data[0]
		data = data[1:]
		if control&rdpOrderStandard == 0 || control&^(rdpOrderStandard|rdpOrderTypeChange) != 0 {
			return RDPBitmapUpdate{}, initialState, ErrMCSConnection
		}
		if control&rdpOrderTypeChange != 0 {
			if len(data) < 1 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			state.orderType = data[0]
			state.hasOrderType = true
			data = data[1:]
		} else if !state.hasOrderType {
			state.orderType = rdpOrderPatBlt // Initial primary order type per MS-RDPEGDI.
			state.hasOrderType = true
		}
		var left, top, width, height int32
		var red, green, blue byte
		operation := rdpBitmapRectangleReplace
		switch state.orderType {
		case rdpOrderDstBlt:
			if len(data) < 10 || data[0] != rdpDstBltFieldMask {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			// Only destination-independent constant raster operations can be
			// represented as a standalone rectangle without framebuffer state.
			switch data[8] {
			case rdpDstBltBlackness:
				red, green, blue = 0, 0, 0
			case rdpDstBltWhiteness:
				red, green, blue = 0xff, 0xff, 0xff
			case rdpDstBltInvert:
				operation = rdpBitmapRectangleDstInvert
			default:
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[9:]
		case rdpOrderOpaqueRect:
			if len(data) < 12 || data[0] != rdpOpaqueRectFieldMask {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			red, green, blue = data[8], data[9], data[10]
			data = data[11:]
		case rdpOrderPatBlt:
			// This strict form is the normative 0x027f example: four absolute
			// coordinates, PATCOPY, both colors, and a non-cached solid brush.
			if len(data) < 18 || binary.LittleEndian.Uint16(data[:2]) != rdpPatBltFieldMask {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[2:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			rop := data[8]
			// BackColor is present for wire compatibility. Both accepted ROPs
			// use the solid brush's ForeColor; neither reads BackColor.
			red, green, blue = data[12], data[13], data[14]
			brushStyle := data[15]
			if brushStyle != rdpPatBltSolidBrush {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			switch rop {
			case rdpPatBltPatCopy:
				operation = rdpBitmapRectangleReplace
			case rdpPatBltPatInvert:
				operation = rdpBitmapRectanglePatInvert
			case rdpPatBltPatAnd:
				operation = rdpBitmapRectanglePatAnd
			case rdpPatBltPatOr:
				operation = rdpBitmapRectanglePatOr
			default:
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[16:]
		default:
			return RDPBitmapUpdate{}, initialState, ErrMCSConnection
		}
		if left < 0 || top < 0 || width <= 0 || height <= 0 ||
			left+width > int32(desktopWidth) || top+height > int32(desktopHeight) {
			return RDPBitmapUpdate{}, initialState, ErrMCSConnection
		}
		pixels := uint64(width) * uint64(height)
		if pixels > maxRDPDesktopArea || totalPixels > maxRDPDesktopArea-pixels || pixels > uint64(int(^uint(0)>>1))/4 {
			return RDPBitmapUpdate{}, initialState, ErrMCSConnection
		}
		totalPixels += pixels
		var rgba []byte
		if operation == rdpBitmapRectangleReplace || operation == rdpBitmapRectanglePatInvert ||
			operation == rdpBitmapRectanglePatAnd || operation == rdpBitmapRectanglePatOr {
			rgba = make([]byte, int(pixels)*4)
			for offset := 0; offset < len(rgba); offset += 4 {
				rgba[offset], rgba[offset+1], rgba[offset+2], rgba[offset+3] = red, green, blue, 0xff
			}
		}
		result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{
			X: uint16(left), Y: uint16(top), Width: uint16(width), Height: uint16(height), Pixels: rgba, operation: operation,
		})
		switch state.orderType {
		case rdpOrderDstBlt:
			state.dstBltUsed = true
		case rdpOrderPatBlt, rdpOrderOpaqueRect:
			state.patBltOpaqueRectUsed = true
		}
	}
	if len(data) != 0 {
		return RDPBitmapUpdate{}, initialState, ErrMCSConnection
	}
	return result, state, nil
}

// parseRDPBitmapUpdateData decodes the shared bitmap-update body used by both
// slow-path TS_UPDATE and fast-path TS_FP_UPDATE_BITMAP.
func parseRDPBitmapUpdateData(payload []byte, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	var result RDPBitmapUpdate
	if len(payload) < 2 || desktopWidth == 0 || desktopHeight == 0 ||
		uint64(desktopWidth)*uint64(desktopHeight) > maxRDPDesktopArea {
		return result, ErrMCSConnection
	}
	count := int(binary.LittleEndian.Uint16(payload[:2]))
	if count == 0 || count > maxRDPBitmapRects {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	payload = payload[2:]
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

const (
	rdpFastPathUpdateBitmap = byte(1)
	maxRDPFastPathPacket    = 0x7fff
)

// parseRDPFastPathBitmapUpdate accepts one unencrypted, unfragmented bitmap
// update. TLS is the security layer; fast-path RDP encryption and compression
// remain deliberately unsupported.
func parseRDPFastPathBitmapUpdate(packet []byte, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	var empty RDPBitmapUpdate
	if len(packet) < 4 || len(packet) > maxRDPFastPathPacket || packet[0] != 0 {
		return empty, ErrMCSConnection
	}
	offset := 2
	packetLength := int(packet[1])
	if packet[1]&0x80 != 0 {
		if len(packet) < 3 {
			return empty, ErrMCSConnection
		}
		packetLength = int(packet[1]&0x7f)<<8 | int(packet[2])
		offset++
		if packetLength < 128 {
			return empty, ErrMCSConnection
		}
	}
	if packetLength != len(packet) || packetLength < offset+4 {
		return empty, ErrMCSConnection
	}

	// This profile accepts exactly one bitmap update per Fast-Path PDU.
	// Other update types, compression and fragment sequences are not negotiated.
	updateHeader := packet[offset]
	if updateHeader&0x0f != rdpFastPathUpdateBitmap ||
		(updateHeader>>4)&0x03 != 0 || updateHeader>>6 != 0 {
		return empty, ErrMCSConnection
	}
	size := int(binary.LittleEndian.Uint16(packet[offset+1 : offset+3]))
	data := packet[offset+3:]
	if size == 0 || size != len(data) {
		return empty, ErrMCSConnection
	}
	return parseRDPBitmapUpdateData(data, desktopWidth, desktopHeight)
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

// decodeRDP6BitmapWithHeader validates TS_CD_HEADER and decodes bounded RDP 6.0
// ARGB and AYCoCg profiles. AYCoCg chroma planes may be half-resolution in both
// dimensions. Planes may be raw or independently scan-line RLE encoded. Plane
// bytes are ordered A (optional), R/Y, G/Co, B/Cg in bottom-up row order;
// output is top-down RGBA.
const (
	rdp6FormatChromaSubsampling = byte(0x10)
	rdp6FormatRLE               = byte(0x08)
	rdp6FormatNoAlpha           = byte(0x04)
	rdp6FormatReservedMask      = byte(0x03)
)

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
	// CLL selects ARGB (zero) or AYCoCg (1..7). Chroma subsampling is
	// defined only for AYCoCg; reserved bits must always be zero.
	colorLossLevel := int(format >> 5)
	chromaSubsampling := format&rdp6FormatChromaSubsampling != 0
	if format&rdp6FormatReservedMask != 0 || (chromaSubsampling && colorLossLevel == 0) {
		return nil, ErrMCSConnection
	}
	noAlpha := format&rdp6FormatNoAlpha != 0
	rle := format&rdp6FormatRLE != 0
	planeCount := 4
	if noAlpha {
		planeCount = 3
	}
	fullPlaneBytes := int(pixels)
	chromaWidth, chromaHeight := (width+1)/2, (height+1)/2
	plans := make([][]byte, planeCount)
	offset := 1
	for i := range plans {
		planeWidth, planeHeight := width, height
		if chromaSubsampling && i >= planeCount-2 {
			planeWidth, planeHeight = chromaWidth, chromaHeight
		}
		planeBytes := planeWidth * planeHeight
		if rle {
			decoded, consumed, err := decodeRDP6RLEPlane(stream[offset:], planeWidth, planeHeight)
			if err != nil || consumed <= 0 || consumed > len(stream)-offset {
				return nil, ErrMCSConnection
			}
			plans[i] = decoded
			offset += consumed
			continue
		}
		if planeBytes > len(stream)-offset {
			return nil, ErrMCSConnection
		}
		plans[i] = stream[offset : offset+planeBytes]
		offset += planeBytes
	}
	// The uncompressed stream optionally carries one ignored alignment byte.
	// RLE streams end exactly after the final plane; arbitrary trailing bytes
	// would make the plane boundaries ambiguous.
	if (!rle && len(stream)-offset > 1) || (rle && offset != len(stream)) {
		return nil, ErrMCSConnection
	}
	decoded := make([]byte, int(decodedBytes))
	for i := 0; i < fullPlaneBytes; i++ {
		wireY := i / width
		dst := ((height-1-wireY)*width + i%width) * 4
		plane := 0
		if !noAlpha {
			decoded[dst+3] = plans[0][i]
			plane = 1
		} else {
			decoded[dst+3] = 0xff
		}
		chromaIndex := i
		if chromaSubsampling {
			chromaIndex = (wireY/2)*chromaWidth + (i%width)/2
		}
		first, second, third := plans[plane][i], plans[plane+1][chromaIndex], plans[plane+2][chromaIndex]
		if colorLossLevel == 0 {
			decoded[dst], decoded[dst+1], decoded[dst+2] = first, second, third
			continue
		}
		red, green, blue := decodeRDP6AYCoCg(first, second, third, colorLossLevel)
		decoded[dst], decoded[dst+1], decoded[dst+2] = red, green, blue
	}
	return decoded, nil
}

// decodeRDP6AYCoCg converts one AYCoCg sample to RGB. Co and Cg are signed
// 8-bit chroma samples restored by the negotiated color-loss shift. The
// transform uses signed arithmetic shifts for the matrix's half coefficients
// and clamps every output channel to the representable 8-bit range.
func decodeRDP6AYCoCg(y, co, cg byte, colorLossLevel int) (byte, byte, byte) {
	orange := clampRDP6Chroma(int(int8(co)) << colorLossLevel)
	greenChroma := clampRDP6Chroma(int(int8(cg)) << colorLossLevel)
	luma := int(y)
	red := luma + (orange >> 1) - (greenChroma >> 1)
	green := luma + (greenChroma >> 1)
	blue := luma - (orange >> 1) - (greenChroma >> 1)
	return clampRDP6Channel(red), clampRDP6Channel(green), clampRDP6Channel(blue)
}

func clampRDP6Chroma(value int) int {
	if value < -255 {
		return -255
	}
	if value > 255 {
		return 255
	}
	return value
}

func clampRDP6Channel(value int) byte {
	if value < 0 {
		return 0
	}
	if value > 255 {
		return 255
	}
	return byte(value)
}

// decodeRDP6RLEPlane decodes one independently encoded RDP6 color plane.
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

// parseRDPBitmapUpdate validates and decodes one unsegmented MCS graphics PDU.
// The 32-bpp compressed path supports bounded RDP 6.0 ARGB and AYCoCg planes
// in raw or scan-line RLE form, including AYCoCg chroma subsampling.
// Network callers use the reassembling ReadBitmapUpdate path below.
func parseRDPBitmapUpdate(packet []byte, expectedChannelID uint16, shareID uint32, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	userData, segmentation, err := parseRDPBitmapMCSFragment(packet, expectedChannelID)
	if err != nil || segmentation != 3 {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	return parseRDPBitmapShareData(userData, shareID, desktopWidth, desktopHeight)
}

// ReadBitmapUpdate reads and decodes one complete server graphics update after
// connection finalization. It accepts bitmap updates and strict primary-order
// subsets. The packet is bounded to a larger TPKT than the handshake path.
// Any malformed or unexpected packet makes the stream terminal.
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
	orderState := s.primaryOrderState
	primaryOrdersEnabled := s.primaryOrdersEnabled
	patBltOpaqueRectEnabled := s.patBltOpaqueRectEnabled
	dstBltEnabled := s.dstBltEnabled
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
		var packet []byte
		var readErr error
		if fragmentCount == 0 {
			var fastPath bool
			packet, fastPath, readErr = readRDPServerUpdatePacket(conn, maxRDPBitmapTPKTPacket)
			if readErr == nil && fastPath {
				update, err = parseRDPFastPathBitmapUpdate(packet, desktopWidth, desktopHeight)
				clear(packet)
				if err != nil || ctx.Err() != nil {
					return RDPBitmapUpdate{}, ErrMCSConnection
				}
				return update, nil
			}
		} else {
			packet, readErr = readTPKTPacket(conn, maxRDPBitmapTPKTPacket)
		}
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
	if len(assembled) >= 20 && binary.LittleEndian.Uint16(assembled[18:20]) == rdpUpdateOrders && !primaryOrdersEnabled {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	var nextOrderState rdpPrimaryOrderState
	update, nextOrderState, err = parseRDPBitmapShareDataWithOrderState(assembled, shareID, desktopWidth, desktopHeight, orderState)
	if err != nil || ctx.Err() != nil ||
		nextOrderState.dstBltUsed && !dstBltEnabled ||
		nextOrderState.patBltOpaqueRectUsed && !patBltOpaqueRectEnabled {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	s.mu.Lock()
	s.primaryOrderState = nextOrderState
	s.mu.Unlock()
	return update, nil
}

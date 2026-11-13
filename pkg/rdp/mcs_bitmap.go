package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"sync/atomic"
	"time"
)

const (
	rdpPDU2Update           = byte(2)
	rdpPDU2Pointer          = byte(0x1b)
	rdpUpdateOrders         = uint16(0)
	rdpUpdateBitmap         = uint16(1)
	rdpOrderStandard        = byte(0x01)
	rdpOrderTypeChange      = byte(0x08)
	rdpOrderOpaqueRect      = byte(0x0a)
	rdpOrderDstBlt          = byte(0x00)
	rdpOrderPatBlt          = byte(0x01)
	rdpOrderScrBlt          = byte(0x02)
	rdpOrderMultiDstBlt     = byte(0x0f)
	rdpOrderMultiPatBlt     = byte(0x10)
	rdpOrderMultiScrBlt     = byte(0x11)
	rdpOrderLineTo          = byte(0x09)
	rdpOrderPolygonSC       = byte(0x14)
	rdpOrderPolyline        = byte(0x16)
	rdpOrderEllipseSC       = byte(0x19)
	rdpROP2Black            = byte(0x01)
	rdpROP2NotMergePen      = byte(0x02)
	rdpROP2MaskNotPen       = byte(0x03)
	rdpROP2MergeNotPen      = byte(0x0c)
	rdpROP2NotCopyPen       = byte(0x04)
	rdpROP2MaskPenNot       = byte(0x05)
	rdpROP2MaskPen          = byte(0x09)
	rdpROP2Not              = byte(0x06)
	rdpROP2XorPen           = byte(0x07)
	rdpROP2NotXorPen        = byte(0x0a)
	rdpROP2Nop              = byte(0x0b)
	rdpROP2White            = byte(0x10)
	rdpROP2CopyPen          = byte(0x0d)
	rdpOrderMultiOpaqueRect = byte(0x12)
	rdpOpaqueRectFieldMask  = byte(0x7f)     // Four coordinates plus three RGB bytes.
	rdpPatBltFieldMask      = uint16(0x027f) // Four coordinates, ROP, colors, and solid BrushStyle.
	rdpPatBltPatCopy        = byte(0xf0)
	rdpPatBltPatInvert      = byte(0x5a)
	rdpPatBltPatAnd         = byte(0xa0)
	rdpPatBltPatOr          = byte(0xfa)
	rdpPatBltNotPatCopy     = byte(0x0f)
	rdpScrBltFieldMask      = byte(0x7f) // Four destination coordinates, ROP, and two source coordinates.
	rdpScrBltSrcCopy        = byte(0xcc)
	rdpPatBltSolidBrush     = byte(0x00)
	rdpDstBltFieldMask      = byte(0x1f) // Four coordinates and bRop.
	rdpMultiDstBltFieldMask = byte(0x7f) // Four coordinates, ROP, count and delta list.
	rdpDstBltBlackness      = byte(0x00)
	rdpDstBltWhiteness      = byte(0xff)
	rdpDstBltInvert         = byte(0x55)
	maxRDPPrimaryOrders     = 1024
	maxRDPMultiDstBltRects  = 45
	maxRDPMultiDstBltBytes  = 395
	maxRDPLinePixels        = 32_768
	maxRDPDeltaPoints       = 34
	maxRDPDeltaBytes        = 147
	maxRDPPolylinePoints    = maxRDPDeltaPoints
	maxRDPPolylineBytes     = maxRDPDeltaBytes
	maxRDPPolygonPoints     = maxRDPDeltaPoints // Local strict-profile limit for delta entries.
	maxRDPPolygonBytes      = maxRDPDeltaBytes  // Local cbData payload limit; 148 bytes including cbData.
	maxRDPPolygonSpans      = 1_114_095         // 17 spans per row at the maximum 16-bit desktop height.
	rdpBitmapCompressed     = uint16(0x0001)
	rdpBitmapNoCompHdr      = uint16(0x0400)
	maxRDPBitmapRects       = 64
	// maxRDPBitmapUpdateRects bounds the rectangles of one bitmap update: Windows sends its whole
	// screen at once, as 64 x 64 tiles (260 for 1280 x 800, CI run #36). 4096 is the largest desktop
	// accepted (maxRDPDesktopArea) in such tiles; the PDU size bounds it further (19 bytes at least
	// per rectangle), and the pixels decoded per update stay bounded by maxRDPDesktopArea. Orders
	// keep maxRDPBitmapRects.
	maxRDPBitmapUpdateRects = 4096
	// Keep each fragment below the conservative MCS/TPKT bound. A complete
	// Share Data PDU has a 16-bit totalLength, so reassembly cannot exceed it.
	maxRDPBitmapTPKTPacket      = 16_383
	maxRDPBitmapReassemblyBytes = int(^uint16(0))
	maxRDPBitmapFragments       = 5
)

// rdpBitmapRectangleOperation describes how a decoded graphics operation affects the
// existing framebuffer. The zero value replaces pixels from the RGBA payload.
type rdpBitmapRectangleOperation uint8

const (
	rdpBitmapRectangleReplace rdpBitmapRectangleOperation = iota
	rdpBitmapRectangleDstInvert
	rdpBitmapRectanglePatInvert
	rdpBitmapRectanglePatAnd
	rdpBitmapRectanglePatOr
	rdpBitmapRectangleScrCopy
	rdpBitmapRectangleLine
	rdpBitmapRectanglePolygon
	rdpBitmapRectangleEllipse
)

// RDPBitmapRectangle is one ordered framebuffer operation from a server graphics
// update. Pixels is tightly packed RGBA for replacement and solid-brush pattern
// operations; line, polygon and ellipse operations carry bounded geometry and color metadata.
type RDPBitmapRectangle struct {
	X               uint16
	Y               uint16
	Width           uint16
	Height          uint16
	Pixels          []byte
	operation       rdpBitmapRectangleOperation
	sourceX         uint16
	sourceY         uint16
	linePoints      [][2]uint16
	lineColor       [4]byte
	lineROP2        byte
	polygonPoints   [][2]uint16
	polygonColor    [4]byte
	polygonFillMode byte
	polygonROP2     byte
	ellipseColor    [4]byte
	ellipseROP2     byte
}

// RDPBitmapUpdate contains ordered framebuffer operations from one complete graphics update.
type RDPBitmapUpdate struct {
	Rectangles []RDPBitmapRectangle
	// DesktopWidth and DesktopHeight are the desktop the rectangles are drawn on, as the server
	// stated it at the last (re)activation: a reactivation may change it (MS-RDPBCGR 1.3.1.3).
	DesktopWidth, DesktopHeight uint16
	// Pointer is a pointer update, with no rectangles, when MCSClientSettings.PointerShapes is on.
	Pointer *RDPPointerUpdate
	// Reactivated says a reactivation came before this update: the pointer cache is gone with the
	// old share (MS-RDPBCGR 1.3.1.3).
	Reactivated bool
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
	// Bits 7..6 are the data priority, which says nothing this client depends on: Windows Server
	// 2022 sends some Share Data at top priority (CI of PR #94), FreeRDP ignores it. Bits 5..4
	// carry the MCS begin/end segmentation flags; the four reserved padding bits must be 0.
	if mcs[0] != mcsSendDataIndication ||
		binary.BigEndian.Uint16(mcs[3:5]) != expectedChannelID || mcs[5]&0x0f != 0 {
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
	scrBltUsed           bool
	multiDstBltUsed      bool
	multiPatBltUsed      bool
	multiScrBltUsed      bool
	lineToUsed           bool
	polylineUsed         bool
	polygonSCUsed        bool
	ellipseSCUsed        bool
	multiOpaqueRectUsed  bool
}

func parseRDPBitmapShareDataWithOrderState(userData []byte, shareID uint32, desktopWidth, desktopHeight uint16, state rdpPrimaryOrderState) (RDPBitmapUpdate, rdpPrimaryOrderState, error) {
	return parseRDPBitmapShareDataAt(userData, shareID, desktopWidth, desktopHeight, 32, state)
}

func parseRDPBitmapShareDataAt(userData []byte, shareID uint32, desktopWidth, desktopHeight, sessionBPP uint16, state rdpPrimaryOrderState) (RDPBitmapUpdate, rdpPrimaryOrderState, error) {
	var result RDPBitmapUpdate
	if len(userData) < 18+4 || len(userData) > maxRDPBitmapReassemblyBytes || shareID == 0 ||
		desktopWidth == 0 || desktopHeight == 0 || uint64(desktopWidth)*uint64(desktopHeight) > maxRDPDesktopArea {
		return result, state, ErrMCSConnection
	}
	if int(binary.LittleEndian.Uint16(userData[0:2])) != len(userData) ||
		binary.LittleEndian.Uint16(userData[2:4]) != rdpShareDataPDU ||
		binary.LittleEndian.Uint32(userData[6:10]) != shareID || userData[14] != rdpPDU2Update ||
		userData[15] != 0 || binary.LittleEndian.Uint16(userData[16:18]) != 0 {
		return result, state, ErrMCSConnection
	}
	payload := userData[18:]
	if len(payload) < 2 {
		return RDPBitmapUpdate{}, state, ErrMCSConnection
	}
	switch binary.LittleEndian.Uint16(payload[:2]) {
	case rdpUpdateBitmap:
		update, err := parseRDPBitmapUpdateDataAt(payload[2:], desktopWidth, desktopHeight, sessionBPP)
		return update, state, err
	case rdpUpdateOrders:
		// Order colors are 32-bpp here; at another depth they would mean other colors (ADR-0086).
		if sessionBPP != 32 {
			return RDPBitmapUpdate{}, state, ErrMCSConnection
		}
		return parseRDPOrdersUpdateData(payload[2:], desktopWidth, desktopHeight, state)
	default:
		return RDPBitmapUpdate{}, state, ErrMCSConnection
	}
}

// isSupportedRDPROP2 reports the deliberately small set of fully rendered ROP2 operations.
func isSupportedRDPROP2(operation byte) bool {
	switch operation {
	case rdpROP2Black, rdpROP2NotMergePen, rdpROP2MaskNotPen, rdpROP2MergeNotPen, rdpROP2NotCopyPen, rdpROP2MaskPenNot, rdpROP2MaskPen, rdpROP2Not, rdpROP2XorPen, rdpROP2NotXorPen, rdpROP2Nop, rdpROP2CopyPen, rdpROP2White:
		return true
	default:
		return false
	}
}

// parseRDPOrdersUpdateData accepts deliberately narrow primary-order profiles:
// DstBlt BLACKNESS/WHITENESS/DSTINVERT, MultiDstBlt with destination-only
// raster operations, OpaqueRect, solid-brush PatBlt, and SRCCOPY ScrBlt, all
// with absolute coordinates and no clipping bounds or omitted fields.
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
		var sourceX, sourceY int32
		var multiRects [][4]int32
		var linePoints [][2]uint16
		var lineColor [4]byte
		lineROP2 := rdpROP2CopyPen
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
		case rdpOrderScrBlt:
			if len(data) < 14 || data[0] != rdpScrBltFieldMask {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			if data[8] != rdpScrBltSrcCopy {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			sourceX = int32(int16(binary.LittleEndian.Uint16(data[9:11])))
			sourceY = int32(int16(binary.LittleEndian.Uint16(data[11:13])))
			operation = rdpBitmapRectangleScrCopy
			data = data[13:]
		case rdpOrderPolyline:
			// Strict seven-field profile: absolute start point, supported ROP2,
			// uncached solid brush, RGB pen color and bounded delta points.
			if len(data) < 13 || data[0] != 0x7f {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			startX := int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			startY := int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			if !isSupportedRDPROP2(data[4]) || binary.LittleEndian.Uint16(data[5:7]) != 0 ||
				startX < 0 || startY < 0 || startX >= int32(desktopWidth) || startY >= int32(desktopHeight) {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			lineROP2 = data[4]
			lineColor = [4]byte{data[7], data[8], data[9], 0xff}
			deltaEntries := int(data[10])
			encodedLength := int(data[11]) // cbData delimits this field; later orders may follow.
			if deltaEntries < 1 || deltaEntries > maxRDPPolylinePoints || encodedLength == 0 ||
				encodedLength > maxRDPPolylineBytes || encodedLength > len(data)-12 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			points, decodeErr := decodeRDPDeltaPoints(data[12:12+encodedLength], deltaEntries, startX, startY, desktopWidth, desktopHeight)
			if decodeErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[12+encodedLength:]
			previousX, previousY := startX, startY
			segmentsAdded := 0
			for _, point := range points {
				currentX, currentY := int32(point[0]), int32(point[1])
				if currentX == previousX && currentY == previousY {
					continue
				}
				segment, segmentErr := rasterizeRDPLine(previousX, previousY, currentX, currentY, desktopWidth, desktopHeight)
				if segmentErr != nil || len(result.Rectangles) >= maxRDPBitmapRects ||
					uint64(len(segment)) > maxRDPDesktopArea-totalPixels {
					return RDPBitmapUpdate{}, initialState, ErrMCSConnection
				}
				first := segment[0]
				result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{X: first[0], Y: first[1], Width: 1, Height: 1,
					operation: rdpBitmapRectangleLine, linePoints: segment, lineColor: lineColor, lineROP2: lineROP2})
				totalPixels += uint64(len(segment))
				segmentsAdded++
				previousX, previousY = currentX, currentY
			}
			if segmentsAdded == 0 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			state.polylineUsed = true
			continue
		case rdpOrderPolygonSC:
			// Strict seven-field profile: absolute start, R2_COPYPEN,
			// ALTERNATE fill, RGB brush color and bounded delta points.
			if len(data) < 12 || data[0] != 0x7f {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			startX := int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			startY := int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			if !isSupportedRDPROP2(data[4]) || data[5] != 0x01 || startX < 0 || startY < 0 ||
				startX >= int32(desktopWidth) || startY >= int32(desktopHeight) {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			polygonColor := [4]byte{data[6], data[7], data[8], 0xff}
			deltaEntries := int(data[9])
			encodedLength := int(data[10]) // cbData delimits this field; later orders may follow.
			if deltaEntries < 2 || deltaEntries > maxRDPPolygonPoints || encodedLength == 0 ||
				encodedLength > maxRDPPolygonBytes || encodedLength > len(data)-11 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			deltaPoints, decodeErr := decodeRDPDeltaPoints(data[11:11+encodedLength], deltaEntries, startX, startY, desktopWidth, desktopHeight)
			if decodeErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			polygonPoints := make([][2]uint16, 1, len(deltaPoints)+1)
			polygonPoints[0] = [2]uint16{uint16(startX), uint16(startY)}
			polygonPoints = append(polygonPoints, deltaPoints...)
			_, bounds, pixels, polygonErr := rasterizeRDPPolygon(polygonPoints, 0x01, desktopWidth, desktopHeight)
			if polygonErr != nil || len(result.Rectangles) >= maxRDPBitmapRects || pixels > maxRDPDesktopArea-totalPixels {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{
				X: bounds[0], Y: bounds[1], Width: bounds[2], Height: bounds[3], operation: rdpBitmapRectanglePolygon,
				polygonPoints: polygonPoints, polygonColor: polygonColor, polygonFillMode: 0x01, polygonROP2: data[4],
			})
			totalPixels += pixels
			state.polygonSCUsed = true
			data = data[11+encodedLength:]
			continue
		case rdpOrderEllipseSC:
			// Strict seven-field profile with inclusive, absolute 16-bit bounds.
			if len(data) < 14 || data[0] != 0x7f {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			left := int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top := int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			right := int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			bottom := int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			if !isSupportedRDPROP2(data[8]) || data[9] != 0x01 || left < 0 || top < 0 || right < left || bottom < top ||
				right >= int32(desktopWidth) || bottom >= int32(desktopHeight) {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			ellipseColor := [4]byte{data[10], data[11], data[12], 0xff}
			width, height := uint16(right-left+1), uint16(bottom-top+1)
			_, bounds, pixels, ellipseErr := rasterizeRDPEllipse(uint16(left), uint16(top), width, height, desktopWidth, desktopHeight)
			if ellipseErr != nil || len(result.Rectangles) >= maxRDPBitmapRects || pixels > maxRDPDesktopArea-totalPixels {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{
				X: bounds[0], Y: bounds[1], Width: bounds[2], Height: bounds[3], operation: rdpBitmapRectangleEllipse,
				ellipseColor: ellipseColor, ellipseROP2: data[8],
			})
			totalPixels += pixels
			state.ellipseSCUsed = true
			data = data[13:]
			continue
		case rdpOrderLineTo:
			// Strict ten-field profile: transparent background, absolute
			// endpoints, R2_COPYPEN and a one-pixel solid pen.
			if len(data) < 21 || binary.LittleEndian.Uint16(data[:2]) != 0x03ff {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[2:]
			if binary.LittleEndian.Uint16(data[0:2]) != 1 || !isSupportedRDPROP2(data[13]) || data[14] != 0 || data[15] != 1 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			startX := int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			startY := int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			endX := int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			endY := int32(int16(binary.LittleEndian.Uint16(data[8:10])))
			if !allZeroBytes(data[10:13]) {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			var lineErr error
			linePoints, lineErr = rasterizeRDPLine(startX, startY, endX, endY, desktopWidth, desktopHeight)
			if lineErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			lineROP2 = data[13]
			lineColor = [4]byte{data[16], data[17], data[18], 0xff}
			data = data[19:]
		case rdpOrderMultiScrBlt:
			// Strict full-field profile: destination anchor, SRCCOPY source
			// anchor, count and a bounded delta-rectangle list.
			if len(data) < 18 || binary.LittleEndian.Uint16(data[:2]) != 0x01ff {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[2:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			if data[8] != rdpScrBltSrcCopy || left < 0 || top < 0 || width <= 0 || height <= 0 ||
				left+width > int32(desktopWidth) || top+height > int32(desktopHeight) {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			sourceX = int32(int16(binary.LittleEndian.Uint16(data[9:11])))
			sourceY = int32(int16(binary.LittleEndian.Uint16(data[11:13])))
			deltaEntries := int(data[13])
			encodedLength := int(binary.LittleEndian.Uint16(data[14:16]))
			if deltaEntries < 1 || deltaEntries > maxRDPMultiDstBltRects || encodedLength == 0 ||
				encodedLength > maxRDPMultiDstBltBytes || encodedLength > len(data)-16 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			decodedRects, decodeErr := decodeRDPMultiDstBltRectangles(data[16:16+encodedLength], deltaEntries)
			if decodeErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			multiRects = decodedRects
			operation = rdpBitmapRectangleScrCopy
			data = data[16+encodedLength:]
		case rdpOrderMultiPatBlt:
			// Strict full-field profile: four coordinates, ROP, colors, a
			// non-cached solid brush, count and bounded delta rectangles.
			if len(data) < 29 || binary.LittleEndian.Uint16(data[:2]) != 0x3fff {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[2:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			rop := data[8]
			// BackColor is retained for wire compatibility; the supported
			// solid-brush ROP subset consumes ForeColor only.
			red, green, blue = data[12], data[13], data[14]
			if data[15] != 0 || data[16] != 0 || data[17] != rdpPatBltSolidBrush || data[18] != 0 ||
				!allZeroBytes(data[19:26]) {
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
			case rdpPatBltNotPatCopy:
				operation = rdpBitmapRectangleReplace
				red, green, blue = ^red, ^green, ^blue
			default:
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			deltaEntries := int(data[26])
			encodedLength := int(binary.LittleEndian.Uint16(data[27:29]))
			if deltaEntries < 1 || deltaEntries > maxRDPMultiDstBltRects || encodedLength == 0 ||
				encodedLength > maxRDPMultiDstBltBytes || encodedLength > len(data)-29 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			decodedRects, decodeErr := decodeRDPMultiDstBltRectangles(data[29:29+encodedLength], deltaEntries)
			if decodeErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			multiRects = decodedRects
			data = data[29+encodedLength:]
		case rdpOrderMultiOpaqueRect:
			// Strict full-field profile: four coordinates, RGB color, count,
			// and a bounded two-byte-length DELTA_RECTS_FIELD.
			if len(data) < 16 || binary.LittleEndian.Uint16(data[:2]) != 0x01ff {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[2:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
			red, green, blue = data[8], data[9], data[10]
			deltaEntries := int(data[11])
			encodedLength := int(binary.LittleEndian.Uint16(data[12:14]))
			if deltaEntries < 1 || deltaEntries > maxRDPMultiDstBltRects || encodedLength == 0 ||
				encodedLength > maxRDPMultiDstBltBytes || encodedLength > len(data)-14 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			decodedRects, decodeErr := decodeRDPMultiDstBltRectangles(data[14:14+encodedLength], deltaEntries)
			if decodeErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			multiRects = decodedRects
			data = data[14+encodedLength:]
		case rdpOrderMultiDstBlt:
			// Strict full-field profile: base rectangle, destination-only ROP,
			// delta count, then a bounded VARIABLE2_FIELD containing DELTA_RECTS.
			if len(data) < 13 || data[0] != rdpMultiDstBltFieldMask {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[1:]
			left = int32(int16(binary.LittleEndian.Uint16(data[0:2])))
			top = int32(int16(binary.LittleEndian.Uint16(data[2:4])))
			width = int32(int16(binary.LittleEndian.Uint16(data[4:6])))
			height = int32(int16(binary.LittleEndian.Uint16(data[6:8])))
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
			deltaEntries := int(data[9])
			encodedLength := int(binary.LittleEndian.Uint16(data[10:12]))
			if deltaEntries < 1 || deltaEntries > maxRDPMultiDstBltRects || encodedLength == 0 ||
				encodedLength > maxRDPMultiDstBltBytes || encodedLength > len(data)-12 {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			decodedRects, decodeErr := decodeRDPMultiDstBltRectangles(data[12:12+encodedLength], deltaEntries)
			if decodeErr != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			multiRects = decodedRects
			data = data[12+encodedLength:]
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
			case rdpPatBltNotPatCopy:
				operation = rdpBitmapRectangleReplace
				red, green, blue = ^red, ^green, ^blue
			default:
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			data = data[16:]
		default:
			return RDPBitmapUpdate{}, initialState, ErrMCSConnection
		}
		rectangles := multiRects
		if state.orderType == rdpOrderLineTo {
			state.lineToUsed = true
			if len(linePoints) == 0 || len(result.Rectangles) >= maxRDPBitmapRects || uint64(len(linePoints)) > maxRDPDesktopArea-totalPixels {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
			first := linePoints[0]
			result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{X: first[0], Y: first[1], Width: 1, Height: 1,
				operation: rdpBitmapRectangleLine, linePoints: linePoints, lineColor: lineColor, lineROP2: lineROP2})
			totalPixels += uint64(len(linePoints))
			continue
		}
		if state.orderType != rdpOrderMultiDstBlt && state.orderType != rdpOrderMultiOpaqueRect && state.orderType != rdpOrderMultiPatBlt && state.orderType != rdpOrderMultiScrBlt {
			rectangles = [][4]int32{{left, top, width, height}}
		}
		for _, bounds := range rectangles {
			rectSourceX, rectSourceY := sourceX, sourceY
			if state.orderType == rdpOrderMultiScrBlt {
				rectSourceX += bounds[0] - left
				rectSourceY += bounds[1] - top
			}
			if err := appendRDPPrimaryRectangle(&result, &totalPixels, bounds[0], bounds[1], bounds[2], bounds[3],
				desktopWidth, desktopHeight, operation, red, green, blue, rectSourceX, rectSourceY); err != nil {
				return RDPBitmapUpdate{}, initialState, ErrMCSConnection
			}
		}
		switch state.orderType {
		case rdpOrderDstBlt:
			state.dstBltUsed = true
		case rdpOrderPatBlt, rdpOrderOpaqueRect:
			state.patBltOpaqueRectUsed = true
		case rdpOrderScrBlt:
			state.scrBltUsed = true
		case rdpOrderMultiDstBlt:
			state.multiDstBltUsed = true
		case rdpOrderMultiPatBlt:
			state.multiPatBltUsed = true
		case rdpOrderMultiScrBlt:
			state.multiScrBltUsed = true
		case rdpOrderLineTo:
			state.lineToUsed = true
		case rdpOrderMultiOpaqueRect:
			state.multiOpaqueRectUsed = true
		}
	}
	if len(data) != 0 {
		return RDPBitmapUpdate{}, initialState, ErrMCSConnection
	}
	return result, state, nil
}

// decodeRDPDeltaPoints decodes the zero-bits-prefixed DELTA_PTS_FIELD shared by
// Polyline and PolygonSC. The initial point is supplied separately; each decoded
// point accumulates signed X/Y deltas and must remain inside the desktop.
func decodeRDPDeltaPoints(encoded []byte, count int, startX, startY int32, desktopWidth, desktopHeight uint16) ([][2]uint16, error) {
	if count < 1 || count > maxRDPDeltaPoints || len(encoded) == 0 || len(encoded) > maxRDPDeltaBytes {
		return nil, ErrMCSConnection
	}
	zeroBytes := (count + 3) / 4
	if len(encoded) < zeroBytes {
		return nil, ErrMCSConnection
	}
	zeroBits := encoded[:zeroBytes]
	if count%4 != 0 {
		unusedBits := 8 - (count%4)*2
		if zeroBits[zeroBytes-1]&byte((1<<unusedBits)-1) != 0 {
			return nil, ErrMCSConnection
		}
	}
	data := encoded[zeroBytes:]
	points := make([][2]uint16, 0, count)
	x, y := startX, startY
	for i := 0; i < count; i++ {
		shift := uint(7 - (i%4)*2)
		maskX, maskY := byte(1<<shift), byte(1<<(shift-1))
		if zeroBits[i/4]&maskX == 0 {
			delta, remaining, err := readRDPPackedSignedDelta(data)
			if err != nil {
				return nil, ErrMCSConnection
			}
			x += delta
			data = remaining
		}
		if zeroBits[i/4]&maskY == 0 {
			delta, remaining, err := readRDPPackedSignedDelta(data)
			if err != nil {
				return nil, ErrMCSConnection
			}
			y += delta
			data = remaining
		}
		if x < 0 || y < 0 || x >= int32(desktopWidth) || y >= int32(desktopHeight) {
			return nil, ErrMCSConnection
		}
		points = append(points, [2]uint16{uint16(x), uint16(y)})
	}
	if len(data) != 0 {
		return nil, ErrMCSConnection
	}
	return points, nil
}

func rasterizeRDPLine(startX, startY, endX, endY int32, desktopWidth, desktopHeight uint16) ([][2]uint16, error) {
	if startX < 0 || startY < 0 || endX < 0 || endY < 0 || startX >= int32(desktopWidth) || endX >= int32(desktopWidth) ||
		startY >= int32(desktopHeight) || endY >= int32(desktopHeight) {
		return nil, ErrMCSConnection
	}
	dx, dy := absRDPInt32(endX-startX), absRDPInt32(endY-startY)
	if max(dx, dy)+1 > maxRDPLinePixels {
		return nil, ErrMCSConnection
	}
	sx, sy := int32(1), int32(1)
	if startX > endX {
		sx = -1
	}
	if startY > endY {
		sy = -1
	}
	errValue := dx - dy
	points := make([][2]uint16, 0, int(max(dx, dy))+1)
	for startX != endX || startY != endY {
		points = append(points, [2]uint16{uint16(startX), uint16(startY)})
		doubleError := 2 * errValue
		if doubleError > -dy {
			errValue -= dy
			startX += sx
		}
		if doubleError < dx {
			errValue += dx
			startY += sy
		}
	}
	if len(points) == 0 {
		return nil, ErrMCSConnection
	}
	return points, nil
}

type rdpBitmapSpan struct {
	X     uint16
	Y     uint16
	Width uint16
}

type rdpPolygonIntersection struct {
	x     float64 // Sort key; start retains exact integer pixel rounding.
	start int64   // ceil(x - 0.5), computed with integer arithmetic.
}

// rasterizeRDPPolygon converts an ALTERNATE-filled polygon into bounded
// horizontal pixel spans. Pixel centers are tested at (x+0.5, y+0.5), and
// horizontal edges are excluded so shared vertices are counted exactly once.
func rasterizeRDPPolygon(points [][2]uint16, fillMode byte, desktopWidth, desktopHeight uint16) ([]rdpBitmapSpan, [4]uint16, uint64, error) {
	var bounds [4]uint16
	if fillMode != 0x01 || len(points) < 3 || len(points) > maxRDPPolygonPoints+1 || desktopWidth == 0 || desktopHeight == 0 {
		return nil, bounds, 0, ErrMCSConnection
	}
	minX, minY := ^uint16(0), ^uint16(0)
	var maxX, maxY uint16
	for _, point := range points {
		if point[0] >= desktopWidth || point[1] >= desktopHeight {
			return nil, bounds, 0, ErrMCSConnection
		}
		minX, minY = min(minX, point[0]), min(minY, point[1])
		maxX, maxY = max(maxX, point[0]), max(maxY, point[1])
	}
	if minX == maxX || minY == maxY {
		return nil, bounds, 0, ErrMCSConnection
	}
	bounds = [4]uint16{minX, minY, maxX - minX + 1, maxY - minY + 1}
	spans := make([]rdpBitmapSpan, 0, min(int(maxY-minY)*(len(points)/2), maxRDPPolygonSpans))
	intersections := make([]rdpPolygonIntersection, 0, len(points))
	var totalPixels uint64
	for y := int64(minY); y < int64(maxY); y++ {
		scanYTwice := 2*y + 1
		intersections = intersections[:0]
		for i, first := range points {
			second := points[(i+1)%len(points)]
			y1, y2 := int64(first[1]), int64(second[1])
			dy := y2 - y1
			if dy == 0 || scanYTwice < min(2*y1, 2*y2) || scanYTwice >= max(2*y1, 2*y2) {
				continue
			}
			x1, x2 := int64(first[0]), int64(second[0])
			dx := x2 - x1
			numerator := 2*x1*dy + (scanYTwice-2*y1)*dx
			denominator := 2 * dy
			startNumerator := numerator - dy
			if denominator < 0 {
				numerator, denominator, startNumerator = -numerator, -denominator, -startNumerator
			}
			intersections = append(intersections, rdpPolygonIntersection{
				x: float64(numerator) / float64(denominator), start: ceilRDPDivision(startNumerator, denominator),
			})
		}
		if len(intersections)%2 != 0 {
			return nil, [4]uint16{}, 0, ErrMCSConnection
		}
		sort.Slice(intersections, func(i, j int) bool { return intersections[i].x < intersections[j].x })
		for i := 0; i < len(intersections); i += 2 {
			left, right := intersections[i].start, intersections[i+1].start
			if left < 0 || right > int64(desktopWidth) || right < left {
				return nil, [4]uint16{}, 0, ErrMCSConnection
			}
			if right == left {
				continue
			}
			if len(spans) >= maxRDPPolygonSpans || uint64(right-left) > maxRDPDesktopArea-totalPixels {
				return nil, [4]uint16{}, 0, ErrMCSConnection
			}
			spans = append(spans, rdpBitmapSpan{X: uint16(left), Y: uint16(y), Width: uint16(right - left)})
			totalPixels += uint64(right - left)
		}
	}
	if len(spans) == 0 || totalPixels == 0 {
		return nil, [4]uint16{}, 0, ErrMCSConnection
	}
	return spans, bounds, totalPixels, nil
}

func ceilRDPDivision(numerator, denominator int64) int64 {
	if numerator >= 0 {
		return (numerator + denominator - 1) / denominator
	}
	return numerator / denominator // Go truncates toward zero, which is ceil for negative values.
}

// rasterizeRDPEllipse rasterizes an inclusive bounding rectangle using pixel
// centers. The returned spans are bounded to the desktop and contain only the
// pixels inside the filled ellipse.
func rasterizeRDPEllipse(left, top, width, height, desktopWidth, desktopHeight uint16) ([]rdpBitmapSpan, [4]uint16, uint64, error) {
	var bounds [4]uint16
	if width == 0 || height == 0 || uint32(left)+uint32(width) > uint32(desktopWidth) ||
		uint32(top)+uint32(height) > uint32(desktopHeight) {
		return nil, bounds, 0, ErrMCSConnection
	}
	bounds = [4]uint16{left, top, width, height}
	widthSquared, heightSquared := uint64(width)*uint64(width), uint64(height)*uint64(height)
	centerXTwice := 2*int64(left) + int64(width)
	centerYTwice := 2*int64(top) + int64(height)
	spans := make([]rdpBitmapSpan, 0, int(height))
	var totalPixels uint64
	for y := int64(top); y < int64(top)+int64(height); y++ {
		deltaYTwice := 2*y + 1 - centerYTwice
		absoluteY := deltaYTwice
		if absoluteY < 0 {
			absoluteY = -absoluteY
		}
		if absoluteY >= int64(height) {
			continue
		}
		remaining := heightSquared - uint64(absoluteY)*uint64(absoluteY)
		radiusNumerator := widthSquared * remaining
		maxDeltaXTwice := sqrtRDPUint64(radiusNumerator / heightSquared)
		leftNumerator := centerXTwice - int64(maxDeltaXTwice) - 1
		rightNumerator := centerXTwice + int64(maxDeltaXTwice) - 1
		xStart := ceilRDPDivision(leftNumerator, 2)
		xEnd := rightNumerator/2 + 1
		if xStart < int64(left) || xEnd > int64(left)+int64(width) || xEnd < xStart {
			return nil, [4]uint16{}, 0, ErrMCSConnection
		}
		if xEnd == xStart {
			continue
		}
		if uint64(xEnd-xStart) > maxRDPDesktopArea-totalPixels {
			return nil, [4]uint16{}, 0, ErrMCSConnection
		}
		spans = append(spans, rdpBitmapSpan{X: uint16(xStart), Y: uint16(y), Width: uint16(xEnd - xStart)})
		totalPixels += uint64(xEnd - xStart)
	}
	if len(spans) == 0 || totalPixels == 0 {
		return nil, [4]uint16{}, 0, ErrMCSConnection
	}
	return spans, bounds, totalPixels, nil
}

func sqrtRDPUint64(value uint64) uint64 {
	root := uint64(math.Sqrt(float64(value)))
	for (root+1)*(root+1) <= value {
		root++
	}
	for root*root > value {
		root--
	}
	return root
}

func absRDPInt32(value int32) int32 {
	if value < 0 {
		return -value
	}
	return value
}

func allZeroBytes(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func decodeRDPMultiDstBltRectangles(encoded []byte, count int) ([][4]int32, error) {
	if count < 1 || count > maxRDPMultiDstBltRects {
		return nil, ErrMCSConnection
	}
	zeroBytes := (count + 1) / 2
	if len(encoded) < zeroBytes {
		return nil, ErrMCSConnection
	}
	zeroBits := encoded[:zeroBytes]
	encoded = encoded[zeroBytes:]
	if count%2 != 0 && zeroBits[zeroBytes-1]&0x0f != 0 {
		return nil, ErrMCSConnection
	}
	rectangles := make([][4]int32, 0, count)
	var previous [4]int32
	for i := 0; i < count; i++ {
		var current [4]int32
		for component := 0; component < 4; component++ {
			bit := uint(7 - (i%2)*4 - component)
			var delta int32
			if zeroBits[i/2]&(1<<bit) == 0 {
				var err error
				delta, encoded, err = readRDPPackedSignedDelta(encoded)
				if err != nil {
					return nil, ErrMCSConnection
				}
			}
			if component < 2 {
				// Left and top are deltas from the preceding rectangle.
				current[component] = previous[component] + delta
			} else if zeroBits[i/2]&(1<<bit) != 0 {
				// An omitted width or height repeats the previous dimension.
				current[component] = previous[component]
			} else {
				// Width and height are values, not deltas.
				current[component] = delta
			}
		}
		if current[0] < 0 || current[1] < 0 || current[2] <= 0 || current[3] <= 0 {
			return nil, ErrMCSConnection
		}
		rectangles = append(rectangles, current)
		previous = current
	}
	if len(encoded) != 0 {
		return nil, ErrMCSConnection
	}
	return rectangles, nil
}

// readRDPPackedSignedDelta decodes the signed 7-bit or 15-bit integer used by
// DELTA_RECTS_FIELD. The high bit selects the two-byte representation.
func readRDPPackedSignedDelta(data []byte) (int32, []byte, error) {
	if len(data) == 0 {
		return 0, data, ErrMCSConnection
	}
	first := data[0]
	if first&0x80 == 0 {
		value := int32(first & 0x7f)
		if value&0x40 != 0 {
			value -= 0x80
		}
		return value, data[1:], nil
	}
	if len(data) < 2 {
		return 0, data, ErrMCSConnection
	}
	value := int32(first&0x7f)<<8 | int32(data[1])
	if value&0x4000 != 0 {
		value -= 0x8000
	}
	return value, data[2:], nil
}

func appendRDPPrimaryRectangle(result *RDPBitmapUpdate, totalPixels *uint64, left, top, width, height int32,
	desktopWidth, desktopHeight uint16, operation rdpBitmapRectangleOperation, red, green, blue byte,
	sourceX, sourceY int32) error {
	if result == nil || totalPixels == nil || left < 0 || top < 0 || width <= 0 || height <= 0 ||
		left+width > int32(desktopWidth) || top+height > int32(desktopHeight) ||
		operation == rdpBitmapRectangleScrCopy && (sourceX < 0 || sourceY < 0 ||
			sourceX+width > int32(desktopWidth) || sourceY+height > int32(desktopHeight)) ||
		len(result.Rectangles) >= maxRDPBitmapRects {
		return ErrMCSConnection
	}
	pixels := uint64(width) * uint64(height)
	if pixels > maxRDPDesktopArea || *totalPixels > maxRDPDesktopArea-pixels || pixels > uint64(int(^uint(0)>>1))/4 {
		return ErrMCSConnection
	}
	*totalPixels += pixels
	var rgba []byte
	if operation == rdpBitmapRectangleReplace || operation == rdpBitmapRectanglePatInvert ||
		operation == rdpBitmapRectanglePatAnd || operation == rdpBitmapRectanglePatOr {
		rgba = make([]byte, int(pixels)*4)
		for offset := 0; offset < len(rgba); offset += 4 {
			rgba[offset], rgba[offset+1], rgba[offset+2], rgba[offset+3] = red, green, blue, 0xff
		}
	}
	result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{
		X: uint16(left), Y: uint16(top), Width: uint16(width), Height: uint16(height), Pixels: rgba,
		operation: operation, sourceX: uint16(sourceX), sourceY: uint16(sourceY),
	})
	return nil
}

// parseRDPBitmapUpdateData decodes the shared bitmap-update body used by both
// slow-path TS_UPDATE and fast-path TS_FP_UPDATE_BITMAP.
func parseRDPBitmapUpdateData(payload []byte, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	return parseRDPBitmapUpdateDataAt(payload, desktopWidth, desktopHeight, 32)
}

// parseRDPBitmapUpdateDataAt decodes TS_UPDATE_BITMAP_DATA for a session of sessionBPP (15, 16 or
// 32, ADR-0086): every rectangle carries that depth. A bitmap may be wider or taller than its
// destination (Windows pads widths to four pixels): only the destination, its top-left part, is kept.
func parseRDPBitmapUpdateDataAt(payload []byte, desktopWidth, desktopHeight, sessionBPP uint16) (RDPBitmapUpdate, error) {
	var result RDPBitmapUpdate
	if sessionBPP != 15 && sessionBPP != 16 && sessionBPP != 32 {
		return result, ErrMCSConnection
	}
	if len(payload) < 2 || desktopWidth == 0 || desktopHeight == 0 ||
		uint64(desktopWidth)*uint64(desktopHeight) > maxRDPDesktopArea {
		return result, ErrMCSConnection
	}
	count := int(binary.LittleEndian.Uint16(payload[:2]))
	// A rectangle takes 18 header bytes and at least one of data: no more fit than the payload holds.
	if count == 0 || count > maxRDPBitmapUpdateRects || count > (len(payload)-2)/19 {
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
		if width == 0 || height == 0 || bpp != sessionBPP || (flags != 0 && flags != rdpBitmapCompressed && flags != rdpBitmapCompressed|rdpBitmapNoCompHdr) || bitmapLength == 0 || bitmapLength > len(payload) ||
			right < left || bottom < top {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		destWidth, destHeight := right-left+1, bottom-top+1
		// The bitmap may be wider than its destination by the padding to four pixels, and no more;
		// it is exactly as tall. A larger one would make the client decode what it never shows.
		if destWidth > width || uint32(width) > (uint32(destWidth)+3)&^3 || destHeight != height ||
			uint32(left)+uint32(destWidth) > uint32(desktopWidth) || uint32(top)+uint32(destHeight) > uint32(desktopHeight) {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		pixels := uint64(width) * uint64(height)
		if pixels > maxRDPDesktopArea || totalPixels > maxRDPDesktopArea-pixels {
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		totalPixels += pixels
		var decoded []byte
		switch {
		case sessionBPP != 32:
			var decodeErr error
			if flags == 0 {
				decoded, decodeErr = decodeRDPBitmapRaw16(payload[:bitmapLength], int(width), int(height), sessionBPP)
			} else {
				decoded, decodeErr = decodeRDPBitmapRLE16(payload[:bitmapLength], int(width), int(height), sessionBPP, flags&rdpBitmapNoCompHdr == 0)
			}
			if decodeErr != nil {
				return RDPBitmapUpdate{}, ErrMCSConnection
			}
		case flags == 0:
			if pixels*4 != uint64(bitmapLength) {
				return RDPBitmapUpdate{}, ErrMCSConnection
			}
			decoded = decodeRDPBitmapRaw(payload, int(width), int(height))
		default:
			var decodeErr error
			if flags&rdpBitmapNoCompHdr != 0 {
				decoded, decodeErr = decodeRDP6Bitmap(payload[:bitmapLength], int(width), int(height))
			} else {
				decoded, decodeErr = decodeRDP6BitmapWithHeader(payload[:bitmapLength], int(width), int(height))
			}
			if decodeErr != nil {
				return RDPBitmapUpdate{}, ErrMCSConnection
			}
		}
		decoded = cropRDPBitmap(decoded, int(width), int(destWidth), int(destHeight))
		result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{X: left, Y: top, Width: destWidth, Height: destHeight, Pixels: decoded})
		payload = payload[bitmapLength:]
	}
	if len(payload) != 0 {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	return result, nil
}

// shareDataType is the pduType2 of a Share Data PDU, 0 when it is too short to say.
func shareDataType(data []byte) byte {
	if len(data) < 15 {
		return 0
	}
	return data[14]
}

// cropRDPBitmap keeps the top-left destWidth x destHeight pixels of a top-down RGBA bitmap.
func cropRDPBitmap(rgba []byte, width, destWidth, destHeight int) []byte {
	if destWidth == width && len(rgba) == width*destHeight*4 {
		return rgba
	}
	out := make([]byte, destWidth*destHeight*4)
	for y := 0; y < destHeight; y++ {
		copy(out[y*destWidth*4:(y+1)*destWidth*4], rgba[y*width*4:y*width*4+destWidth*4])
	}
	clear(rgba)
	return out
}

const (
	rdpFastPathUpdateBitmap = byte(1)
	maxRDPFastPathPacket    = 0x7fff
)

// parseRDPFastPathBitmapUpdate accepts one unencrypted, unfragmented bitmap
// update. TLS is the security layer; fast-path RDP encryption and compression
// remain deliberately unsupported.
func parseRDPFastPathBitmapUpdate(packet []byte, desktopWidth, desktopHeight uint16) (RDPBitmapUpdate, error) {
	return parseRDPFastPathBitmapUpdateAt(packet, desktopWidth, desktopHeight, 32)
}

func parseRDPFastPathBitmapUpdateAt(packet []byte, desktopWidth, desktopHeight, sessionBPP uint16) (RDPBitmapUpdate, error) {
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
	// TS_UPDATE_BITMAP_DATA starts with its updateType, as in the slow path.
	if size < 2 || size != len(data) || binary.LittleEndian.Uint16(data[:2]) != rdpUpdateBitmap {
		return empty, ErrMCSConnection
	}
	return parseRDPBitmapUpdateDataAt(data[2:], desktopWidth, desktopHeight, sessionBPP)
}

// rdpFastPathUpdateIsIgnored recognizes the updates that show nothing in the screen stream: the
// pointer, which the operator's browser draws itself, and the frame synchronization. The list is
// closed: any other code goes on to be refused, and a fragment is not judged by its first piece.
func rdpFastPathUpdateIsIgnored(packet []byte) bool {
	offset := 2
	if len(packet) > 1 && packet[1]&0x80 != 0 {
		offset = 3
	}
	if len(packet) < offset+3 || packet[offset]>>4 != 0 {
		return false
	}
	if int(binary.LittleEndian.Uint16(packet[offset+1:offset+3])) != len(packet)-offset-3 {
		return false
	}
	switch packet[offset] & 0x0f {
	case 0x3, // synchronize
		0x5, // pointer hidden
		0x6, // pointer default
		0x8, // pointer position
		0x9, // pointer color
		0xa, // pointer cached
		0xb: // pointer new
		return true
	}
	return false
}

// rdpShareDataIsIgnored does the same for a Share Data PDU of this share that carries no graphics:
// the pointer, keyboard indicators, session information, and the reason a server gives before it
// disconnects, which closes the stream by itself.
func rdpShareDataIsIgnored(data []byte, shareID uint32) bool {
	if len(data) < 18 || int(binary.LittleEndian.Uint16(data[0:2])) != len(data) ||
		binary.LittleEndian.Uint16(data[2:4]) != rdpShareDataPDU ||
		binary.LittleEndian.Uint32(data[6:10]) != shareID || data[15] != 0 {
		return false
	}
	switch data[14] {
	case 0x1b, // pointer
		0x26, // save session info
		0x29, // set keyboard indicators
		0x2a, // set keyboard IME status
		0x2f: // set error info
		return true
	}
	return false
}

// rdpShareDataIsLogonNotification recognizes, in a Share Data PDU already found to be of this
// share, a Save Session Info that says the user logged on: INFOTYPE_LOGON (0), INFOTYPE_LOGON_LONG
// (1) or INFOTYPE_LOGON_PLAINNOTIFY (2). Extended logon information (3) is not a logon.
func rdpShareDataIsLogonNotification(data []byte) bool {
	if len(data) < 22 || data[14] != 0x26 {
		return false
	}
	return binary.LittleEndian.Uint32(data[18:22]) <= 2
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
	// formatHeader, low bits first (MS-RDPEGDI 2.2.2.5.1): CLL in bits 0-2, then CS, RLE, NA.
	rdp6FormatColorLossMask     = byte(0x07)
	rdp6FormatChromaSubsampling = byte(0x08)
	rdp6FormatRLE               = byte(0x10)
	rdp6FormatNoAlpha           = byte(0x20)
	rdp6FormatReservedMask      = byte(0xc0)
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
		(int(binary.LittleEndian.Uint16(data[4:6])) != width && int(binary.LittleEndian.Uint16(data[4:6])) != width*4) ||
		uint64(binary.LittleEndian.Uint16(data[6:8])) != decodedBytes {
		return nil, ErrMCSConnection
	}
	return decodeRDP6Bitmap(data[8:], width, height)
}

// decodeRDP6Bitmap decodes the planes alone: announcing NO_BITMAP_COMPRESSION_HDR, this client does
// not depend on what bitmapLength counts when a header is present, where FreeRDP and the
// specification differ.
func decodeRDP6Bitmap(stream []byte, width, height int) ([]byte, error) {
	if width <= 0 || height <= 0 || len(stream) == 0 {
		return nil, ErrMCSConnection
	}
	pixels := uint64(width) * uint64(height)
	decodedBytes := pixels * 4
	if pixels > maxRDPDesktopArea || decodedBytes > uint64(^uint16(0)) {
		return nil, ErrMCSConnection
	}
	format := stream[0]
	// CLL selects ARGB (zero) or AYCoCg (1..7). Chroma subsampling is
	// defined only for AYCoCg; reserved bits must always be zero.
	colorLossLevel := int(format & rdp6FormatColorLossMask)
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
		// The alpha plane, when sent, is read and bounded like the others, and not shown: a remote
		// desktop is opaque, and Windows sends its 32-bpp screen with an alpha plane of zeros
		// (ADR-0071, CI run #46: drawn as sent, the screen was transparent, and white).
		plane := 0
		if !noAlpha {
			plane = 1
		}
		decoded[dst+3] = 0xff
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
		// A run repeats the last raw value of this line, whichever segment gave it; 0 before any.
		var value byte
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
				value = plane[rowStart+column-1]
			}
			if runCount > width-column {
				return nil, 0, ErrMCSConnection
			}
			if runCount > 0 {
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

// countingReader counts the bytes read through it.
type countingReader struct {
	reader io.Reader
	count  *atomic.Uint64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.count.Add(uint64(n))
	return n, err
}

// ServerBytes is the number of bytes of updates the target has sent since the connection was
// finalized, as read from TLS (record payloads, not their framing): the throughput ADR-0090 (lot A)
// measures. A reactivation's exchange is not counted.
func (s *CredSSPClientSession) ServerBytes() uint64 {
	if s == nil {
		return 0
	}
	return s.serverBytes.Load()
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
	// What the target sends, counted for the measurements of ADR-0090 (lot A).
	counted := countingReader{reader: conn, count: &s.serverBytes}
	ioChannelID := s.mcsResponse.IOChannelID
	var shareID uint32
	var desktopWidth, desktopHeight, sessionBPP uint16
	var orderState rdpPrimaryOrderState
	// What a reactivation changes, read again after one; s.mu is held.
	loadShare := func() {
		shareID = s.serverCapabilities.ShareID
		desktopWidth, desktopHeight = s.serverCapabilities.DesktopWidth, s.serverCapabilities.DesktopHeight
		sessionBPP = s.serverCapabilities.PreferredBitsPerPixel
		if sessionBPP == 0 {
			// Only a session built by hand has none: ExchangeCapabilities always sets a validated 15, 16
			// or 32. Without it, the depth this client asks for.
			sessionBPP = 32
		}
		orderState = s.primaryOrderState
	}
	loadShare()
	pointerShapes := s.mcsSettings.PointerShapes
	// The static channels joined (ADR-0095): their data goes to its channel, not to the screen.
	staticChannels := s.mcsResponse.StaticChannelIDs
	reactivated := false
	primaryOrdersEnabled := s.primaryOrdersEnabled
	patBltOpaqueRectEnabled := s.patBltOpaqueRectEnabled
	dstBltEnabled := s.dstBltEnabled
	scrBltEnabled := s.scrBltEnabled
	multiDstBltEnabled := s.multiDstBltEnabled
	multiPatBltEnabled := s.multiPatBltEnabled
	multiScrBltEnabled := s.multiScrBltEnabled
	lineToEnabled := s.lineToEnabled
	polylineEnabled := s.polylineEnabled
	polygonSCEnabled := s.polygonSCEnabled
	ellipseSCEnabled := s.ellipseSCEnabled
	multiOpaqueRectEnabled := s.multiOpaqueRectEnabled
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
			if !errors.Is(err, ErrMCSConnection) && !errors.Is(err, ErrSessionEnded) {
				err = ErrMCSConnection // a described refusal keeps its description, an end says it is one
			}
			update = RDPBitmapUpdate{}
			return
		}
		if setErr := conn.SetReadDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.mu.Lock()
			s.closeTransportLocked()
			s.mu.Unlock()
			err = ErrMCSConnection
			update = RDPBitmapUpdate{}
			return
		}
		update.DesktopWidth, update.DesktopHeight = desktopWidth, desktopHeight
		update.Reactivated = reactivated
	}()

readUpdate:
	// What the channels sent during a finalization, first, in the order it came.
	if pending := s.takePendingChannelPacket(); pending != nil {
		_, channelErr := s.readChannelPacket(pending, staticChannels)
		clear(pending)
		if channelErr != nil {
			return RDPBitmapUpdate{}, fmt.Errorf("%w: %w", ErrMCSConnection, channelErr)
		}
		goto readUpdate
	}
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
			// A Fast-Path PDU is up to 0x7fff bytes (a 15-bit length): Windows fills it past
			// 16 383 (CI run #46). A TPKT stays bounded by parseRDPBitmapMCSFragment.
			packet, fastPath, readErr = readRDPServerUpdatePacket(counted, maxRDPFastPathPacket)
			if readErr == nil && fastPath {
				// One update per PDU, whole or in fragments (FIRST, NEXT..., LAST of one code),
				// reassembled to the size this client announced, then shown or ignored.
				var assembler rdpFastPathAssembler
				var code byte
				var data []byte
				for complete := false; !complete; {
					var fragmentation byte
					var piece []byte
					code, fragmentation, piece, err = splitRDPFastPathUpdate(packet)
					if err == nil {
						data, complete, err = assembler.add(code, fragmentation, piece)
					}
					if err != nil {
						described := fmt.Errorf("%w: update refused: %s: %v", ErrMCSConnection, describeRDPServerPacket(packet), err)
						clear(packet)
						return RDPBitmapUpdate{}, described
					}
					if !complete {
						clear(packet)
						var nextFastPath bool
						packet, nextFastPath, readErr = readRDPServerUpdatePacket(counted, maxRDPFastPathPacket)
						if readErr != nil || !nextFastPath || ctx.Err() != nil {
							clear(packet)
							if errors.Is(readErr, ErrMCSConnection) {
								return RDPBitmapUpdate{}, readErr
							}
							return RDPBitmapUpdate{}, fmt.Errorf("%w: a Fast-Path update interrupted mid-fragments", ErrMCSConnection)
						}
					}
				}
				if pointerShapes && rdpFastPathCodeIsPointer(code) {
					pointer, pointerErr := parseRDPFastPathPointer(code, data)
					if pointerErr != nil {
						described := fmt.Errorf("%w: pointer update refused: %s, %s", ErrRDPPointer, describeRDPServerPacket(packet), describeRDPPointerHeader(code, data))
						clear(packet)
						return RDPBitmapUpdate{}, described
					}
					clear(packet)
					return RDPBitmapUpdate{Pointer: &pointer}, nil
				}
				if rdpFastPathCodeIsIgnored(code) {
					clear(packet)
					goto readUpdate
				}
				// TS_UPDATE_BITMAP_DATA starts with its updateType, as in the slow path.
				if code != rdpFastPathUpdateBitmap || len(data) < 2 || binary.LittleEndian.Uint16(data[:2]) != rdpUpdateBitmap {
					described := fmt.Errorf("%w: update refused: %s", ErrMCSConnection, describeRDPServerPacket(packet))
					clear(packet)
					return RDPBitmapUpdate{}, described
				}
				update, err = parseRDPBitmapUpdateDataAt(data[2:], desktopWidth, desktopHeight, sessionBPP)
				if err != nil {
					// Which rectangle, against which desktop (CI of PR #157, Windows Server 2019: a
					// bitmap update refused after a resize, and the message did not say why).
					described := fmt.Errorf("%w: update refused: %s: %v; on a %dx%d desktop at %d bpp: %s", ErrMCSConnection,
						describeRDPServerPacket(packet), err, desktopWidth, desktopHeight, sessionBPP, describeRDPBitmapRectangles(data[2:]))
					clear(packet)
					return RDPBitmapUpdate{}, described
				}
				clear(packet)
				if ctx.Err() != nil {
					return RDPBitmapUpdate{}, ErrMCSConnection
				}
				return update, nil
			}
		} else {
			packet, readErr = readTPKTPacket(counted, maxRDPBitmapTPKTPacket)
		}
		if readErr != nil {
			clear(assembled)
			if errors.Is(readErr, ErrMCSConnection) {
				return RDPBitmapUpdate{}, readErr // what the read refused, said
			}
			return RDPBitmapUpdate{}, ErrMCSConnection
		}
		if fragmentCount == 0 && rdpIsDisconnectUltimatum(packet) {
			clear(packet)
			return RDPBitmapUpdate{}, ErrSessionEnded
		}
		if onChannel, channelErr := s.readChannelPacket(packet, staticChannels); channelErr != nil || onChannel {
			clear(packet)
			if channelErr != nil {
				clear(assembled)
				return RDPBitmapUpdate{}, fmt.Errorf("%w: %w", ErrMCSConnection, channelErr)
			}
			if fragmentCount == 0 {
				goto readUpdate
			}
			continue
		}
		fragment, segmentation, fragmentErr := parseRDPBitmapMCSFragment(packet, ioChannelID)
		if fragmentErr != nil {
			// Said, not bare: a reconnection to Windows ended here with nothing to go on (ADR-0071).
			described := fmt.Errorf("%w: update refused: %s", ErrMCSConnection, describeRDPServerPacket(packet))
			clear(packet)
			clear(assembled)
			return RDPBitmapUpdate{}, described
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
	if rdpIsDeactivateAll(assembled) {
		err = s.reactivate(ctx, conn, assembled, deadline)
		clear(assembled)
		if err != nil {
			return RDPBitmapUpdate{}, err
		}
		s.mu.Lock()
		loadShare()
		s.mu.Unlock()
		reactivated = true
		goto readUpdate
	}
	if pointerShapes && rdpShareDataIsIgnored(assembled, shareID) && assembled[14] == rdpPDU2Pointer {
		pointer, pointerErr := parseRDPPointerPDU(assembled[18:])
		clear(assembled)
		if pointerErr != nil {
			return RDPBitmapUpdate{}, fmt.Errorf("%w: slow-path pointer update refused", ErrRDPPointer)
		}
		return RDPBitmapUpdate{Pointer: &pointer}, nil
	}
	if rdpShareDataIsIgnored(assembled, shareID) {
		if rdpShareDataIsLogonNotification(assembled) {
			s.mu.Lock()
			s.logonNotified = true
			s.mu.Unlock()
		}
		clear(assembled)
		goto readUpdate
	}
	defer clear(assembled)
	if len(assembled) >= 20 && binary.LittleEndian.Uint16(assembled[18:20]) == rdpUpdateOrders && !primaryOrdersEnabled {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	var nextOrderState rdpPrimaryOrderState
	update, nextOrderState, err = parseRDPBitmapShareDataAt(assembled, shareID, desktopWidth, desktopHeight, sessionBPP, orderState)
	if err != nil {
		return RDPBitmapUpdate{}, fmt.Errorf("%w: update refused: share data of %d bytes, pduType2 0x%02x", ErrMCSConnection, len(assembled), shareDataType(assembled))
	}
	if ctx.Err() != nil ||
		nextOrderState.dstBltUsed && !dstBltEnabled ||
		nextOrderState.patBltOpaqueRectUsed && !patBltOpaqueRectEnabled ||
		nextOrderState.scrBltUsed && !scrBltEnabled ||
		nextOrderState.multiDstBltUsed && !multiDstBltEnabled ||
		nextOrderState.multiPatBltUsed && !multiPatBltEnabled ||
		nextOrderState.multiScrBltUsed && !multiScrBltEnabled ||
		nextOrderState.lineToUsed && !lineToEnabled ||
		nextOrderState.polylineUsed && !polylineEnabled ||
		nextOrderState.polygonSCUsed && !polygonSCEnabled ||
		nextOrderState.ellipseSCUsed && !ellipseSCEnabled ||
		nextOrderState.multiOpaqueRectUsed && !multiOpaqueRectEnabled {
		return RDPBitmapUpdate{}, ErrMCSConnection
	}
	s.mu.Lock()
	s.primaryOrderState = nextOrderState
	s.mu.Unlock()
	return update, nil
}

// rdpIsDisconnectUltimatum recognizes an MCS Disconnect Provider Ultimatum (T.125 choice 8, its
// reason in the low bits): how a server ends a session (ADR-0071 §3, "Fin"). The whole TPKT is
// that PDU and nothing else.
func rdpIsDisconnectUltimatum(packet []byte) bool {
	return len(packet) == 9 && packet[0] == 3 && packet[1] == 0 && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet) &&
		equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) && packet[7]&0xfc == 0x20
}

// describeRDPBitmapRectangles names the first rectangles of a TS_UPDATE_BITMAP_DATA, without their
// pixels: where each goes, its size, depth, flags and length. For a refusal's message.
func describeRDPBitmapRectangles(data []byte) string {
	if len(data) < 2 {
		return "no rectangle count"
	}
	count := int(binary.LittleEndian.Uint16(data[:2]))
	out := fmt.Sprintf("%d rectangle(s)", count)
	rest := data[2:]
	for i := 0; i < count && i < 3; i++ {
		if len(rest) < 18 {
			return out + ", cut short"
		}
		left, top := binary.LittleEndian.Uint16(rest[0:2]), binary.LittleEndian.Uint16(rest[2:4])
		right, bottom := binary.LittleEndian.Uint16(rest[4:6]), binary.LittleEndian.Uint16(rest[6:8])
		width, height := binary.LittleEndian.Uint16(rest[8:10]), binary.LittleEndian.Uint16(rest[10:12])
		bpp, flags := binary.LittleEndian.Uint16(rest[12:14]), binary.LittleEndian.Uint16(rest[14:16])
		length := int(binary.LittleEndian.Uint16(rest[16:18]))
		out += fmt.Sprintf("; [%d] dest %d,%d-%d,%d size %dx%d %d bpp flags 0x%04x length %d", i, left, top, right, bottom, width, height, bpp, flags, length)
		if len(rest) < 18+length {
			return out + ", cut short"
		}
		rest = rest[18+length:]
	}
	return out
}

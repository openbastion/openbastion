package rdp

import (
	"encoding/binary"
	"math"
)

const (
	rdpOrderSecondary                     = byte(0x02)
	rdpOrderMemBlt                        = byte(0x0d)
	rdpOrderMem3Blt                       = byte(0x0e)
	rdpCacheBitmapUncompressedRev2        = byte(0x04)
	rdpCacheBitmapCompressedRev2          = byte(0x05)
	rdpCacheBitmapCompressedRev3          = byte(0x08)
	rdpCacheBitmapRev2CacheID             = uint16(0)
	rdpCacheBitmapRev2BitsPerPixel32      = uint16(6)
	rdpCacheBitmapRev2HeightSame          = uint16(0x001)
	rdpCacheBitmapRev2PersistentKey       = uint16(0x002)
	rdpCacheBitmapRev2NoCompressionHeader = uint16(0x008)
	rdpCacheBitmapRev2DoNotCache          = uint16(0x010)
	rdpCacheBitmapRev3DoNotCache          = uint16(0x010)
	rdpCacheBitmapRev3Ignorable           = uint16(0x008)
	rdpBitmapCacheEntries                 = 256
	maxRDPBitmapCacheEntryBytes           = 16 << 20
	maxRDPBitmapCacheBytes                = 32 << 20
)

type rdpCachedBitmap struct {
	width  uint16
	height uint16
	pixels []byte // immutable top-down RGBA; cache replacements install a new slice
}

type rdpBitmapCacheState struct {
	entries map[uint16]rdpCachedBitmap
	bytes   uint64
}

func cloneRDPPrimaryOrderState(in rdpPrimaryOrderState) rdpPrimaryOrderState {
	if in.cache == nil {
		return in
	}
	cache := &rdpBitmapCacheState{entries: make(map[uint16]rdpCachedBitmap, len(in.cache.entries)), bytes: in.cache.bytes}
	for index, entry := range in.cache.entries {
		cache.entries[index] = entry
	}
	in.cache = cache
	return in
}

func clearRDPBitmapCacheState(state *rdpPrimaryOrderState) {
	if state == nil || state.cache == nil {
		return
	}
	for index, entry := range state.cache.entries {
		clear(entry.pixels)
		delete(state.cache.entries, index)
	}
	state.cache.bytes = 0
	state.cache = nil
}

func readRDPUnsigned16(data []byte) (uint16, []byte, error) {
	if len(data) < 1 {
		return 0, data, ErrMCSConnection
	}
	first := data[0]
	if first&0x80 == 0 {
		return uint16(first), data[1:], nil
	}
	if len(data) < 2 {
		return 0, data, ErrMCSConnection
	}
	return uint16(first&0x7f)<<8 | uint16(data[1]), data[2:], nil
}

func readRDPUnsigned32(data []byte) (uint32, []byte, error) {
	if len(data) < 1 {
		return 0, data, ErrMCSConnection
	}
	first := data[0]
	count := int(first>>6) + 1
	if len(data) < count {
		return 0, data, ErrMCSConnection
	}
	value := uint32(first & 0x3f)
	for i := 1; i < count; i++ {
		value = value<<8 | uint32(data[i])
	}
	return value, data[count:], nil
}

// parseRDPSecondaryOrder consumes one length-delimited secondary order. The
// historical +13 adjustment is applied before any field is read.
func parseRDPSecondaryOrder(data []byte, state *rdpPrimaryOrderState, sessionBPP uint16) ([]byte, error) {
	if state == nil || len(data) < 5 {
		return data, ErrMCSConnection
	}
	encodedLength := int(binary.LittleEndian.Uint16(data[:2]))
	orderLength := encodedLength + 13
	if orderLength < 6 || orderLength-1 > len(data) {
		return data, ErrMCSConnection
	}
	order := data[:orderLength-1] // controlFlags was consumed by the caller
	extraFlags := binary.LittleEndian.Uint16(order[2:4])
	orderType := order[4]
	body := order[5:]
	var err error
	switch orderType {
	case rdpCacheBitmapUncompressedRev2, rdpCacheBitmapCompressedRev2:
		err = parseRDPCacheBitmapRev2(body, extraFlags, orderType, sessionBPP, state)
	case rdpCacheBitmapCompressedRev3:
		err = parseRDPCacheBitmapRev3(body, extraFlags, sessionBPP, state)
	default:
		err = ErrMCSConnection
	}
	if err != nil {
		return data, ErrMCSConnection
	}
	return data[orderLength-1:], nil
}

func parseRDPCacheBitmapRev2(data []byte, extraFlags uint16, orderType byte, sessionBPP uint16, state *rdpPrimaryOrderState) error {
	cacheID := extraFlags & 0x0007
	bppID := (extraFlags >> 3) & 0x000f
	flags := extraFlags >> 7
	if cacheID != rdpCacheBitmapRev2CacheID || bppID != rdpCacheBitmapRev2BitsPerPixel32 || sessionBPP != 32 ||
		flags&^(rdpCacheBitmapRev2HeightSame|rdpCacheBitmapRev2NoCompressionHeader) != 0 ||
		flags&rdpCacheBitmapRev2PersistentKey != 0 || flags&rdpCacheBitmapRev2DoNotCache != 0 ||
		orderType == rdpCacheBitmapUncompressedRev2 && flags&rdpCacheBitmapRev2NoCompressionHeader != 0 {
		return ErrMCSConnection
	}
	width, rest, err := readRDPUnsigned16(data)
	if err != nil || width == 0 {
		return ErrMCSConnection
	}
	data = rest
	height := width
	if flags&rdpCacheBitmapRev2HeightSame == 0 {
		height, data, err = readRDPUnsigned16(data)
		if err != nil || height == 0 {
			return ErrMCSConnection
		}
	}
	bitmapLength, rest, err := readRDPUnsigned32(data)
	if err != nil || bitmapLength == 0 || bitmapLength > maxRDPBitmapCacheEntryBytes {
		return ErrMCSConnection
	}
	data = rest
	cacheIndex, rest, err := readRDPUnsigned16(data)
	if err != nil || cacheIndex >= rdpBitmapCacheEntries {
		return ErrMCSConnection
	}
	data = rest
	if uint64(width)*uint64(height)*4 > maxRDPBitmapCacheEntryBytes || int(bitmapLength) != len(data) {
		return ErrMCSConnection
	}
	var pixels []byte
	if orderType == rdpCacheBitmapUncompressedRev2 {
		if uint64(width)*uint64(height)*4 != uint64(bitmapLength) {
			return ErrMCSConnection
		}
		pixels = decodeRDPBitmapRaw(data, int(width), int(height))
	} else if flags&rdpCacheBitmapRev2NoCompressionHeader != 0 {
		pixels, err = decodeRDP6Bitmap(data, int(width), int(height))
	} else {
		pixels, err = decodeRDP6BitmapWithHeader(data, int(width), int(height))
	}
	if err != nil || len(pixels) == 0 {
		clear(pixels)
		return ErrMCSConnection
	}
	return storeRDPBitmapCache(state, cacheIndex, width, height, pixels)
}

func parseRDPCacheBitmapRev3(data []byte, extraFlags uint16, sessionBPP uint16, state *rdpPrimaryOrderState) error {
	cacheID := extraFlags & 0x0007
	bppID := (extraFlags >> 3) & 0x000f
	flags := extraFlags >> 7
	if cacheID != 0 || bppID != rdpCacheBitmapRev2BitsPerPixel32 || sessionBPP != 32 ||
		flags&^rdpCacheBitmapRev3Ignorable != 0 || flags&rdpCacheBitmapRev3DoNotCache != 0 || len(data) < 2+8+12 {
		return ErrMCSConnection
	}
	cacheIndex := binary.LittleEndian.Uint16(data[:2])
	if cacheIndex >= rdpBitmapCacheEntries {
		return ErrMCSConnection
	}
	// Both 32-bit halves of the mandatory revision-3 key are consumed. This
	// in-memory-only profile does not persist or reuse the key across sessions.
	_ = binary.LittleEndian.Uint32(data[2:6])
	_ = binary.LittleEndian.Uint32(data[6:10])
	bitmap := data[10:]
	if bitmap[0] != 32 || bitmap[1] != 0 || bitmap[2] != 0 || bitmap[3] != 0 {
		return ErrMCSConnection
	}
	width := binary.LittleEndian.Uint16(bitmap[4:6])
	height := binary.LittleEndian.Uint16(bitmap[6:8])
	bitmapLength := binary.LittleEndian.Uint32(bitmap[8:12])
	if width == 0 || height == 0 || uint64(width)*uint64(height)*4 > maxRDPBitmapCacheEntryBytes ||
		uint64(bitmapLength) != uint64(width)*uint64(height)*4 || int(bitmapLength) != len(bitmap)-12 {
		return ErrMCSConnection
	}
	pixels := decodeRDPBitmapRaw(bitmap[12:], int(width), int(height))
	return storeRDPBitmapCache(state, cacheIndex, width, height, pixels)
}

func storeRDPBitmapCache(state *rdpPrimaryOrderState, index, width, height uint16, pixels []byte) error {
	if state == nil || index >= rdpBitmapCacheEntries || width == 0 || height == 0 ||
		len(pixels) == 0 || len(pixels) > maxRDPBitmapCacheEntryBytes ||
		uint64(len(pixels)) != uint64(width)*uint64(height)*4 {
		clear(pixels)
		return ErrMCSConnection
	}
	if state.cache == nil {
		state.cache = &rdpBitmapCacheState{entries: make(map[uint16]rdpCachedBitmap)}
	}
	previous, exists := state.cache.entries[index]
	previousBytes := uint64(len(previous.pixels))
	if !exists && len(state.cache.entries) >= rdpBitmapCacheEntries || state.cache.bytes < previousBytes ||
		state.cache.bytes-previousBytes > maxRDPBitmapCacheBytes ||
		uint64(len(pixels)) > maxRDPBitmapCacheBytes-(state.cache.bytes-previousBytes) {
		clear(pixels)
		return ErrMCSConnection
	}
	state.cache.entries[index] = rdpCachedBitmap{width: width, height: height, pixels: pixels}
	state.cache.bytes = state.cache.bytes - previousBytes + uint64(len(pixels))
	return nil
}

func cachedRDPBitmap(state *rdpPrimaryOrderState, cacheID, cacheIndex uint16) (rdpCachedBitmap, error) {
	if state == nil || cacheID != 0 || state.cache == nil {
		return rdpCachedBitmap{}, ErrMCSConnection
	}
	entry, ok := state.cache.entries[cacheIndex]
	if !ok || entry.width == 0 || entry.height == 0 || len(entry.pixels) != int(entry.width)*int(entry.height)*4 {
		return rdpCachedBitmap{}, ErrMCSConnection
	}
	return entry, nil
}

func rdpROP3DependsOnPattern(rop byte) bool {
	return (rop & 0x0f) != ((rop >> 4) & 0x0f)
}

func parseRDPMemBltOrder(data []byte, control byte, state *rdpPrimaryOrderState, result *RDPBitmapUpdate,
	totalPixels *uint64, desktopWidth, desktopHeight uint16) ([]byte, error) {
	const allowed = rdpOrderStandard | rdpOrderTypeChange | rdpOrderBounds | rdpOrderDeltaCoordinates |
		rdpOrderZeroBoundsDeltas | rdpOrderZeroFieldByteMask
	if state == nil || result == nil || totalPixels == nil || control&^allowed != 0 ||
		control&rdpOrderZeroBoundsDeltas != 0 && control&rdpOrderBounds == 0 {
		return data, ErrMCSConnection
	}
	flags, rest, err := readRDPPrimaryFieldFlags(data, 9, control)
	if err != nil {
		return data, ErrMCSConnection
	}
	data = rest
	var bounds *[4]int32
	if control&rdpOrderBounds != 0 {
		if control&rdpOrderZeroBoundsDeltas == 0 {
			state.bounds, data, err = readRDPPrimaryBounds(data, state.bounds)
			if err != nil {
				return data, ErrMCSConnection
			}
		}
		bounds = &state.bounds
	}
	fields := state.memBltFields
	delta := control&rdpOrderDeltaCoordinates != 0
	for field := 0; field < 9; field++ {
		if flags&(1<<field) == 0 {
			continue
		}
		switch field {
		case 0, 8:
			if len(data) < 2 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(binary.LittleEndian.Uint16(data[:2]))
			data = data[2:]
		case 1, 2, 3, 4, 6, 7:
			fields[field], data, err = readRDPPrimaryCoord(data, fields[field], delta)
			if err != nil {
				return data, ErrMCSConnection
			}
		case 5:
			if len(data) < 1 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(data[0])
			data = data[1:]
		}
	}
	entry, err := cachedRDPBitmap(state, uint16(fields[0]), uint16(fields[8]))
	if err != nil || fields[0]>>8 != 0 || fields[1] < math.MinInt16 || fields[1] > math.MaxInt16 ||
		fields[2] < math.MinInt16 || fields[2] > math.MaxInt16 || fields[3] <= 0 || fields[4] <= 0 ||
		fields[5] < 0 || fields[5] > 255 || rdpROP3DependsOnPattern(byte(fields[5])) {
		return data, ErrMCSConnection
	}
	sourceX := fields[6]
	sourceY := int32(entry.height) - fields[4] - fields[7]
	if sourceX < 0 || sourceY < 0 || sourceX+fields[3] > int32(entry.width) || sourceY+fields[4] > int32(entry.height) {
		return data, ErrMCSConnection
	}
	if byte(fields[5]) != 0xaa { // DSTCOPY is a protocol no-op; still validate and commit its field state.
		if err := appendRDPCachedBitmapOperation(result, totalPixels, entry, fields[1], fields[2], fields[3], fields[4], sourceX, sourceY,
			byte(fields[5]), [4]byte{0, 0, 0, 0xff}, bounds, desktopWidth, desktopHeight); err != nil {
			return data, err
		}
	}
	state.memBltFields = fields
	state.memBltUsed = true
	return data, nil
}

func parseRDPMem3BltOrder(data []byte, control byte, state *rdpPrimaryOrderState, result *RDPBitmapUpdate,
	totalPixels *uint64, desktopWidth, desktopHeight uint16) ([]byte, error) {
	const allowed = rdpOrderStandard | rdpOrderTypeChange | rdpOrderBounds | rdpOrderDeltaCoordinates |
		rdpOrderZeroBoundsDeltas | rdpOrderZeroFieldByteMask
	if state == nil || result == nil || totalPixels == nil || control&^allowed != 0 ||
		control&rdpOrderZeroBoundsDeltas != 0 && control&rdpOrderBounds == 0 {
		return data, ErrMCSConnection
	}
	flags, rest, err := readRDPPrimaryFieldFlags(data, 16, control)
	if err != nil {
		return data, ErrMCSConnection
	}
	data = rest
	var bounds *[4]int32
	if control&rdpOrderBounds != 0 {
		if control&rdpOrderZeroBoundsDeltas == 0 {
			state.bounds, data, err = readRDPPrimaryBounds(data, state.bounds)
			if err != nil {
				return data, ErrMCSConnection
			}
		}
		bounds = &state.bounds
	}
	fields := state.mem3BltFields
	delta := control&rdpOrderDeltaCoordinates != 0
	for field := 0; field < 16; field++ {
		if flags&(1<<field) == 0 {
			continue
		}
		switch {
		case field == 0 || field == 15:
			if len(data) < 2 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(binary.LittleEndian.Uint16(data[:2]))
			data = data[2:]
		case field >= 1 && field <= 4 || field == 6 || field == 7:
			fields[field], data, err = readRDPPrimaryCoord(data, fields[field], delta)
			if err != nil {
				return data, ErrMCSConnection
			}
		case field == 5 || field == 12:
			if len(data) < 1 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(data[0])
			data = data[1:]
		case field == 8 || field == 9:
			if len(data) < 3 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(data[0]) | int32(data[1])<<8 | int32(data[2])<<16
			data = data[3:]
		case field == 10 || field == 11:
			if len(data) < 1 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(int8(data[0]))
			data = data[1:]
		case field == 13:
			// BrushHatch belongs to a non-solid brush and is outside this profile.
			if len(data) < 1 {
				return data, ErrMCSConnection
			}
			fields[field] = int32(data[0])
			data = data[1:]
		case field == 14:
			if len(data) < 7 {
				return data, ErrMCSConnection
			}
			data = data[7:]
		}
	}
	entry, err := cachedRDPBitmap(state, uint16(fields[0]), uint16(fields[15]))
	if err != nil || fields[0]>>8 != 0 || fields[1] < math.MinInt16 || fields[1] > math.MaxInt16 ||
		fields[2] < math.MinInt16 || fields[2] > math.MaxInt16 || fields[3] <= 0 || fields[4] <= 0 ||
		fields[5] < 0 || fields[5] > 255 || fields[12] != 0 || flags&(1<<13|1<<14) != 0 {
		return data, ErrMCSConnection
	}
	sourceX := fields[6]
	sourceY := int32(entry.height) - fields[4] - fields[7]
	if sourceX < 0 || sourceY < 0 || sourceX+fields[3] > int32(entry.width) || sourceY+fields[4] > int32(entry.height) {
		return data, ErrMCSConnection
	}
	pattern := [4]byte{byte(fields[9]), byte(fields[9] >> 8), byte(fields[9] >> 16), 0xff}
	if byte(fields[5]) != 0xaa {
		if err := appendRDPCachedBitmapOperation(result, totalPixels, entry, fields[1], fields[2], fields[3], fields[4], sourceX, sourceY,
			byte(fields[5]), pattern, bounds, desktopWidth, desktopHeight); err != nil {
			return data, err
		}
	}
	state.mem3BltFields = fields
	state.mem3BltUsed = true
	return data, nil
}

func appendRDPCachedBitmapOperation(result *RDPBitmapUpdate, totalPixels *uint64, entry rdpCachedBitmap,
	left, top, width, height, sourceX, sourceY int32, rop3 byte, pattern [4]byte, bounds *[4]int32,
	desktopWidth, desktopHeight uint16) error {
	clippedLeft, clippedTop, clippedWidth, clippedHeight, visible := clipRDPPrimaryRectangle(left, top, width, height, bounds, desktopWidth, desktopHeight)
	if !visible {
		return nil
	}
	pixels := uint64(clippedWidth) * uint64(clippedHeight)
	if len(result.Rectangles) >= maxRDPBitmapRects || pixels > maxRDPDesktopArea ||
		*totalPixels > maxRDPDesktopArea-pixels || pixels > uint64(int(^uint(0)>>1))/4 {
		return ErrMCSConnection
	}
	sourceLeft := sourceX + clippedLeft - left
	sourceTop := sourceY + clippedTop - top
	if sourceLeft < 0 || sourceTop < 0 || sourceLeft+clippedWidth > int32(entry.width) || sourceTop+clippedHeight > int32(entry.height) {
		return ErrMCSConnection
	}
	copyPixels := make([]byte, int(pixels)*4)
	for row := int32(0); row < clippedHeight; row++ {
		src := (int(sourceTop+row)*int(entry.width) + int(sourceLeft)) * 4
		dst := int(row) * int(clippedWidth) * 4
		copy(copyPixels[dst:dst+int(clippedWidth)*4], entry.pixels[src:src+int(clippedWidth)*4])
	}
	*totalPixels += pixels
	result.Rectangles = append(result.Rectangles, RDPBitmapRectangle{
		X: uint16(clippedLeft), Y: uint16(clippedTop), Width: uint16(clippedWidth), Height: uint16(clippedHeight),
		Pixels: copyPixels, operation: rdpBitmapRectangleROP3, rop3: rop3, patternColor: pattern,
	})
	return nil
}

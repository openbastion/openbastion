package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func mcsTestRDPSecondaryOrder(orderType byte, extraFlags uint16, body []byte) []byte {
	length := 6 + len(body)
	encodedLength := length - 13
	if encodedLength < 0 || encodedLength > 0x7fff {
		panic("test secondary order length out of range")
	}
	out := []byte{rdpOrderStandard | rdpOrderSecondary, byte(encodedLength), byte(encodedLength >> 8),
		byte(extraFlags), byte(extraFlags >> 8), orderType}
	return append(out, body...)
}

func mcsTestRDPRev2BitmapCacheOrder(index uint16, width, height uint16, pixels []byte) []byte {
	body := append(mcsTestRDPUnsigned16(width), mcsTestRDPUnsigned16(height)...)
	body = append(body, mcsTestRDPUnsigned32(uint32(len(pixels)))...)
	body = append(body, mcsTestRDPUnsigned16(index)...)
	body = append(body, pixels...)
	extraFlags := rdpCacheBitmapRev2BitsPerPixel32 << 3
	return mcsTestRDPSecondaryOrder(rdpCacheBitmapUncompressedRev2, extraFlags, body)
}

func mcsTestRDPRev3BitmapCacheOrder(index uint16, width, height uint16, pixels []byte) []byte {
	body := binary.LittleEndian.AppendUint16(nil, index)
	body = binary.LittleEndian.AppendUint32(body, 0x11223344)
	body = binary.LittleEndian.AppendUint32(body, 0x55667788)
	body = append(body, 32, 0, 0, 0)
	body = binary.LittleEndian.AppendUint16(body, width)
	body = binary.LittleEndian.AppendUint16(body, height)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(pixels)))
	body = append(body, pixels...)
	extraFlags := rdpCacheBitmapRev2BitsPerPixel32 << 3
	return mcsTestRDPSecondaryOrder(rdpCacheBitmapCompressedRev3, extraFlags, body)
}

func mcsTestRDPUnsigned16(value uint16) []byte {
	if value < 0x80 {
		return []byte{byte(value)}
	}
	return []byte{byte(value>>8) | 0x80, byte(value)}
}

func mcsTestRDPUnsigned32(value uint32) []byte {
	switch {
	case value < 0x40:
		return []byte{byte(value)}
	case value < 0x4000:
		return []byte{byte(value>>8) | 0x40, byte(value)}
	case value < 0x400000:
		return []byte{byte(value>>16) | 0x80, byte(value >> 8), byte(value)}
	default:
		return []byte{byte(value>>24) | 0xc0, byte(value >> 16), byte(value >> 8), byte(value)}
	}
}

func mcsTestRDPMemBltOrder(cacheID uint16, index uint16, left, top, width, height int16, rop byte, sourceX, sourceY int16) []byte {
	out := []byte{rdpOrderStandard | rdpOrderTypeChange, rdpOrderMemBlt, 0xff, 0x01}
	out = binary.LittleEndian.AppendUint16(out, cacheID)
	for _, value := range []int16{left, top, width, height} {
		out = binary.LittleEndian.AppendUint16(out, uint16(value))
	}
	out = append(out, rop)
	out = binary.LittleEndian.AppendUint16(out, uint16(sourceX))
	out = binary.LittleEndian.AppendUint16(out, uint16(sourceY))
	return binary.LittleEndian.AppendUint16(out, index)
}

func mcsTestRDPMem3BltOrder(cacheID, index uint16, left, top, width, height int16, rop byte,
	sourceX, sourceY int16, foreColor [3]byte, brushStyle byte) []byte {
	// The third field-flag byte is omitted; fields 13 (hatch) and 14 (extra) are absent.
	out := []byte{rdpOrderStandard | rdpOrderTypeChange | rdpOrderZeroFieldByteBit0, rdpOrderMem3Blt, 0xff, 0x9f}
	out = binary.LittleEndian.AppendUint16(out, cacheID)
	for _, value := range []int16{left, top, width, height} {
		out = binary.LittleEndian.AppendUint16(out, uint16(value))
	}
	out = append(out, rop)
	out = binary.LittleEndian.AppendUint16(out, uint16(sourceX))
	out = binary.LittleEndian.AppendUint16(out, uint16(sourceY))
	out = append(out, 0, 0, 0) // BackColor.
	out = append(out, foreColor[:]...)
	out = append(out, 0, 0, brushStyle) // Brush origin and style.
	return binary.LittleEndian.AppendUint16(out, index)
}

func mcsTestRDP2x2RawBitmap() []byte {
	// Bottom-up BGRX rows: red/green, then blue/white.
	return []byte{
		0, 0, 255, 0, 0, 255, 0, 0,
		255, 0, 0, 0, 255, 255, 255, 0,
	}
}

func TestRDPBitmapCacheRev2ThenMemBltAcrossUpdates(t *testing.T) {
	cacheOrder := mcsTestRDPRev2BitmapCacheOrder(7, 2, 2, mcsTestRDP2x2RawBitmap())
	_, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, cacheOrder, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil || state.cache == nil || state.cache.bytes != 16 || len(state.cache.entries) != 1 {
		t.Fatalf("cache update state=%+v err=%v", state, err)
	}
	memBlt := mcsTestRDPMemBltOrder(0, 7, 3, 2, 2, 2, 0xcc, 0, 0)
	update, next, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, memBlt, 0, 0), 8, 8, 32, state)
	if err != nil || !next.memBltUsed || len(update.Rectangles) != 1 {
		t.Fatalf("MemBlt update=%+v state=%+v err=%v", update, next, err)
	}
	got := update.Rectangles[0]
	if got.X != 3 || got.Y != 2 || got.Width != 2 || got.Height != 2 || got.operation != rdpBitmapRectangleROP3 ||
		!bytes.Equal(got.Pixels, []byte{0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 255, 0, 255, 0, 255}) {
		t.Fatalf("MemBlt rectangle = %+v pixels=%v", got, got.Pixels)
	}
	fb, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := fb.Draw(update); err != nil {
		t.Fatal(err)
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for y := 0; y < 2; y++ {
		start := fb.image.PixOffset(3, 2+y)
		if !bytes.Equal(fb.image.Pix[start:start+8], got.Pixels[y*8:(y+1)*8]) {
			t.Fatalf("framebuffer row %d = %v, want %v", y, fb.image.Pix[start:start+8], got.Pixels[y*8:(y+1)*8])
		}
	}
}

func TestRDPBitmapCacheRev3RawThenMem3Blt(t *testing.T) {
	cacheOrder := mcsTestRDPRev3BitmapCacheOrder(2, 2, 2, mcsTestRDP2x2RawBitmap())
	mem3Blt := mcsTestRDPMem3BltOrder(0, 2, 0, 0, 2, 2, 0xf0, 0, 0, [3]byte{0x12, 0x34, 0x56}, 0)
	orders := append(cacheOrder, mem3Blt...)
	update, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(2, orders, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil || !state.mem3BltUsed || len(update.Rectangles) != 1 {
		t.Fatalf("Mem3Blt update=%+v state=%+v err=%v", update, state, err)
	}
	wantCached := []byte{0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 255, 0, 255, 0, 255}
	if !bytes.Equal(state.cache.entries[2].pixels, wantCached) {
		t.Fatalf("rev3 cached pixels=%v want=%v", state.cache.entries[2].pixels, wantCached)
	}
	if update.Rectangles[0].patternColor != [4]byte{0x12, 0x34, 0x56, 0xff} || update.Rectangles[0].rop3 != 0xf0 {
		t.Fatalf("Mem3Blt operation = %+v", update.Rectangles[0])
	}
	fb, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := fb.Draw(update); err != nil {
		t.Fatal(err)
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	start := fb.image.PixOffset(0, 0)
	if !bytes.Equal(fb.image.Pix[start:start+4], []byte{0x12, 0x34, 0x56, 0xff}) {
		t.Fatalf("PATCOPY result = %v", fb.image.Pix[start:start+4])
	}
}

func TestRDPBitmapCacheRejectsUnsupportedAndMalformedOrdersAtomically(t *testing.T) {
	valid := mcsTestRDPRev2BitmapCacheOrder(1, 2, 2, mcsTestRDP2x2RawBitmap())
	badMemBlt := mcsTestRDPMemBltOrder(0, 1, 0, 0, 2, 2, 0xf0, 0, 0) // Pattern-dependent ROP3.
	cases := map[string][]byte{
		"secondary control flags": append([]byte{rdpOrderStandard | rdpOrderSecondary | 0x04}, valid[1:]...),
		"unknown secondary order": mcsTestRDPSecondaryOrder(0x07, 0, make([]byte, 20)),
		"persistent key": mcsTestRDPSecondaryOrder(rdpCacheBitmapUncompressedRev2,
			(rdpCacheBitmapRev2BitsPerPixel32<<3)|(rdpCacheBitmapRev2PersistentKey<<7), append([]byte{2, 2, 16, 0}, mcsTestRDP2x2RawBitmap()...)),
		"unsupported depth":      mcsTestRDPSecondaryOrder(rdpCacheBitmapUncompressedRev2, 0x28, append([]byte{2, 2, 16, 0}, mcsTestRDP2x2RawBitmap()...)),
		"truncated body":         valid[:len(valid)-1],
		"cache reference absent": badMemBlt,
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			_, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
			if !errors.Is(err, ErrMCSConnection) || state.cache != nil || state.memBltUsed {
				t.Fatalf("state=%+v err=%v, want atomic refusal", state, err)
			}
		})
	}
	orders := append(append([]byte(nil), valid...), badMemBlt...)
	if _, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(2, orders, 0, 0), 8, 8, 32, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) || state.cache != nil {
		t.Fatalf("valid cache followed by invalid MemBlt committed state=%+v err=%v", state, err)
	}
}

func TestRDPBitmapCacheBoundsAndROP3TruthTable(t *testing.T) {
	state := rdpPrimaryOrderState{}
	if err := storeRDPBitmapCache(&state, 0, 1, 1, make([]byte, maxRDPBitmapCacheEntryBytes+1)); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("oversized entry error = %v", err)
	}
	for _, test := range []struct {
		name string
		rop  byte
		want byte
	}{
		{name: "SRCCOPY", rop: 0xcc, want: 0x33},
		{name: "PATCOPY", rop: 0xf0, want: 0x55},
		{name: "DSTCOPY", rop: 0xaa, want: 0x22},
		{name: "BLACKNESS", rop: 0x00, want: 0x00},
		{name: "WHITENESS", rop: 0xff, want: 0xff},
		{name: "MERGECOPY", rop: 0xc0, want: 0x11},
		{name: "PATOR", rop: 0xfa, want: 0x77},
		{name: "NOTSRCERASE", rop: 0x11, want: 0xcc},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := []byte{0x22, 0x22, 0x22, 0xff}
			source := []byte{0x33, 0x33, 0x33, 0xff}
			pattern := [4]byte{0x55, 0x55, 0x55, 0xff}
			applyRDPROP3(destination, source, pattern, test.rop)
			if !bytes.Equal(destination, []byte{test.want, test.want, test.want, 0xff}) {
				t.Fatalf("ROP3 result = %v, want %02x", destination, test.want)
			}
		})
	}
}

func TestRDPMemBltDstCopyIsConsumedWithoutFramebufferWork(t *testing.T) {
	cacheOrder := mcsTestRDPRev2BitmapCacheOrder(0, 2, 2, mcsTestRDP2x2RawBitmap())
	memBlt := mcsTestRDPMemBltOrder(0, 0, 1, 1, 2, 2, 0xaa, 0, 0)
	orders := append(cacheOrder, memBlt...)
	update, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(2, orders, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil || len(update.Rectangles) != 0 || !state.memBltUsed || state.cache == nil {
		t.Fatalf("DSTCOPY update=%+v state=%+v err=%v", update, state, err)
	}
}

func TestRDPBitmapCacheCapabilitiesAreAdvertisedAsOneCompleteProfile(t *testing.T) {
	for _, test := range []struct {
		name          string
		bpp           uint16
		wantCache     bool
		wantMemOrders bool
	}{
		{name: "32 bpp", bpp: 32, wantCache: true, wantMemOrders: true},
		{name: "16 bpp", bpp: 16},
		{name: "15 bpp", bpp: 15},
	} {
		t.Run(test.name, func(t *testing.T) {
			caps := marshalRDPClientCapabilitySets(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800}, test.bpp)
			var order, cache []byte
			count := uint16(0)
			for rest := caps; len(rest) > 0; {
				if len(rest) < 4 {
					t.Fatalf("truncated capability header: %x", rest)
				}
				length := int(binary.LittleEndian.Uint16(rest[2:4]))
				if length < 4 || length > len(rest) {
					t.Fatalf("invalid capability length %d in %x", length, rest)
				}
				switch binary.LittleEndian.Uint16(rest[:2]) {
				case rdpCapOrder:
					order = rest[:length]
				case rdpCapBitmapCacheRev2:
					cache = rest[:length]
				}
				count++
				rest = rest[length:]
			}
			if count != rdpClientCapabilitySetCountForDepth(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800}, test.bpp) {
				t.Fatalf("capability count=%d", count)
			}
			if len(order) != 88 || len(cache) != map[bool]int{true: 40, false: 0}[test.wantCache] {
				t.Fatalf("order len=%d cache len=%d", len(order), len(cache))
			}
			wantMemBlt, wantMem3Blt, wantRev3 := byte(0), byte(0), uint16(0)
			if test.wantMemOrders {
				wantMemBlt, wantMem3Blt, wantRev3 = 1, 1, rdpOrderSupportCacheBitmapRev3
			}
			wantOrderFlags := uint16(0x000a)
			if test.wantMemOrders {
				wantOrderFlags |= rdpOrderFlagExtraFlags
			}
			if binary.LittleEndian.Uint16(order[34:36]) != wantOrderFlags ||
				order[rdpOrderSupportOffset+rdpOrderSupportMemBltIndex] != wantMemBlt ||
				order[rdpOrderSupportOffset+rdpOrderSupportMem3BltIndex] != wantMem3Blt ||
				binary.LittleEndian.Uint16(order[rdpOrderSupportExFlagsOffset:rdpOrderSupportExFlagsOffset+2]) != wantRev3 {
				t.Fatalf("order profile for %d bpp = %x", test.bpp, order)
			}
			if test.wantCache && (binary.LittleEndian.Uint32(cache[8:12]) != rdpBitmapCacheEntries || cache[7] != 1) {
				t.Fatalf("bitmap cache capability = %x", cache)
			}
		})
	}
}

func TestRDPBitmapCacheRev2CompressedWithAndWithoutHeader(t *testing.T) {
	stream := []byte{0x20}
	stream = append(stream, 1, 2, 3, 4) // R plane.
	stream = append(stream, 11, 12, 13, 14)
	stream = append(stream, 21, 22, 23, 24)
	withHeader := mcsTestRDP6BitmapData(4, 1, stream)
	for _, test := range []struct {
		name  string
		flags uint16
		data  []byte
	}{
		{name: "header", data: withHeader},
		{name: "no header", flags: rdpCacheBitmapRev2NoCompressionHeader, data: stream},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := append(mcsTestRDPUnsigned16(4), mcsTestRDPUnsigned16(1)...)
			body = append(body, mcsTestRDPUnsigned32(uint32(len(test.data)))...)
			body = append(body, mcsTestRDPUnsigned16(3)...)
			body = append(body, test.data...)
			extraFlags := (rdpCacheBitmapRev2BitsPerPixel32 << 3) | (test.flags << 7)
			order := mcsTestRDPSecondaryOrder(rdpCacheBitmapCompressedRev2, extraFlags, body)
			_, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
			if err != nil || state.cache == nil || len(state.cache.entries[3].pixels) != 16 {
				t.Fatalf("compressed cache state=%+v err=%v", state, err)
			}
			want := []byte{1, 11, 21, 0xff, 2, 12, 22, 0xff, 3, 13, 23, 0xff, 4, 14, 24, 0xff}
			if !bytes.Equal(state.cache.entries[3].pixels, want) {
				t.Fatalf("compressed pixels=%v want=%v", state.cache.entries[3].pixels, want)
			}
		})
	}
}

func TestRDPMemBltDeltaCoordinatesAndClipping(t *testing.T) {
	cacheOrder := mcsTestRDPRev2BitmapCacheOrder(0, 2, 2, mcsTestRDP2x2RawBitmap())
	first := mcsTestRDPMemBltOrder(0, 0, -1, 0, 2, 2, 0xcc, 0, 0)
	// Only the destination left/top fields are sent; the remaining fields are reused.
	second := []byte{rdpOrderStandard | rdpOrderDeltaCoordinates | rdpOrderZeroFieldByteBit0, 0x06, 1, 1}
	firstOrders := append(append([]byte(nil), cacheOrder...), first...)
	_, firstState, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(2, firstOrders, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatalf("first cache/MemBlt state=%+v err=%v", firstState, err)
	}
	var secondUpdate RDPBitmapUpdate
	var totalPixels uint64
	secondRest, secondErr := parseRDPMemBltOrder(second[1:], second[0], &firstState, &secondUpdate, &totalPixels, 8, 8)
	if secondErr != nil || len(secondRest) != 0 {
		t.Fatalf("direct delta MemBlt state=%+v rest=%x err=%v", firstState, secondRest, secondErr)
	}
	orders := append(append(cacheOrder, first...), second...)
	update, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(3, orders, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil || !state.memBltUsed || len(update.Rectangles) != 2 {
		t.Fatalf("MemBlt updates=%+v state=%+v err=%v", update, state, err)
	}
	clipped := update.Rectangles[0]
	if clipped.X != 0 || clipped.Width != 1 || !bytes.Equal(clipped.Pixels, []byte{255, 255, 255, 255, 0, 255, 0, 255}) {
		t.Fatalf("clipped MemBlt = %+v pixels=%v", clipped, clipped.Pixels)
	}
	delta := update.Rectangles[1]
	if delta.X != 0 || delta.Y != 1 || delta.Width != 2 || delta.Height != 2 {
		t.Fatalf("delta MemBlt = %+v", delta)
	}
}

func TestRDPBitmapCacheRev3RejectsNonRawCodecAndWaitingList(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags uint16
		codec byte
	}{
		{name: "codec", codec: 1},
		{name: "waiting list", flags: rdpCacheBitmapRev3DoNotCache},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := binary.LittleEndian.AppendUint16(nil, 0)
			body = binary.LittleEndian.AppendUint32(body, 1)
			body = binary.LittleEndian.AppendUint32(body, 2)
			body = append(body, 32, 0, 0, test.codec)
			body = binary.LittleEndian.AppendUint16(body, 1)
			body = binary.LittleEndian.AppendUint16(body, 1)
			body = binary.LittleEndian.AppendUint32(body, 4)
			body = append(body, 0, 0, 0, 0)
			extraFlags := (rdpCacheBitmapRev2BitsPerPixel32 << 3) | (test.flags << 7)
			order := mcsTestRDPSecondaryOrder(rdpCacheBitmapCompressedRev3, extraFlags, body)
			if _, _, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, 32, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error=%v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestRDPBitmapCacheStateCloneAndCloseErase(t *testing.T) {
	original := rdpPrimaryOrderState{}
	if err := storeRDPBitmapCache(&original, 1, 1, 1, []byte{1, 2, 3, 0xff}); err != nil {
		t.Fatal(err)
	}
	cloned := cloneRDPPrimaryOrderState(original)
	if err := storeRDPBitmapCache(&cloned, 1, 1, 1, []byte{4, 5, 6, 0xff}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original.cache.entries[1].pixels, []byte{1, 2, 3, 0xff}) ||
		!bytes.Equal(cloned.cache.entries[1].pixels, []byte{4, 5, 6, 0xff}) {
		t.Fatalf("cache clone mutated the original: original=%v cloned=%v", original.cache.entries[1].pixels, cloned.cache.entries[1].pixels)
	}
	pixelBuffer := cloned.cache.entries[1].pixels
	session := &CredSSPClientSession{primaryOrderState: cloned}
	session.Close()
	if session.primaryOrderState.cache != nil || pixelBuffer[0] != 0 {
		t.Fatalf("Close did not erase cache state: session=%+v pixels=%v", session.primaryOrderState, pixelBuffer)
	}
}

func TestRDPBitmapCacheVariableUnsignedEncodings(t *testing.T) {
	for _, value := range []uint16{0, 0x7f, 0x80, 0x1234, 0x7fff} {
		encoded := mcsTestRDPUnsigned16(value)
		got, rest, err := readRDPUnsigned16(append(encoded, 0xaa))
		if err != nil || got != value || !bytes.Equal(rest, []byte{0xaa}) {
			t.Fatalf("16-bit value %#x: got=%#x rest=%x err=%v", value, got, rest, err)
		}
	}
	for _, value := range []uint32{0, 0x3f, 0x40, 0x1234, 0x4000, 0x3fffff, 0x400000, 0x3fffffff} {
		encoded := mcsTestRDPUnsigned32(value)
		got, rest, err := readRDPUnsigned32(append(encoded, 0xaa))
		if err != nil || got != value || !bytes.Equal(rest, []byte{0xaa}) {
			t.Fatalf("32-bit value %#x: got=%#x rest=%x err=%v", value, got, rest, err)
		}
	}
	if _, _, err := readRDPUnsigned16([]byte{0x80}); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("truncated 16-bit encoding error=%v", err)
	}
	if _, _, err := readRDPUnsigned32([]byte{0xc0, 0, 0}); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("truncated 32-bit encoding error=%v", err)
	}
}

func TestReadBitmapUpdateOverTLSDecodesBitmapCacheAndMemBlt(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const shareID = uint32(0x000103ea)
	cachePacket := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestRDPRev2BitmapCacheOrder(4, 2, 2, mcsTestRDP2x2RawBitmap()))
	memBltPacket := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestRDPMemBltOrder(0, 4, 1, 1, 2, 2, 0xcc, 0, 0))
	packet := append(cachePacket, memBltPacket...)
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr == nil {
			acceptErr = writeFull(tlsConn, packet)
		}
		serverResult <- acceptErr
	}()
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: conn}, connectionFinalized: true, capabilitiesExchanged: true,
		mcsResponse:          MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities:   RDPServerCapabilities{ShareID: shareID, DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32},
		mcsSettings:          MCSClientSettings{DesktopWidth: 8, DesktopHeight: 8},
		primaryOrdersEnabled: true, dstBltEnabled: true, memBltEnabled: true, mem3BltEnabled: true,
	}
	update, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
	if err != nil {
		session.Close()
		t.Fatalf("ReadBitmapUpdate: %v", err)
	}
	if len(update.Rectangles) != 1 || !session.primaryOrderState.memBltUsed || session.primaryOrderState.cache == nil {
		session.Close()
		t.Fatalf("TLS bitmap cache/MemBlt update=%+v state=%+v", update, session.primaryOrderState)
	}
	if err := <-serverResult; err != nil {
		session.Close()
		t.Fatalf("TLS peer: %v", err)
	}
	session.Close()
}

func TestRDPBitmapCacheRev2HeightSameAndTwoByteIndex(t *testing.T) {
	body := append(mcsTestRDPUnsigned16(2), mcsTestRDPUnsigned32(16)...)
	body = append(body, mcsTestRDPUnsigned16(200)...)
	body = append(body, mcsTestRDP2x2RawBitmap()...)
	extraFlags := (rdpCacheBitmapRev2BitsPerPixel32 << 3) | (rdpCacheBitmapRev2HeightSame << 7)
	order := mcsTestRDPSecondaryOrder(rdpCacheBitmapUncompressedRev2, extraFlags, body)
	_, state, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil || state.cache == nil || state.cache.entries[200].width != 2 || state.cache.entries[200].height != 2 {
		t.Fatalf("height-same cache state=%+v err=%v", state, err)
	}
}

func TestRDPMem3BltRejectsNonSolidBrush(t *testing.T) {
	cacheOrder := mcsTestRDPRev2BitmapCacheOrder(0, 2, 2, mcsTestRDP2x2RawBitmap())
	mem3Blt := mcsTestRDPMem3BltOrder(0, 0, 0, 0, 2, 2, 0xf0, 0, 0, [3]byte{1, 2, 3}, 1)
	orders := append(cacheOrder, mem3Blt...)
	if _, _, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(2, orders, 0, 0), 8, 8, 32, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("non-solid Mem3Blt error=%v, want ErrMCSConnection", err)
	}
}

func TestRDPOrdersAt15And16BPPAllowOnlyDstBlt(t *testing.T) {
	for _, bpp := range []uint16{15, 16} {
		t.Run(fmt.Sprintf("%d bpp", bpp), func(t *testing.T) {
			dstBlt := mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x55)
			update, _, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, dstBlt, 0, 0), 8, 8, bpp, rdpPrimaryOrderState{})
			if err != nil || len(update.Rectangles) != 1 {
				t.Fatalf("DstBlt update=%+v err=%v", update, err)
			}
			memBlt := mcsTestRDPMemBltOrder(0, 0, 0, 0, 1, 1, 0xcc, 0, 0)
			if _, _, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, memBlt, 0, 0), 8, 8, bpp, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("MemBlt at %d bpp error=%v, want ErrMCSConnection", bpp, err)
			}
			cache := mcsTestRDPRev2BitmapCacheOrder(0, 2, 2, mcsTestRDP2x2RawBitmap())
			if _, _, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, cache, 0, 0), 8, 8, bpp, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("bitmap cache at %d bpp error=%v, want ErrMCSConnection", bpp, err)
			}
		})
	}
	if _, _, err := parseRDPOrdersUpdateDataAt(mcsTestOrdersUpdateData(1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x55), 0, 0), 8, 8, 24, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("24-bpp DstBlt error=%v, want ErrMCSConnection", err)
	}
}

func TestApplyRDPROP3MatchesEveryTruthTable(t *testing.T) {
	for rop := 0; rop < 256; rop++ {
		for pattern := 0; pattern <= 1; pattern++ {
			for source := 0; source <= 1; source++ {
				for destination := 0; destination <= 1; destination++ {
					pixel := []byte{byte(destination * 0xff), byte(destination * 0xff), byte(destination * 0xff), 0xff}
					sourcePixel := []byte{byte(source * 0xff), byte(source * 0xff), byte(source * 0xff), 0xff}
					patternColor := [4]byte{byte(pattern * 0xff), byte(pattern * 0xff), byte(pattern * 0xff), 0xff}
					applyRDPROP3(pixel, sourcePixel, patternColor, byte(rop))
					index := pattern<<2 | source<<1 | destination
					want := byte(0)
					if rop&(1<<index) != 0 {
						want = 0xff
					}
					if pixel[0] != want || pixel[1] != want || pixel[2] != want || pixel[3] != 0xff {
						t.Fatalf("ROP3 %#02x P=%d S=%d D=%d: got=%v want RGB=%02x alpha=ff", rop, pattern, source, destination, pixel, want)
					}
				}
			}
		}
	}
}

func TestRDPBitmapCacheAggregateBudgetAndReplacementAccounting(t *testing.T) {
	oldPixels := []byte{1, 2, 3, 0xff}
	state := rdpPrimaryOrderState{cache: &rdpBitmapCacheState{
		entries: map[uint16]rdpCachedBitmap{0: {width: 1, height: 1, pixels: oldPixels}},
		bytes:   maxRDPBitmapCacheBytes, // Simulate other committed entries without allocating them.
	}}
	if err := storeRDPBitmapCache(&state, 0, 1, 1, []byte{4, 5, 6, 0xff}); err != nil {
		t.Fatalf("replacement at budget limit: %v", err)
	}
	if state.cache.bytes != maxRDPBitmapCacheBytes || !bytes.Equal(state.cache.entries[0].pixels, []byte{4, 5, 6, 0xff}) {
		t.Fatalf("replacement accounting bytes=%d entry=%v", state.cache.bytes, state.cache.entries[0].pixels)
	}
	rejectedPixels := []byte{7, 8, 9, 0xff}
	if err := storeRDPBitmapCache(&state, 1, 1, 1, rejectedPixels); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("aggregate budget error=%v, want ErrMCSConnection", err)
	}
	if rejectedPixels[0] != 0 || state.cache.bytes != maxRDPBitmapCacheBytes {
		t.Fatalf("rejected cache entry was retained: pixels=%v bytes=%d", rejectedPixels, state.cache.bytes)
	}
}

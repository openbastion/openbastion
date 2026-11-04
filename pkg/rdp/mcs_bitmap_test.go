package rdp

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseRDPBitmapUpdateDecodesRaw32BPPBottomUp(t *testing.T) {
	// Wire rows are bottom-up: blue/white, then red/green.
	bitmap := []byte{
		255, 0, 0, 0, 255, 255, 255, 0,
		0, 0, 255, 0, 0, 255, 0, 0,
	}
	packet := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(0, 0, 2, 2, 32, 0, bitmap))
	got, err := parseRDPBitmapUpdate(packet, mcsGlobalChannelID, 0x000103ea, 1280, 720)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 1 {
		t.Fatalf("rectangles = %d", len(got.Rectangles))
	}
	r := got.Rectangles[0]
	if r.X != 0 || r.Y != 0 || r.Width != 2 || r.Height != 2 {
		t.Fatalf("rectangle = %+v", r)
	}
	want := []byte{
		255, 0, 0, 255, 0, 255, 0, 255,
		0, 0, 255, 255, 255, 255, 255, 255,
	}
	if string(r.Pixels) != string(want) {
		t.Fatalf("RGBA pixels = %v, want %v", r.Pixels, want)
	}
}

func TestParseRDPBitmapUpdateRejectsMalformedInput(t *testing.T) {
	const shareID = uint32(0x000103ea)
	validBitmap := []byte{0, 0, 0, 0}
	base := mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, validBitmap))
	trailingPayload := []byte{1, 0, 1, 0}
	trailingPayload = append(trailingPayload, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, validBitmap)...)
	trailingPayload = append(trailingPayload, 0)
	trailingBitmapData := mcsTestFinalizationResponse(shareID, rdpPDU2Update, 2, trailingPayload)
	cases := map[string][]byte{
		"truncated":                        append([]byte(nil), base[:len(base)-1]...),
		"wrong MCS initiator":              mutateBitmapMCS(base, func(mcs []byte) { mcs[2]++ }),
		"wrong MCS channel":                mutateBitmapMCS(base, func(mcs []byte) { mcs[4]++ }),
		"wrong MCS segmentation":           mutateBitmapMCS(base, func(mcs []byte) { mcs[5] = 0x71 }),
		"wrong share data PDU":             mutateBitmapShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[2:4], 0x0018) }),
		"wrong share source":               mutateBitmapShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[4:6], 1003) }),
		"wrong share id":                   mutateBitmapShare(base, func(share []byte) { binary.LittleEndian.PutUint32(share[6:10], 0) }),
		"wrong stream":                     mutateBitmapShare(base, func(share []byte) { share[11] = 1 }),
		"wrong update type":                mutateBitmapShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[18:20], 0) }),
		"compressed bitmap":                mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 1, 1, 32, rdpBitmapCompressed, validBitmap)),
		"compressed bitmap without header": mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 1, 1, 32, rdpBitmapNoCompHdr, validBitmap)),
		"unknown bitmap flags":             mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 2, validBitmap)),
		"unsupported pixel depth":          mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 1, 1, 24, 0, validBitmap)),
		"zero rectangle count":             mcsTestBitmapUpdatePacket(shareID),
		"rectangle count over limit":       mcsTestBitmapUpdateCount(shareID, maxRDPBitmapRects+1),
		"empty rectangle":                  mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 0, 1, 32, 0, validBitmap)),
		"bounds mismatch":                  mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangleBounds(1, 2, 2, 2, 1, 1, 32, 0, validBitmap)),
		"rectangle outside desktop":        mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1280, 719, 1, 1, 32, 0, validBitmap)),
		"bitmap length mismatch":           mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0})),
		"trailing bitmap data":             trailingBitmapData,
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRDPBitmapUpdate(packet, mcsGlobalChannelID, shareID, 1280, 720); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
	if _, err := parseRDPBitmapUpdate(base, 1004, shareID, 1280, 720); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("unexpected channel accepted: %v", err)
	}
	if _, err := parseRDPBitmapUpdate(base, mcsGlobalChannelID, shareID, 0, 720); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("zero desktop dimension accepted: %v", err)
	}
}

func TestParseRDPBitmapUpdateSupportsMultipleRectangles(t *testing.T) {
	one := mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 255, 0})
	two := mcsTestBitmapRectangle(4, 5, 1, 1, 32, 0, []byte{255, 0, 0, 0})
	got, err := parseRDPBitmapUpdate(mcsTestBitmapUpdatePacket(0x000103ea, one, two), mcsGlobalChannelID, 0x000103ea, 1280, 720)
	if err != nil || len(got.Rectangles) != 2 || got.Rectangles[0].X != 0 || got.Rectangles[1].X != 4 {
		t.Fatalf("multiple rectangles = %+v, %v", got, err)
	}
}

func FuzzParseRDPBitmapUpdate(f *testing.F) {
	f.Add(mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 0, 0})))
	f.Add([]byte("not an RDP bitmap update"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseRDPBitmapUpdate(packet, mcsGlobalChannelID, 0x000103ea, 1280, 720)
	})
}

func mcsTestBitmapUpdatePacket(shareID uint32, rectangles ...[]byte) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[:2], rdpUpdateBitmap)
	binary.LittleEndian.PutUint16(payload[2:4], uint16(len(rectangles)))
	for _, rectangle := range rectangles {
		payload = append(payload, rectangle...)
	}
	return mcsTestFinalizationResponse(shareID, rdpPDU2Update, 2, payload)
}

func mcsTestBitmapUpdateCount(shareID uint32, count int) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[:2], rdpUpdateBitmap)
	binary.LittleEndian.PutUint16(payload[2:4], uint16(count))
	return mcsTestFinalizationResponse(shareID, rdpPDU2Update, 2, payload)
}

func mcsTestBitmapRectangle(left, top, width, height, bpp, flags uint16, pixels []byte) []byte {
	return mcsTestBitmapRectangleBounds(left, top, left+width-1, top+height-1, width, height, bpp, flags, pixels)
}

func mcsTestBitmapRectangleBounds(left, top, right, bottom, width, height, bpp, flags uint16, pixels []byte) []byte {
	out := make([]byte, 18+len(pixels))
	binary.LittleEndian.PutUint16(out[0:2], left)
	binary.LittleEndian.PutUint16(out[2:4], top)
	binary.LittleEndian.PutUint16(out[4:6], right)
	binary.LittleEndian.PutUint16(out[6:8], bottom)
	binary.LittleEndian.PutUint16(out[8:10], width)
	binary.LittleEndian.PutUint16(out[10:12], height)
	binary.LittleEndian.PutUint16(out[12:14], bpp)
	binary.LittleEndian.PutUint16(out[14:16], flags)
	binary.LittleEndian.PutUint16(out[16:18], uint16(len(pixels)))
	copy(out[18:], pixels)
	return out
}

func mutateBitmapMCS(packet []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), packet...)
	mutate(out[7:])
	return out
}

func mutateBitmapShare(packet []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), packet...)
	mcs := out[7:]
	_, share, err := readPERLength(mcs[6:])
	if err == nil {
		mutate(share)
	}
	return out
}

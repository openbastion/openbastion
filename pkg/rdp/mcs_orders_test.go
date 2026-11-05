package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"image/color"
	"image/png"
	"net"
	"testing"
	"time"
)

func TestParseRDPOrdersUpdateDecodesScrBltSourceCopy(t *testing.T) {
	order := mcsTestScrBltOrder(0x09, true, 3, 2, 2, 2, 0xcc, 0, 0)
	got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 1 || !state.scrBltUsed {
		t.Fatalf("ScrBlt update = %+v, state=%+v", got, state)
	}
	rect := got.Rectangles[0]
	if rect.X != 3 || rect.Y != 2 || rect.Width != 2 || rect.Height != 2 ||
		rect.sourceX != 0 || rect.sourceY != 0 || len(rect.Pixels) != 0 || rect.operation != rdpBitmapRectangleScrCopy {
		t.Fatalf("ScrBlt rectangle = %+v", rect)
	}
}

func mcsTestScrBltOrder(controlFlags byte, typeChange bool, left, top, width, height int16, rop byte, sourceX, sourceY int16) []byte {
	out := []byte{controlFlags}
	if typeChange {
		out = append(out, 0x02) // TS_ENC_SCRBLT_ORDER.
	}
	out = append(out, 0x7f) // Four destination coordinates, ROP, and two source coordinates.
	for _, value := range []int16{left, top, width, height} {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		out = append(out, encoded[:]...)
	}
	out = append(out, rop)
	for _, value := range []int16{sourceX, sourceY} {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		out = append(out, encoded[:]...)
	}
	return out
}

func TestParseRDPOrdersUpdateDecodesMultiDstBlt(t *testing.T) {
	order := mcsTestMultiDstBltOrder(0x09, true, 0, 0, 2, 2, rdpDstBltInvert,
		2, []byte{0x05, 1, 1, 2, 2, 3, 1})
	got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 16, 16, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if !state.multiDstBltUsed || state.orderType != rdpOrderMultiDstBlt || len(got.Rectangles) != 2 {
		t.Fatalf("MultiDstBlt update = %+v, state=%+v", got, state)
	}
	want := [][4]uint16{{1, 1, 2, 2}, {4, 1, 1, 2}}
	for i, rect := range got.Rectangles {
		if [4]uint16{rect.X, rect.Y, rect.Width, rect.Height} != want[i] ||
			rect.operation != rdpBitmapRectangleDstInvert || len(rect.Pixels) != 0 {
			t.Errorf("rectangle %d = %+v, want bounds %v and DSTINVERT", i, rect, want[i])
		}
	}
}

func TestParseRDPOrdersUpdateDecodesMultiDstBltConstantROP(t *testing.T) {
	for _, test := range []struct {
		name  string
		rop   byte
		pixel []byte
	}{
		{name: "BLACKNESS", rop: rdpDstBltBlackness, pixel: []byte{0, 0, 0, 0xff}},
		{name: "WHITENESS", rop: rdpDstBltWhiteness, pixel: []byte{0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := mcsTestMultiDstBltOrder(0x09, true, 2, 3, 2, 1, test.rop, 1, []byte{0x00, 0x01, 0x00, 0x01, 0x01})
			got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
			if err != nil {
				t.Fatal(err)
			}
			if !state.multiDstBltUsed || len(got.Rectangles) != 1 {
				t.Fatalf("MultiDstBlt update = %+v, state=%+v", got, state)
			}
			for _, rect := range got.Rectangles {
				if [4]uint16{rect.X, rect.Y, rect.Width, rect.Height} != [4]uint16{1, 0, 1, 1} {
					t.Fatalf("%s rectangle bounds = (%d,%d,%d,%d)", test.name, rect.X, rect.Y, rect.Width, rect.Height)
				}
				if len(rect.Pixels) < 4 || !bytes.Equal(rect.Pixels[:4], test.pixel) {
					t.Fatalf("%s rectangle pixel = %v, want %v", test.name, rect.Pixels, test.pixel)
				}
			}
		})
	}
}

func TestDecodeRDPMultiDstBltRectanglesKeepsDimensionsAbsolute(t *testing.T) {
	got, err := decodeRDPMultiDstBltRectangles([]byte{0x05, 1, 1, 2, 2, 3, 1}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := [][4]int32{{1, 1, 2, 2}, {4, 1, 1, 2}}
	if len(got) != len(want) {
		t.Fatalf("decoded rectangles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rectangle %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestDecodeRDPMultiDstBltRectanglesRejectsZeroDimensions(t *testing.T) {
	if _, err := decodeRDPMultiDstBltRectangles([]byte{0x00, 0, 0, 0, 1}, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("zero-width rectangle error = %v, want ErrMCSConnection", err)
	}
}

func TestDecodeRDPMultiDstBltRectanglesSupportsSigned15BitDeltas(t *testing.T) {
	got, err := decodeRDPMultiDstBltRectangles([]byte{0x40, 0x80, 0x64, 0x01, 0x01}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != [4]int32{100, 0, 1, 1} {
		t.Fatalf("15-bit delta rectangles = %v, want [[100 0 1 1]]", got)
	}
	if value, rest, err := readRDPPackedSignedDelta([]byte{0xff, 0xff}); err != nil || value != -1 || len(rest) != 0 {
		t.Fatalf("15-bit signed delta = %d, remaining=%x, err=%v; want -1", value, rest, err)
	}
	if value, rest, err := readRDPPackedSignedDelta([]byte{0x7f}); err != nil || value != -1 || len(rest) != 0 {
		t.Fatalf("7-bit signed delta = %d, remaining=%x, err=%v; want -1", value, rest, err)
	}
}

func TestParseRDPOrdersUpdateRejectsMalformedMultiDstBlt(t *testing.T) {
	valid := mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 0x01, 0x01, 0x01, 0x01})
	cases := map[string][]byte{
		"source-dependent ROP":            mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, 0xcc, 1, []byte{0x00, 1, 1, 1, 1}),
		"pattern-dependent ROP":           mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, 0xf0, 1, []byte{0x00, 1, 1, 1, 1}),
		"wrong field mask":                func() []byte { out := append([]byte(nil), valid...); out[2] = 0x3f; return out }(),
		"delta coordinates":               mcsTestMultiDstBltOrder(0x19, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 1, 1, 1, 1}),
		"missing type change":             mcsTestMultiDstBltOrder(0x01, false, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 1, 1, 1, 1}),
		"zero delta entries":              mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 0, nil),
		"too many delta entries":          mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 46, mcsTestMultiDstBltDeltaRects(46)),
		"truncated variable field":        valid[:len(valid)-1],
		"variable field length mismatch":  func() []byte { out := append([]byte(nil), valid...); out[len(out)-7]++; return out }(),
		"trailing bytes":                  append(append([]byte(nil), valid...), 0),
		"delta rectangle outside desktop": mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 0x7f, 0x01, 0x01, 0x01}),
		"negative delta width":            mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 0x01, 0x01, 0x7e, 0x01}),
		"zero delta width":                mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 0, 0, 0, 1}),
		"trailing delta payload":          mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x00, 1, 1, 1, 1, 0}),
		"nonzero unused zero bits":        mcsTestMultiDstBltOrder(0x09, true, 1, 1, 2, 2, rdpDstBltBlackness, 1, []byte{0x01, 1, 1, 1, 1}),
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func mcsTestMultiDstBltDeltaRects(count int) []byte {
	encoded := make([]byte, (count+1)/2)
	for i := range encoded {
		encoded[i] = 0xcc // left/top unchanged; width/height explicitly set.
	}
	if count%2 != 0 {
		encoded[len(encoded)-1] &= 0xf0 // Unused low nibble must be zero.
	}
	for i := 0; i < count; i++ {
		encoded = append(encoded, 1, 1)
	}
	return encoded
}

func mcsTestMultiDstBltOrder(controlFlags byte, typeChange bool, left, top, width, height int16, rop byte, deltaEntries byte, deltaRects []byte) []byte {
	out := []byte{controlFlags}
	if typeChange {
		out = append(out, rdpOrderMultiDstBlt)
	}
	out = append(out, 0x7f) // Four coordinates, bRop, nDeltaEntries and CodedDeltaList.
	for _, value := range []int16{left, top, width, height} {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		out = append(out, encoded[:]...)
	}
	out = append(out, rop, deltaEntries)
	var length [2]byte
	binary.LittleEndian.PutUint16(length[:], uint16(len(deltaRects)))
	out = append(out, length[:]...)
	return append(out, deltaRects...)
}

func TestParseRDPOrdersUpdateDecodesOpaqueRectangles(t *testing.T) {
	orders := append(mcsTestOpaqueRectOrder(0x09, true, 1, 2, 2, 1, 0x11, 0x22, 0x33),
		mcsTestOpaqueRectOrder(0x01, false, 4, 0, 1, 2, 0xaa, 0xbb, 0xcc)...)
	userData := mcsTestOrdersShareData(0x000103ea, 2, orders, 0x7f, 0x42)

	got, err := parseRDPBitmapShareData(userData, 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 2 {
		t.Fatalf("rectangle count = %d, want 2", len(got.Rectangles))
	}
	want := []struct {
		x, y, width, height uint16
		pixel               []byte
	}{
		{1, 2, 2, 1, []byte{0x11, 0x22, 0x33, 0xff}},
		{4, 0, 1, 2, []byte{0xaa, 0xbb, 0xcc, 0xff}},
	}
	for i, rect := range got.Rectangles {
		w := want[i]
		if rect.X != w.x || rect.Y != w.y || rect.Width != w.width || rect.Height != w.height {
			t.Errorf("rectangle %d = %+v, want (%d,%d %dx%d)", i, rect, w.x, w.y, w.width, w.height)
		}
		for offset := 0; offset < len(rect.Pixels); offset += 4 {
			if string(rect.Pixels[offset:offset+4]) != string(w.pixel) {
				t.Errorf("rectangle %d pixel %d = %v, want %v", i, offset/4, rect.Pixels[offset:offset+4], w.pixel)
				break
			}
		}
	}
}

func TestParseRDPOrdersUpdateRejectsUnsupportedScrBltProfiles(t *testing.T) {
	valid := mcsTestScrBltOrder(0x09, true, 2, 2, 2, 2, 0xcc, 0, 0)
	cases := map[string][]byte{
		"unsupported ROP":          mcsTestScrBltOrder(0x09, true, 2, 2, 2, 2, 0x66, 0, 0),
		"negative source X":        mcsTestScrBltOrder(0x09, true, 2, 2, 2, 2, 0xcc, -1, 0),
		"negative source Y":        mcsTestScrBltOrder(0x09, true, 2, 2, 2, 2, 0xcc, 0, -1),
		"source X outside desktop": mcsTestScrBltOrder(0x09, true, 2, 2, 2, 2, 0xcc, 7, 0),
		"source Y outside desktop": mcsTestScrBltOrder(0x09, true, 2, 2, 2, 2, 0xcc, 0, 7),
		"destination X outside":    mcsTestScrBltOrder(0x09, true, 7, 2, 2, 2, 0xcc, 0, 0),
		"destination Y outside":    mcsTestScrBltOrder(0x09, true, 2, 7, 2, 2, 0xcc, 0, 0),
		"zero width":               mcsTestScrBltOrder(0x09, true, 2, 2, 0, 2, 0xcc, 0, 0),
		"missing type change":      mcsTestScrBltOrder(0x01, false, 2, 2, 2, 2, 0xcc, 0, 0),
		"wrong field mask":         func() []byte { out := append([]byte(nil), valid...); out[2] = 0x3f; return out }(),
		"delta coordinates":        mcsTestScrBltOrder(0x19, true, 2, 2, 2, 2, 0xcc, 0, 0),
		"truncated order":          valid[:len(valid)-1],
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestParseRDPOrdersUpdateDecodesSolidPatBlt(t *testing.T) {
	order := mcsTestPatBltOrder(0x01, false, 26, 451, 13, 13, 0xf0, [3]byte{0xff, 0xff, 0x00}, [3]byte{0x5b, 0xef, 0x00}, 0x00)
	got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 640, 480, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 1 || !state.hasOrderType || state.orderType != rdpOrderPatBlt || !state.patBltOpaqueRectUsed {
		t.Fatalf("PatBlt update = %+v, state=%+v", got, state)
	}
	rect := got.Rectangles[0]
	if rect.X != 26 || rect.Y != 451 || rect.Width != 13 || rect.Height != 13 {
		t.Fatalf("PatBlt rectangle = %+v", rect)
	}
	wantPixel := []byte{0x5b, 0xef, 0x00, 0xff}
	for offset := 0; offset < len(rect.Pixels); offset += 4 {
		if !bytes.Equal(rect.Pixels[offset:offset+4], wantPixel) {
			t.Fatalf("PatBlt pixel %d = %v, want %v", offset/4, rect.Pixels[offset:offset+4], wantPixel)
		}
	}
}

func TestParseRDPOrdersUpdateDecodesDstBltSupportedRasterOperations(t *testing.T) {
	for _, test := range []struct {
		name     string
		rop      byte
		color    [3]byte
		stateful bool
	}{
		{name: "BLACKNESS", rop: 0x00, color: [3]byte{0x00, 0x00, 0x00}},
		{name: "WHITENESS", rop: 0xff, color: [3]byte{0xff, 0xff, 0xff}},
		{name: "DSTINVERT", rop: 0x55, stateful: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := mcsTestDstBltOrder(0x09, true, 2, 3, 2, 2, test.rop)
			got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Rectangles) != 1 || !state.hasOrderType || state.orderType != rdpOrderDstBlt || !state.dstBltUsed {
				t.Fatalf("DstBlt update = %+v, state=%+v", got, state)
			}
			rect := got.Rectangles[0]
			if rect.X != 2 || rect.Y != 3 || rect.Width != 2 || rect.Height != 2 {
				t.Fatalf("DstBlt rectangle = %+v", rect)
			}
			if test.stateful {
				if len(rect.Pixels) != 0 {
					t.Fatalf("DSTINVERT unexpectedly carries replacement pixels: %d bytes", len(rect.Pixels))
				}
			} else {
				wantPixel := []byte{test.color[0], test.color[1], test.color[2], 0xff}
				for offset := 0; offset < len(rect.Pixels); offset += 4 {
					if !bytes.Equal(rect.Pixels[offset:offset+4], wantPixel) {
						t.Fatalf("DstBlt pixel %d = %v, want %v", offset/4, rect.Pixels[offset:offset+4], wantPixel)
					}
				}
			}
		})
	}
}

func TestParseRDPOrdersUpdateRejectsUnsupportedDstBltProfiles(t *testing.T) {
	valid := mcsTestDstBltOrder(0x09, true, 1, 1, 2, 2, 0x00)
	cases := map[string][]byte{
		"source-dependent ROP":        mcsTestDstBltOrder(0x09, true, 1, 1, 2, 2, 0xcc),
		"unsupported destination ROP": mcsTestDstBltOrder(0x09, true, 1, 1, 2, 2, 0xaa),
		"missing initial type change": mcsTestDstBltOrder(0x01, false, 1, 1, 2, 2, 0x00),
		"wrong field mask":            func() []byte { out := append([]byte(nil), valid...); out[2] = 0x0f; return out }(),
		"negative coordinate":         mcsTestDstBltOrder(0x09, true, -1, 1, 2, 2, 0x00),
		"outside desktop":             mcsTestDstBltOrder(0x09, true, 7, 7, 2, 2, 0xff),
		"zero height":                 mcsTestDstBltOrder(0x09, true, 1, 1, 2, 0, 0x00),
		"truncated order":             valid[:len(valid)-1],
		"delta coordinates":           mcsTestDstBltOrder(0x19, true, 1, 1, 2, 2, 0x00),
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func mcsTestDstBltOrder(controlFlags byte, typeChange bool, left, top, width, height int16, rop byte) []byte {
	out := []byte{controlFlags}
	if typeChange {
		out = append(out, rdpOrderDstBlt)
	}
	out = append(out, 0x1f) // Four coordinates and bRop.
	for _, value := range []int16{left, top, width, height} {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		out = append(out, encoded[:]...)
	}
	return append(out, rop)
}

func TestParseRDPOrdersUpdateDecodesSolidPatInvert(t *testing.T) {
	order := mcsTestPatBltOrder(0x09, true, 2, 3, 2, 2, 0x5a, [3]byte{0xff, 0xff, 0xff}, [3]byte{0x0f, 0xf0, 0xaa}, 0)
	got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 1 || !state.hasOrderType || state.orderType != rdpOrderPatBlt || !state.patBltOpaqueRectUsed {
		t.Fatalf("PATINVERT update = %+v, state=%+v", got, state)
	}
	wantPatternPixel := []byte{0x0f, 0xf0, 0xaa, 0xff}
	for offset := 0; offset < len(got.Rectangles[0].Pixels); offset += 4 {
		if !bytes.Equal(got.Rectangles[0].Pixels[offset:offset+4], wantPatternPixel) {
			t.Fatalf("PATINVERT pattern pixel %d = %v, want %v", offset/4, got.Rectangles[0].Pixels[offset:offset+4], wantPatternPixel)
		}
	}
}

func TestParseRDPOrdersUpdateDecodesSolidPatBltBooleanRasterOperations(t *testing.T) {
	for _, test := range []struct {
		name string
		rop  byte
	}{
		{name: "PATAND", rop: 0xa0},
		{name: "PATOR", rop: 0xfa},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := mcsTestPatBltOrder(0x09, true, 2, 3, 2, 2, test.rop, [3]byte{0xff, 0xff, 0xff}, [3]byte{0x0f, 0xf0, 0xaa}, 0)
			got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Rectangles) != 1 || !state.patBltOpaqueRectUsed {
				t.Fatalf("%s update = %+v, state=%+v", test.name, got, state)
			}
			wantPattern := []byte{0x0f, 0xf0, 0xaa, 0xff}
			for offset := 0; offset < len(got.Rectangles[0].Pixels); offset += 4 {
				if !bytes.Equal(got.Rectangles[0].Pixels[offset:offset+4], wantPattern) {
					t.Fatalf("%s pattern pixel %d = %v, want %v", test.name, offset/4, got.Rectangles[0].Pixels[offset:offset+4], wantPattern)
				}
			}
		})
	}
}

func TestParseRDPOrdersUpdateDecodesSolidNotPatCopy(t *testing.T) {
	order := mcsTestPatBltOrder(0x09, true, 2, 3, 2, 2, 0x0f, [3]byte{0xff, 0xff, 0xff}, [3]byte{0x0f, 0xf0, 0xaa}, 0)
	got, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 1 || !state.patBltOpaqueRectUsed {
		t.Fatalf("NOTPATCOPY update = %+v, state=%+v", got, state)
	}
	wantPixel := []byte{0xf0, 0x0f, 0x55, 0xff}
	for offset := 0; offset < len(got.Rectangles[0].Pixels); offset += 4 {
		if !bytes.Equal(got.Rectangles[0].Pixels[offset:offset+4], wantPixel) {
			t.Fatalf("NOTPATCOPY pixel %d = %v, want %v", offset/4, got.Rectangles[0].Pixels[offset:offset+4], wantPixel)
		}
	}
}

func TestParseRDPOrdersUpdateRejectsUnsupportedPatBltProfiles(t *testing.T) {
	valid := mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0)
	cases := map[string][]byte{
		"unsupported ROP":                  mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0xcc, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"unsupported destination-only ROP": mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0x55, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"non-solid brush":                  mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 2),
		"incomplete field mask":            func() []byte { out := append([]byte(nil), valid...); out[2] = 0x3f; return out }(),
		"unexpected field mask":            func() []byte { out := append([]byte(nil), valid...); out[3] = 0x03; return out }(),
		"negative coordinate":              mcsTestPatBltOrder(0x09, true, -1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"outside desktop":                  mcsTestPatBltOrder(0x09, true, 7, 7, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"zero width":                       mcsTestPatBltOrder(0x09, true, 1, 1, 0, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"truncated order":                  valid[:len(valid)-1],
		"delta coordinates":                mcsTestPatBltOrder(0x19, true, 1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
	}
	for name, order := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func mcsTestPatBltOrder(controlFlags byte, typeChange bool, left, top, width, height int16, rop byte, backColor, foreColor [3]byte, brushStyle byte) []byte {
	out := []byte{controlFlags}
	if typeChange {
		out = append(out, rdpOrderPatBlt)
	}
	out = append(out, 0x7f, 0x02) // Four coordinates, ROP, both colors, and BrushStyle.
	for _, value := range []int16{left, top, width, height} {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		out = append(out, encoded[:]...)
	}
	out = append(out, rop)
	out = append(out, backColor[:]...)
	out = append(out, foreColor[:]...)
	return append(out, brushStyle)
}

func TestParseRDPOrdersUpdateRejectsUnsupportedAndMalformedOrders(t *testing.T) {
	valid := mcsTestOpaqueRectOrder(0x09, true, 1, 1, 2, 2, 1, 2, 3)
	cases := map[string][]byte{
		"unsupported order type": mcsTestOpaqueRectOrderWithType(0x09, 0x01, true, 1, 1, 2, 2, 1, 2, 3),
		"bounds flag":            mcsTestOpaqueRectOrder(0x0d, true, 1, 1, 2, 2, 1, 2, 3),
		"delta coordinates":      mcsTestOpaqueRectOrder(0x19, true, 1, 1, 2, 2, 1, 2, 3),
		"partial fields":         mcsTestOpaqueRectOrder(0x09, true, 1, 1, 2, 2, 1, 2, 3)[:3+8],
		"omitted fields": func() []byte {
			order := mcsTestOpaqueRectOrder(0x09, true, 1, 1, 2, 2, 1, 2, 3)
			order[2] = 0x3f
			return order
		}(),
		"secondary order":     mcsTestOpaqueRectOrder(0x0b, true, 1, 1, 2, 2, 1, 2, 3),
		"negative left":       mcsTestOpaqueRectOrder(0x09, true, -1, 1, 2, 2, 1, 2, 3),
		"outside desktop":     mcsTestOpaqueRectOrder(0x09, true, 7, 7, 2, 2, 1, 2, 3),
		"zero width":          mcsTestOpaqueRectOrder(0x09, true, 1, 1, 0, 2, 1, 2, 3),
		"missing type change": mcsTestOpaqueRectOrder(0x01, false, 1, 1, 2, 2, 1, 2, 3),
	}
	for name, orderData := range cases {
		t.Run(name, func(t *testing.T) {
			userData := mcsTestOrdersShareData(0x000103ea, 1, orderData, 0, 0)
			if _, err := parseRDPBitmapShareData(userData, 0x000103ea, 8, 8); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
	trailing := append(append([]byte(nil), valid...), 0)
	if _, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, trailing, 0, 0), 0x000103ea, 8, 8); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("trailing order data error = %v, want ErrMCSConnection", err)
	}
	if _, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 0, valid, 0, 0), 0x000103ea, 8, 8); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("zero order count error = %v, want ErrMCSConnection", err)
	}
	if _, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, maxRDPPrimaryOrders+1, valid, 0, 0), 0x000103ea, 8, 8); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("excessive order count error = %v, want ErrMCSConnection", err)
	}
}

func mcsTestOpaqueRectOrder(controlFlags byte, typeChange bool, left, top, width, height int16, red, green, blue byte) []byte {
	return mcsTestOpaqueRectOrderWithType(controlFlags, 0x0a, typeChange, left, top, width, height, red, green, blue)
}

func mcsTestOpaqueRectOrderWithType(controlFlags, orderType byte, typeChange bool, left, top, width, height int16, red, green, blue byte) []byte {
	out := []byte{controlFlags}
	if typeChange {
		out = append(out, orderType)
	}
	out = append(out, 0x7f)
	for _, value := range []int16{left, top, width, height} {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		out = append(out, encoded[:]...)
	}
	return append(out, red, green, blue)
}

func mcsTestOrdersShareData(shareID uint32, orderCount uint16, orders []byte, padA, padB byte) []byte {
	payload := []byte{0, 0}
	payload = append(payload, mcsTestOrdersUpdateData(orderCount, orders, padA, padB)...)
	share := make([]byte, 18+len(payload))
	binary.LittleEndian.PutUint16(share[0:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint16(share[4:6], rdpServerChannelID)
	binary.LittleEndian.PutUint32(share[6:10], shareID)
	share[11] = 2
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(share)))
	share[14] = rdpPDU2Update
	copy(share[18:], payload)
	return share
}

func TestParseRDPOrdersUpdateRetainsOrderTypeAcrossPDUs(t *testing.T) {
	firstOrder := mcsTestOpaqueRectOrder(0x09, true, 1, 1, 1, 1, 0x10, 0x20, 0x30)
	first, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, firstOrder, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil || len(first.Rectangles) != 1 || !state.hasOrderType || state.orderType != rdpOrderOpaqueRect {
		t.Fatalf("first order update = %+v, state=%+v, err=%v", first, state, err)
	}

	secondOrder := mcsTestOpaqueRectOrder(0x01, false, 2, 2, 1, 1, 0x40, 0x50, 0x60)
	second, nextState, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, secondOrder, 0, 0), 8, 8, state)
	if err != nil || len(second.Rectangles) != 1 || nextState != state {
		t.Fatalf("second order update = %+v, state=%+v, err=%v", second, nextState, err)
	}
	if got := second.Rectangles[0].Pixels; string(got) != string([]byte{0x40, 0x50, 0x60, 0xff}) {
		t.Fatalf("second order pixel = %v", got)
	}
}

func TestParseRDPOrdersUpdateDoesNotCommitStateOnMalformedOrder(t *testing.T) {
	initial := rdpPrimaryOrderState{orderType: rdpOrderOpaqueRect, hasOrderType: true}
	malformed := mcsTestOpaqueRectOrder(0x01, false, 7, 7, 2, 2, 1, 2, 3)
	if _, gotState, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, malformed, 0, 0), 8, 8, initial); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("malformed order error = %v, want ErrMCSConnection", err)
	} else if gotState != initial {
		t.Fatalf("malformed order changed state: got %+v, want %+v", gotState, initial)
	}
}

func FuzzParseRDPOrdersUpdate(f *testing.F) {
	f.Add(mcsTestOrdersUpdateData(1, mcsTestOpaqueRectOrder(0x09, true, 0, 0, 1, 1, 0, 0, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestScrBltOrder(0x09, true, 1, 0, 1, 1, 0xcc, 0, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestPatBltOrder(0x01, false, 0, 0, 1, 1, 0xf0, [3]byte{}, [3]byte{0xff, 0xff, 0xff}, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestPatBltOrder(0x09, true, 0, 0, 1, 1, 0x5a, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestPatBltOrder(0x09, true, 0, 0, 1, 1, 0xa0, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestPatBltOrder(0x09, true, 0, 0, 1, 1, 0xfa, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestPatBltOrder(0x09, true, 0, 0, 1, 1, 0x0f, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x00), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestMultiDstBltOrder(0x09, true, 0, 0, 1, 1, rdpDstBltBlackness, 1, []byte{0x00, 1, 0, 1, 1}), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x55), 0, 0))
	f.Add([]byte("not an orders update"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseRDPOrdersUpdateData(data, 64, 64, rdpPrimaryOrderState{})
	})
}

func mcsTestOrdersUpdateData(orderCount uint16, orders []byte, padA, padB byte) []byte {
	data := make([]byte, 6)
	data[0], data[1], data[4], data[5] = padA, 0, padB, 0
	binary.LittleEndian.PutUint16(data[2:4], orderCount)
	return append(data, orders...)
}

func TestReadBitmapUpdateOverTLSRetainsPrimaryOrderType(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	const shareID = uint32(0x000103ea)
	first := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x00))
	second := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestPatBltOrder(0x09, true, 1, 0, 1, 1, 0xf0, [3]byte{1, 2, 3}, [3]byte{0x11, 0x22, 0x33}, 0))
	third := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestOpaqueRectOrder(0x09, true, 2, 0, 1, 1, 0xaa, 0xbb, 0xcc))
	fourth := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestScrBltOrder(0x09, true, 3, 0, 1, 1, 0xcc, 0, 0))
	fifth := mcsTestOrdersUpdatePacket(shareID, 1, mcsTestMultiDstBltOrder(0x09, true, 4, 0, 1, 1, rdpDstBltBlackness, 1, []byte{0x00, 1, 0, 1, 1}))
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
			acceptErr = writeFull(tlsConn, first)
		}
		if acceptErr == nil {
			acceptErr = writeFull(tlsConn, second)
		}
		if acceptErr == nil {
			acceptErr = writeFull(tlsConn, third)
		}
		if acceptErr == nil {
			acceptErr = writeFull(tlsConn, fourth)
		}
		if acceptErr == nil {
			acceptErr = writeFull(tlsConn, fifth)
		}
		serverResult <- acceptErr
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport:               &Transport{Conn: tlsConn},
		connectionFinalized:     true,
		capabilitiesExchanged:   true,
		primaryOrdersEnabled:    true, // Simulates future Confirm Active order negotiation.
		patBltOpaqueRectEnabled: true, // Shared negotiation index 1.
		dstBltEnabled:           true, // DstBlt has its own independent negotiation index.
		scrBltEnabled:           true, // ScrBlt has its own independent negotiation index.
		multiDstBltEnabled:      true, // MultiDstBlt has its own independent negotiation index 15.
		mcsResponse:             MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities:      RDPServerCapabilities{ShareID: shareID, DesktopWidth: 8, DesktopHeight: 8},
	}
	for i, want := range [][]byte{{0x00, 0x00, 0x00, 0xff}, {0x11, 0x22, 0x33, 0xff}, {0xaa, 0xbb, 0xcc, 0xff}} {
		update, readErr := session.ReadBitmapUpdate(context.Background(), time.Second)
		if readErr != nil || len(update.Rectangles) != 1 || string(update.Rectangles[0].Pixels) != string(want) {
			t.Fatalf("ReadBitmapUpdate #%d = %+v, err=%v", i, update, readErr)
		}
	}
	scrBltUpdate, readErr := session.ReadBitmapUpdate(context.Background(), time.Second)
	if readErr != nil || len(scrBltUpdate.Rectangles) != 1 || scrBltUpdate.Rectangles[0].operation != rdpBitmapRectangleScrCopy {
		t.Fatalf("ReadBitmapUpdate ScrBlt = %+v, err=%v", scrBltUpdate, readErr)
	}
	multiDstUpdate, readErr := session.ReadBitmapUpdate(context.Background(), time.Second)
	if readErr != nil || len(multiDstUpdate.Rectangles) != 1 || !session.primaryOrderState.multiDstBltUsed {
		t.Fatalf("ReadBitmapUpdate MultiDstBlt = %+v, state=%+v, err=%v", multiDstUpdate, session.primaryOrderState, readErr)
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	session.Close()
}

func mcsTestOrdersUpdatePacket(shareID uint32, orderCount uint16, orders []byte) []byte {
	userData := mcsTestOrdersShareData(shareID, orderCount, orders, 0, 0)
	mcs := []byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x70}
	mcs = appendPERLength(mcs, len(userData))
	mcs = append(mcs, userData...)
	packet := make([]byte, 7+len(mcs))
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
}

func TestRDPFramebufferAppliesOpaqueRectOrder(t *testing.T) {
	order := mcsTestOpaqueRectOrder(0x09, true, 2, 3, 2, 2, 0x12, 0x34, 0x56)
	update, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, order, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 3; y < 5; y++ {
		for x := 2; x < 4; x++ {
			r, g, b, a := decoded.At(x, y).RGBA()
			if r != 0x12*257 || g != 0x34*257 || b != 0x56*257 || a != 0xffff {
				t.Fatalf("pixel (%d,%d) = (%x,%x,%x,%x)", x, y, r, g, b, a)
			}
		}
	}
	if r, g, b, a := decoded.At(0, 0).RGBA(); r != 0 || g != 0 || b != 0 || a != 0xffff {
		t.Fatalf("untouched pixel = (%x,%x,%x,%x), want opaque black", r, g, b, a)
	}
}

func TestRDPFramebufferAppliesDstBltOrder(t *testing.T) {
	for _, test := range []struct {
		name  string
		rop   byte
		color [3]byte
	}{
		{name: "BLACKNESS", rop: 0x00, color: [3]byte{0x00, 0x00, 0x00}},
		{name: "WHITENESS", rop: 0xff, color: [3]byte{0xff, 0xff, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := mcsTestDstBltOrder(0x09, true, 2, 3, 2, 2, test.rop)
			update, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, order, 0, 0), 0x000103ea, 8, 8)
			if err != nil {
				t.Fatal(err)
			}
			framebuffer, err := NewRDPFramebuffer(8, 8)
			if err != nil {
				t.Fatal(err)
			}
			message, err := framebuffer.Apply(update, time.Unix(3, 0))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := png.Decode(bytes.NewReader(message.PNG))
			if err != nil {
				t.Fatal(err)
			}
			for y := 3; y < 5; y++ {
				for x := 2; x < 4; x++ {
					r, g, b, a := decoded.At(x, y).RGBA()
					if r != uint32(test.color[0])*257 || g != uint32(test.color[1])*257 || b != uint32(test.color[2])*257 || a != 0xffff {
						t.Fatalf("pixel (%d,%d) = (%x,%x,%x,%x)", x, y, r, g, b, a)
					}
				}
			}
		})
	}
}

func TestRDPFramebufferAppliesDstInvertOperation(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	seedOrder := mcsTestPatBltOrder(0x01, false, 2, 3, 2, 2, 0xf0, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0)
	seedUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, seedOrder, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := framebuffer.Apply(seedUpdate, time.Unix(4, 0)); err != nil {
		t.Fatal(err)
	}

	invertOrder := mcsTestDstBltOrder(0x09, true, 2, 3, 2, 2, 0x55)
	invertUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, invertOrder, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(invertUpdate.Rectangles) != 1 || len(invertUpdate.Rectangles[0].Pixels) != 0 {
		t.Fatalf("DSTINVERT update = %+v", invertUpdate)
	}
	message, err := framebuffer.Apply(invertUpdate, time.Unix(5, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 3; y < 5; y++ {
		for x := 2; x < 4; x++ {
			r, g, b, a := decoded.At(x, y).RGBA()
			if r != 0xed*257 || g != 0xcb*257 || b != 0xa9*257 || a != 0xffff {
				t.Fatalf("inverted pixel (%d,%d) = (%x,%x,%x,%x)", x, y, r, g, b, a)
			}
		}
	}
}

func TestRDPFramebufferAppliesPatInvertOperation(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	seedOrder := mcsTestPatBltOrder(0x01, false, 2, 3, 2, 2, 0xf0, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0)
	seedUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, seedOrder, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := framebuffer.Apply(seedUpdate, time.Unix(6, 0)); err != nil {
		t.Fatal(err)
	}

	invertOrder := mcsTestPatBltOrder(0x09, true, 2, 3, 2, 2, 0x5a, [3]byte{}, [3]byte{0x0f, 0xf0, 0xaa}, 0)
	invertUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, invertOrder, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(invertUpdate.Rectangles) != 1 {
		t.Fatalf("PATINVERT update = %+v", invertUpdate)
	}
	message, err := framebuffer.Apply(invertUpdate, time.Unix(7, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 3; y < 5; y++ {
		for x := 2; x < 4; x++ {
			r, g, b, a := decoded.At(x, y).RGBA()
			if r != 0x1d*257 || g != 0xc4*257 || b != 0xfc*257 || a != 0xffff {
				t.Fatalf("PATINVERT pixel (%d,%d) = (%x,%x,%x,%x)", x, y, r, g, b, a)
			}
		}
	}
}

func TestRDPFramebufferAppliesNotPatCopy(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	seedOrder := mcsTestPatBltOrder(0x01, false, 2, 3, 2, 2, 0xf0, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0)
	seedUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, seedOrder, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := framebuffer.Apply(seedUpdate, time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}

	order := mcsTestPatBltOrder(0x09, true, 2, 3, 2, 2, 0x0f, [3]byte{}, [3]byte{0x0f, 0xf0, 0xaa}, 0)
	update, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, order, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(11, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 3; y < 5; y++ {
		for x := 2; x < 4; x++ {
			r, g, b, a := decoded.At(x, y).RGBA()
			if r != 0xf0*257 || g != 0x0f*257 || b != 0x55*257 || a != 0xffff {
				t.Fatalf("NOTPATCOPY pixel (%d,%d) = (%x,%x,%x,%x)", x, y, r, g, b, a)
			}
		}
	}
}

func TestRDPFramebufferAppliesOverlappingScrBltSourceCopy(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	seed := RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{
		Width: 1, Height: 3, Pixels: []byte{
			0x10, 0x20, 0x30, 0xff,
			0x40, 0x50, 0x60, 0xff,
			0x70, 0x80, 0x90, 0xff,
		},
	}}}
	if _, err := framebuffer.Apply(seed, time.Unix(12, 0)); err != nil {
		t.Fatal(err)
	}
	order := mcsTestScrBltOrder(0x09, true, 0, 1, 1, 2, 0xcc, 0, 0)
	update, state, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 1, 3, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if !state.scrBltUsed {
		t.Fatalf("ScrBlt negotiation state = %+v", state)
	}
	message, err := framebuffer.Apply(update, time.Unix(13, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	want := []color.RGBA{
		{R: 0x10, G: 0x20, B: 0x30, A: 0xff},
		{R: 0x10, G: 0x20, B: 0x30, A: 0xff},
		{R: 0x40, G: 0x50, B: 0x60, A: 0xff},
	}
	for y, expected := range want {
		if got := color.RGBAModel.Convert(decoded.At(0, y)).(color.RGBA); got != expected {
			t.Fatalf("overlapping ScrBlt pixel %d = %#v, want %#v", y, got, expected)
		}
	}
}

func TestRDPFramebufferAppliesMultiDstBltAtomically(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	seed := mcsTestPatBltOrder(0x01, false, 0, 0, 2, 2, rdpPatBltPatCopy, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0)
	seedUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, seed, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := framebuffer.Apply(seedUpdate, time.Unix(20, 0)); err != nil {
		t.Fatal(err)
	}
	order := mcsTestMultiDstBltOrder(0x09, true, 6, 6, 1, 1, rdpDstBltInvert, 2,
		[]byte{0x00, 0, 0, 1, 1, 1, 0, 1, 1})
	update, _, err := parseRDPOrdersUpdateData(mcsTestOrdersUpdateData(1, order, 0, 0), 8, 8, rdpPrimaryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(21, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range [][2]int{{0, 0}, {1, 0}} {
		got := color.RGBAModel.Convert(decoded.At(point[0], point[1])).(color.RGBA)
		if got != (color.RGBA{R: 0xed, G: 0xcb, B: 0xa9, A: 0xff}) {
			t.Fatalf("MultiDstBlt pixel %v = %#v, want inverted seed", point, got)
		}
	}
	for _, point := range [][2]int{{2, 0}, {6, 6}} {
		if got := color.RGBAModel.Convert(decoded.At(point[0], point[1])).(color.RGBA); got != (color.RGBA{A: 0xff}) {
			t.Fatalf("untouched pixel %v = %#v, want opaque black", point, got)
		}
	}
}

func TestRDPFramebufferAppliesPatBltBooleanRasterOperations(t *testing.T) {
	for _, test := range []struct {
		name string
		rop  byte
		want [3]byte
	}{
		{name: "PATAND", rop: 0xa0, want: [3]byte{0x02, 0x30, 0x02}},
		{name: "PATOR", rop: 0xfa, want: [3]byte{0x1f, 0xf4, 0xfe}},
	} {
		t.Run(test.name, func(t *testing.T) {
			framebuffer, err := NewRDPFramebuffer(8, 8)
			if err != nil {
				t.Fatal(err)
			}
			seedOrder := mcsTestPatBltOrder(0x01, false, 2, 3, 2, 2, 0xf0, [3]byte{}, [3]byte{0x12, 0x34, 0x56}, 0)
			seedUpdate, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, seedOrder, 0, 0), 0x000103ea, 8, 8)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := framebuffer.Apply(seedUpdate, time.Unix(8, 0)); err != nil {
				t.Fatal(err)
			}

			order := mcsTestPatBltOrder(0x09, true, 2, 3, 2, 2, test.rop, [3]byte{}, [3]byte{0x0f, 0xf0, 0xaa}, 0)
			update, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, order, 0, 0), 0x000103ea, 8, 8)
			if err != nil {
				t.Fatal(err)
			}
			message, err := framebuffer.Apply(update, time.Unix(9, 0))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := png.Decode(bytes.NewReader(message.PNG))
			if err != nil {
				t.Fatal(err)
			}
			for y := 3; y < 5; y++ {
				for x := 2; x < 4; x++ {
					r, g, b, a := decoded.At(x, y).RGBA()
					if r != uint32(test.want[0])*257 || g != uint32(test.want[1])*257 || b != uint32(test.want[2])*257 || a != 0xffff {
						t.Fatalf("%s pixel (%d,%d) = (%x,%x,%x,%x), want %v/opaque", test.name, x, y, r, g, b, a, test.want)
					}
				}
			}
		})
	}
}

func TestRDPFramebufferAppliesPatBltOrder(t *testing.T) {
	order := mcsTestPatBltOrder(0x01, false, 2, 3, 2, 2, 0xf0, [3]byte{0xff, 0xff, 0xff}, [3]byte{0x12, 0x34, 0x56}, 0)
	update, err := parseRDPBitmapShareData(mcsTestOrdersShareData(0x000103ea, 1, order, 0, 0), 0x000103ea, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	message, err := framebuffer.Apply(update, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(message.PNG))
	if err != nil {
		t.Fatal(err)
	}
	for y := 3; y < 5; y++ {
		for x := 2; x < 4; x++ {
			r, g, b, a := decoded.At(x, y).RGBA()
			if r != 0x12*257 || g != 0x34*257 || b != 0x56*257 || a != 0xffff {
				t.Fatalf("pixel (%d,%d) = (%x,%x,%x,%x)", x, y, r, g, b, a)
			}
		}
	}
}

func TestReadBitmapUpdateRejectsUnnegotiatedPrimaryOrders(t *testing.T) {
	cases := []struct {
		name                    string
		order                   []byte
		primaryOrdersEnabled    bool
		patBltOpaqueRectEnabled bool
		dstBltEnabled           bool
		scrBltEnabled           bool
		multiDstBltEnabled      bool
	}{
		{
			name:                 "all primary orders disabled",
			order:                mcsTestOpaqueRectOrder(0x09, true, 0, 0, 1, 1, 0x11, 0x22, 0x33),
			primaryOrdersEnabled: false,
		},
		{
			name:                 "DstBlt negotiation index disabled",
			order:                mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x00),
			primaryOrdersEnabled: true,
		},
		{
			name:                 "PatBlt/OpaqueRect shared negotiation index disabled",
			order:                mcsTestOpaqueRectOrder(0x09, true, 0, 0, 1, 1, 0x11, 0x22, 0x33),
			primaryOrdersEnabled: true,
		},
		{
			name:                 "ScrBlt negotiation index disabled",
			order:                mcsTestScrBltOrder(0x09, true, 1, 1, 1, 1, 0xcc, 0, 0),
			primaryOrdersEnabled: true,
		},
		{
			name:                 "MultiDstBlt negotiation index disabled",
			order:                mcsTestMultiDstBltOrder(0x09, true, 1, 1, 1, 1, rdpDstBltBlackness, 1, []byte{0x00, 1, 0, 1, 1}),
			primaryOrdersEnabled: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			certificate, roots, _ := rdpTestCertificate(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			const shareID = uint32(0x000103ea)
			packet := mcsTestOrdersUpdatePacket(shareID, 1, test.order)
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

			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
			if err := tlsConn.Handshake(); err != nil {
				t.Fatal(err)
			}
			session := &CredSSPClientSession{
				transport:               &Transport{Conn: tlsConn},
				connectionFinalized:     true,
				capabilitiesExchanged:   true,
				primaryOrdersEnabled:    test.primaryOrdersEnabled,
				patBltOpaqueRectEnabled: test.patBltOpaqueRectEnabled,
				dstBltEnabled:           test.dstBltEnabled,
				scrBltEnabled:           test.scrBltEnabled,
				multiDstBltEnabled:      test.multiDstBltEnabled,
				mcsResponse:             MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
				serverCapabilities:      RDPServerCapabilities{ShareID: shareID, DesktopWidth: 8, DesktopHeight: 8},
			}
			if update, readErr := session.ReadBitmapUpdate(context.Background(), time.Second); !errors.Is(readErr, ErrMCSConnection) || len(update.Rectangles) != 0 {
				t.Fatalf("unnegotiated orders update = %+v, err=%v", update, readErr)
			}
			session.mu.Lock()
			transportClosed := session.transport == nil
			session.mu.Unlock()
			if !transportClosed {
				t.Fatal("unnegotiated primary order did not close the transport")
			}
			if serverErr := <-serverResult; serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

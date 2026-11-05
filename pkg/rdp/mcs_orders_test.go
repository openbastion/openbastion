package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"image/png"
	"net"
	"testing"
	"time"
)

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

func TestParseRDPOrdersUpdateDecodesDstBltConstantRasterOperations(t *testing.T) {
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
			wantPixel := []byte{test.color[0], test.color[1], test.color[2], 0xff}
			for offset := 0; offset < len(rect.Pixels); offset += 4 {
				if !bytes.Equal(rect.Pixels[offset:offset+4], wantPixel) {
					t.Fatalf("DstBlt pixel %d = %v, want %v", offset/4, rect.Pixels[offset:offset+4], wantPixel)
				}
			}
		})
	}
}

func TestParseRDPOrdersUpdateRejectsUnsupportedDstBltProfiles(t *testing.T) {
	valid := mcsTestDstBltOrder(0x09, true, 1, 1, 2, 2, 0x00)
	cases := map[string][]byte{
		"destination-dependent ROP":   mcsTestDstBltOrder(0x09, true, 1, 1, 2, 2, 0x55),
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

func TestParseRDPOrdersUpdateRejectsUnsupportedPatBltProfiles(t *testing.T) {
	valid := mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0)
	cases := map[string][]byte{
		"unsupported ROP":       mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0xcc, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"non-solid brush":       mcsTestPatBltOrder(0x09, true, 1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 2),
		"incomplete field mask": func() []byte { out := append([]byte(nil), valid...); out[2] = 0x3f; return out }(),
		"unexpected field mask": func() []byte { out := append([]byte(nil), valid...); out[3] = 0x03; return out }(),
		"negative coordinate":   mcsTestPatBltOrder(0x09, true, -1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"outside desktop":       mcsTestPatBltOrder(0x09, true, 7, 7, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"zero width":            mcsTestPatBltOrder(0x09, true, 1, 1, 0, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
		"truncated order":       valid[:len(valid)-1],
		"delta coordinates":     mcsTestPatBltOrder(0x19, true, 1, 1, 2, 2, 0xf0, [3]byte{1, 2, 3}, [3]byte{4, 5, 6}, 0),
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
	f.Add(mcsTestOrdersUpdateData(1, mcsTestPatBltOrder(0x01, false, 0, 0, 1, 1, 0xf0, [3]byte{}, [3]byte{0xff, 0xff, 0xff}, 0), 0, 0))
	f.Add(mcsTestOrdersUpdateData(1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, 0x00), 0, 0))
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
		mcsResponse:             MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities:      RDPServerCapabilities{ShareID: shareID, DesktopWidth: 8, DesktopHeight: 8},
	}
	for i, want := range [][]byte{{0x00, 0x00, 0x00, 0xff}, {0x11, 0x22, 0x33, 0xff}, {0xaa, 0xbb, 0xcc, 0xff}} {
		update, readErr := session.ReadBitmapUpdate(context.Background(), time.Second)
		if readErr != nil || len(update.Rectangles) != 1 || string(update.Rectangles[0].Pixels) != string(want) {
			t.Fatalf("ReadBitmapUpdate #%d = %+v, err=%v", i, update, readErr)
		}
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

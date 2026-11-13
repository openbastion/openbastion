package rdp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
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
		"wrong MCS channel":                mutateBitmapMCS(base, func(mcs []byte) { mcs[4]++ }),
		"wrong MCS segmentation":           mutateBitmapMCS(base, func(mcs []byte) { mcs[5] = 0x71 }),
		"wrong share data PDU":             mutateBitmapShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[2:4], 0x0018) }),
		"wrong share id":                   mutateBitmapShare(base, func(share []byte) { binary.LittleEndian.PutUint32(share[6:10], 0) }),
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

func TestParseRDPBitmapUpdateAcceptsLargeBoundedTPKT(t *testing.T) {
	const shareID = uint32(0x000103ea)
	pixels := make([]byte, 63*63*4)
	packet := mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(0, 0, 63, 63, 32, 0, pixels))
	if len(packet) <= maxTPKTPacket || len(packet) > maxRDPBitmapTPKTPacket {
		t.Fatalf("fixture length = %d, want (%d, %d]", len(packet), maxTPKTPacket, maxRDPBitmapTPKTPacket)
	}
	got, err := parseRDPBitmapUpdate(packet, mcsGlobalChannelID, shareID, 1280, 720)
	if err != nil || len(got.Rectangles) != 1 || len(got.Rectangles[0].Pixels) != len(pixels) {
		t.Fatalf("large bitmap decode = rectangles %d, err %v", len(got.Rectangles), err)
	}
	oversized := append([]byte(nil), packet...)
	oversized = append(oversized, 0)
	binary.BigEndian.PutUint16(oversized[2:4], uint16(len(oversized)))
	if _, err := parseRDPBitmapUpdate(oversized, mcsGlobalChannelID, shareID, 1280, 720); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("oversized packet error = %v, want ErrMCSConnection", err)
	}
}

func TestReadBitmapUpdateOverTLSAcceptsLargeBoundedTPKT(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const shareID = uint32(0x000103ea)
	pixels := make([]byte, 63*63*4)
	packet := mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(0, 0, 63, 63, 32, 0, pixels))
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
		transport:             &Transport{Conn: tlsConn},
		connectionFinalized:   true,
		capabilitiesExchanged: true,
		mcsResponse:           MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities:    RDPServerCapabilities{ShareID: shareID, DesktopWidth: 1280, DesktopHeight: 720},
	}
	got, err := session.ReadBitmapUpdate(context.Background(), time.Second)
	if err != nil || len(got.Rectangles) != 1 || len(got.Rectangles[0].Pixels) != len(pixels) {
		t.Fatalf("ReadBitmapUpdate = rectangles %d, err %v", len(got.Rectangles), err)
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	session.Close()
}

func TestReadBitmapUpdateOverTLSReassemblesMCSFragments(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const shareID = uint32(0x000103ea)
	pixels := make([]byte, 120*120*4)
	for i := 0; i < len(pixels); i += 4 {
		pixels[i+2] = 0x7f // BGRX wire order; decoded red must be 0x7f.
	}
	userData := mcsTestBitmapUpdateUserData(shareID, mcsTestBitmapRectangle(10, 20, 120, 120, 32, 0, pixels))
	if len(userData) <= 3*maxRDPBitmapTPKTPacket {
		t.Fatalf("fixture userData = %d bytes; want more than three fragments", len(userData))
	}
	const chunk = 14_000
	var fragments [][]byte
	for offset, index := 0, 0; offset < len(userData); index++ {
		end := offset + chunk
		if end > len(userData) {
			end = len(userData)
		}
		segmentation := byte(0) // middle
		if index == 0 {
			segmentation = 2 // begin
		} else if end == len(userData) {
			segmentation = 1 // end
		}
		fragments = append(fragments, mcsTestBitmapFragment(userData[offset:end], segmentation))
		offset = end
	}
	if len(fragments) != 5 {
		t.Fatalf("fragment count = %d, want 5", len(fragments))
	}
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
			for _, fragment := range fragments {
				if acceptErr = writeFull(tlsConn, fragment); acceptErr != nil {
					break
				}
			}
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
		transport:             &Transport{Conn: tlsConn},
		connectionFinalized:   true,
		capabilitiesExchanged: true,
		mcsResponse:           MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities:    RDPServerCapabilities{ShareID: shareID, DesktopWidth: 1280, DesktopHeight: 720},
	}
	got, err := session.ReadBitmapUpdate(context.Background(), time.Second)
	if err != nil || len(got.Rectangles) != 1 || len(got.Rectangles[0].Pixels) != len(pixels) {
		t.Fatalf("ReadBitmapUpdate = rectangles %d, err %v", len(got.Rectangles), err)
	}
	if got.Rectangles[0].Pixels[0] != 0x7f || got.Rectangles[0].Pixels[3] != 0xff {
		t.Fatalf("decoded first pixel = %v, want [127 0 0 255]", got.Rectangles[0].Pixels[:4])
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	session.Close()
}

func TestReadBitmapUpdateOverTLSRejectsRepeatedBeginFragment(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const shareID = uint32(0x000103ea)
	userData := mcsTestBitmapUpdateUserData(shareID, mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 0, 0}))
	first := mcsTestBitmapFragment(userData[:len(userData)/2], 2)
	second := mcsTestBitmapFragment(userData[len(userData)/2:], 2)
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
			acceptErr = writeFull(tlsConn, append(first, second...))
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
		transport:             &Transport{Conn: tlsConn},
		connectionFinalized:   true,
		capabilitiesExchanged: true,
		mcsResponse:           MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities:    RDPServerCapabilities{ShareID: shareID, DesktopWidth: 1280, DesktopHeight: 720},
	}
	if _, err := session.ReadBitmapUpdate(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("repeated begin error = %v, want ErrMCSConnection", err)
	}
	if session.transport != nil {
		t.Fatal("malformed fragment sequence did not close TLS transport")
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func mcsTestBitmapFragment(userData []byte, segmentation byte) []byte {
	mcs := []byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x40 | ((segmentation & 0x03) << 4)}
	mcs = appendPERLength(mcs, len(userData))
	mcs = append(mcs, userData...)
	packet := make([]byte, 7+len(mcs))
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
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
	userData := mcsTestBitmapUpdateUserData(shareID, rectangles...)
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

func mcsTestBitmapUpdateUserData(shareID uint32, rectangles ...[]byte) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[:2], rdpUpdateBitmap)
	binary.LittleEndian.PutUint16(payload[2:4], uint16(len(rectangles)))
	for _, rectangle := range rectangles {
		payload = append(payload, rectangle...)
	}
	share := make([]byte, 18+len(payload))
	binary.LittleEndian.PutUint16(share[:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint16(share[4:6], rdpServerChannelID)
	binary.LittleEndian.PutUint32(share[6:10], shareID)
	share[11] = 2
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(share)))
	share[14] = rdpPDU2Update
	copy(share[18:], payload)
	return share
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

func TestParseRDPBitmapUpdateDecodesRDP6ARGBRawPlanes(t *testing.T) {
	const shareID = uint32(0x000103ea)
	stream := []byte{0x20, 0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff}
	compressed := mcsTestRDP6BitmapData(4, 1, stream)
	packet := mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(0, 0, 4, 1, 32, rdpBitmapCompressed, compressed))
	got, err := parseRDPBitmapUpdate(packet, mcsGlobalChannelID, shareID, 1280, 720)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xff, 0, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if pixels := got.Rectangles[0].Pixels; string(pixels) != string(want) {
		t.Fatalf("decoded RGBA = %v, want %v", pixels, want)
	}
}

func TestDecodeRDP6BitmapUsesBottomUpPlaneRows(t *testing.T) {
	stream := []byte{0x20}
	stream = append(stream, 1, 2, 3, 4, 5, 6, 7, 8) // red, bottom row first
	stream = append(stream, 11, 12, 13, 14, 15, 16, 17, 18)
	stream = append(stream, 21, 22, 23, 24, 25, 26, 27, 28)
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 2, stream), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		5, 15, 25, 0xff, 6, 16, 26, 0xff, 7, 17, 27, 0xff, 8, 18, 28, 0xff,
		1, 11, 21, 0xff, 2, 12, 22, 0xff, 3, 13, 23, 0xff, 4, 14, 24, 0xff,
	}
	if string(got) != string(want) {
		t.Fatalf("decoded RGBA = %v, want %v", got, want)
	}
}

func TestDecodeRDP6BitmapWithAlphaAndOptionalPadding(t *testing.T) {
	stream := []byte{0x00, 0x80, 0xff, 0x40, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xee}
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 1, stream), 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	// The alpha plane (0x80, 0xff, 0x40, 0x00) is read, and the colours after it fall in place; the
	// screen stays opaque (ADR-0071, CI run #46).
	want := []byte{1, 5, 9, 0xff, 2, 6, 10, 0xff, 3, 7, 11, 0xff, 4, 8, 12, 0xff}
	if string(got) != string(want) {
		t.Fatalf("decoded RGBA = %v, want %v", got, want)
	}
}

func TestDecodeRDP6BitmapRejectsUnsupportedOrMalformedStreams(t *testing.T) {
	valid := []byte{0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	base := mcsTestRDP6BitmapData(4, 1, valid)
	cases := map[string][]byte{
		"truncated compression header":   base[:7],
		"nonzero first row size":         mutateRDP6Data(base, func(data []byte) { data[0] = 1 }),
		"compressed length mismatch":     mutateRDP6Data(base, func(data []byte) { binary.LittleEndian.PutUint16(data[2:4], 1) }),
		"scan width mismatch":            mutateRDP6Data(base, func(data []byte) { binary.LittleEndian.PutUint16(data[4:6], 8) }),
		"decoded size mismatch":          mutateRDP6Data(base, func(data []byte) { binary.LittleEndian.PutUint16(data[6:8], 4) }),
		"RLE truncated plane":            mcsTestRDP6BitmapData(4, 1, []byte{0x0c, 0x40, 1, 2}),
		"chroma subsampling unsupported": mutateRDP6Data(base, func(data []byte) { data[8] = 0x14 }),
		"reserved format bits":           mutateRDP6Data(base, func(data []byte) { data[8] = 0xc0 }),
		"short plane data":               base[:len(base)-1],
		"trailing data":                  append(append([]byte(nil), base...), 0, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRDP6BitmapWithHeader(data, 4, 1); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
	if _, err := decodeRDP6BitmapWithHeader(base, 3, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("unaligned width error = %v, want ErrMCSConnection", err)
	}
}

func TestDecodeRDP6AYCoCgRestoresColorLossAndClampsRGB(t *testing.T) {
	// CLL=1 restores signed Co/Cg samples by one bit before inverse conversion.
	// The expected values follow the MS-RDPEGDI inverse AYCoCg matrix.
	stream := []byte{0x21}                      // CLL=1, no alpha, no subsampling, raw planes.
	stream = append(stream, 128, 128, 128, 128) // Y
	stream = append(stream, 64, 64, 64, 64)     // Co = +128 after restoration
	stream = append(stream, 32, 32, 32, 32)     // Cg = +64 after restoration
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 1, stream), 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		160, 160, 32, 0xff, 160, 160, 32, 0xff,
		160, 160, 32, 0xff, 160, 160, 32, 0xff,
	}
	if string(got) != string(want) {
		t.Fatalf("decoded AYCoCg RGBA = %v, want %v", got, want)
	}

	red, green, blue := decodeRDP6AYCoCg(250, 127, 127, 1)
	if red != 250 || green != 255 || blue != 0 {
		t.Fatalf("clamped AYCoCg = (%d,%d,%d), want (250,255,0)", red, green, blue)
	}
	red, green, blue = decodeRDP6AYCoCg(128, 0xc0, 0xe0, 1) // Co=-128, Cg=-64
	if red != 96 || green != 96 || blue != 224 {
		t.Fatalf("negative AYCoCg = (%d,%d,%d), want (96,96,224)", red, green, blue)
	}
	for cll := 1; cll <= 7; cll++ {
		red, green, blue = decodeRDP6AYCoCg(128, 1, 0, cll)
		wantRed := byte(128 + (1 << (cll - 1)))
		wantBlue := byte(128 - (1 << (cll - 1)))
		if red != wantRed || green != 128 || blue != wantBlue {
			t.Fatalf("CLL=%d AYCoCg = (%d,%d,%d), want (%d,128,%d)", cll, red, green, blue, wantRed, wantBlue)
		}
	}

	// The alpha plane is read and bounded, never passed through the color-space transform, and the
	// screen stays opaque: a remote desktop has no transparency, and Windows sends its 32-bpp
	// screen with an alpha plane of zeros (CI run #46), which drew it white (ADR-0071).
	alphaStream := []byte{0x01}
	alphaStream = append(alphaStream, 0x11, 0x22, 0x33, 0x44) // alpha
	alphaStream = append(alphaStream, 128, 128, 128, 128)     // Y
	alphaStream = append(alphaStream, 0, 0, 0, 0)             // Co
	alphaStream = append(alphaStream, 0, 0, 0, 0)             // Cg
	withAlpha, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 1, alphaStream), 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if withAlpha[i*4+3] != 0xff {
			t.Fatalf("pixel %d alpha = %02x, want opaque", i, withAlpha[i*4+3])
		}
	}
}

func TestDecodeRDP6AYCoCgSupportsRLEPlanes(t *testing.T) {
	stream := []byte{0x31}                    // CLL=1, RLE, no alpha.
	for _, value := range []byte{128, 0, 0} { // neutral gray: Y=128, Co=Cg=0
		stream = append(stream, 0x40, value, value, value, value)
	}
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 1, stream), 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(got); i += 4 {
		if got[i] != 128 || got[i+1] != 128 || got[i+2] != 128 || got[i+3] != 0xff {
			t.Fatalf("pixel %d = %v, want opaque neutral gray", i/4, got[i:i+4])
		}
	}
}

func TestDecodeRDP6AYCoCgSubsamplingExpandsOddHeight(t *testing.T) {
	const width, height = 4, 5
	const chromaWidth, chromaHeight = 2, 3
	stream := []byte{0x29} // CLL=1, CS=1, no alpha, raw planes.
	for range width * height {
		stream = append(stream, 128) // full-resolution luma.
	}
	// Chroma rows are encoded bottom-up at ceil(width/2) x ceil(height/2).
	stream = append(stream, 64, 0, 0xc0, 32, 0xe0, 16) // Co: +64, 0 / -64, +32 / -32, +16.
	stream = append(stream, make([]byte, chromaWidth*chromaHeight)...)
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(width, height, stream), width, height)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != width*height*4 {
		t.Fatalf("decoded size = %d, want %d", len(got), width*height*4)
	}
	// Super-sampling replicates each chroma sample to a 2x2 block, cropping
	// the final block to one row for the odd-height edge.
	rowColors := [][]byte{
		{96, 128, 160, 0xff, 96, 128, 160, 0xff, 144, 128, 112, 0xff, 144, 128, 112, 0xff},
		{64, 128, 192, 0xff, 64, 128, 192, 0xff, 160, 128, 96, 0xff, 160, 128, 96, 0xff},
		{64, 128, 192, 0xff, 64, 128, 192, 0xff, 160, 128, 96, 0xff, 160, 128, 96, 0xff},
		{192, 128, 64, 0xff, 192, 128, 64, 0xff, 128, 128, 128, 0xff, 128, 128, 128, 0xff},
		{192, 128, 64, 0xff, 192, 128, 64, 0xff, 128, 128, 128, 0xff, 128, 128, 128, 0xff},
	}
	want := make([]byte, 0, width*height*4)
	for _, row := range rowColors {
		want = append(want, row...)
	}
	if string(got) != string(want) {
		t.Fatalf("decoded subsampled AYCoCg = %v, want %v", got, want)
	}
	const shareID = uint32(0x000103ea)
	bitmapData := mcsTestRDP6BitmapData(width, height, stream)
	packet := mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(0, 0, width, height, 32, rdpBitmapCompressed, bitmapData))
	update, err := parseRDPBitmapUpdate(packet, mcsGlobalChannelID, shareID, 1280, 720)
	if err != nil || len(update.Rectangles) != 1 || string(update.Rectangles[0].Pixels) != string(want) {
		t.Fatalf("Bitmap Update subsampled decode = %+v, err=%v", update, err)
	}
}

// The alpha plane is read and its colours fall in place: the same pixels as without it, opaque.
func TestDecodeRDP6AYCoCgSubsamplingReadsTheAlphaPlane(t *testing.T) {
	const width, height = 4, 3
	stream := []byte{0x09} // CLL=1, CS=1, alpha present, raw planes.
	for i := range width * height {
		stream = append(stream, byte(i+1))
	}
	for range width * height {
		stream = append(stream, 128) // luma.
	}
	stream = append(stream, 64, 0, 0xc0, 0) // Co at 2x2 chroma resolution.
	stream = append(stream, 0, 0, 0, 0)     // Cg at 2x2 chroma resolution.
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(width, height, stream), width, height)
	if err != nil {
		t.Fatal(err)
	}
	withoutAlpha := append([]byte{0x29}, stream[1+width*height:]...) // NA set, the alpha plane gone
	want, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(width, height, withoutAlpha), width, height)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("with the alpha plane: %v\nwithout it: %v", got, want)
	}
	for i := 3; i < len(got); i += 4 {
		if got[i] != 0xff {
			t.Fatalf("alpha %d at byte %d", got[i], i)
		}
	}
}

func TestDecodeRDP6AYCoCgSubsamplingSupportsRLEPlanes(t *testing.T) {
	const width, height = 4, 5
	stream := []byte{0x39} // CLL=1, CS=1, RLE, no alpha.
	appendRLEPlane := func(planeWidth, planeHeight int, firstRow []byte) {
		for y := 0; y < planeHeight; y++ {
			stream = append(stream, byte(planeWidth<<4))
			if y == 0 {
				stream = append(stream, firstRow...)
			} else {
				stream = append(stream, make([]byte, planeWidth)...)
			}
		}
	}
	appendRLEPlane(width, height, []byte{128, 128, 128, 128})
	appendRLEPlane(width/2, (height+1)/2, []byte{64, 0})
	appendRLEPlane(width/2, (height+1)/2, []byte{0, 0})
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(width, height, stream), width, height)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(got); i += 4 {
		want := []byte{192, 128, 64, 0xff}
		if (i/4)%width >= 2 {
			want = []byte{128, 128, 128, 0xff}
		}
		if string(got[i:i+4]) != string(want) {
			t.Fatalf("RLE subsampled pixel %d = %v, want %v", i/4, got[i:i+4], want)
		}
	}
}

func TestDecodeRDP6AYCoCgSubsamplingRejectsTruncatedRLEChromaPlane(t *testing.T) {
	stream := []byte{0x39}                            // CLL=1, CS=1, RLE, no alpha.
	stream = append(stream, 0x40, 128, 128, 128, 128) // full-resolution luma.
	stream = append(stream, 0x20, 64, 0)              // Co, 2x1.
	stream = append(stream, 0x20, 0)                  // truncated Cg, 2x1.
	data := mcsTestRDP6BitmapData(4, 1, stream)
	if _, err := decodeRDP6BitmapWithHeader(data, 4, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("truncated RLE chroma error = %v, want ErrMCSConnection", err)
	}
}

func TestDecodeRDP6BitmapRejectsCSWithoutAYCoCg(t *testing.T) {
	stream := []byte{0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	data := mcsTestRDP6BitmapData(4, 1, stream)
	if _, err := decodeRDP6BitmapWithHeader(data, 4, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("ARGB subsampling error = %v, want ErrMCSConnection", err)
	}
}

func TestDecodeRDP6RLEPlaneMatchesPublishedMSRDPEGDIVector(t *testing.T) {
	// MS-RDPEGDI 3.1.9.2.3, six pixels by three rows.
	encoded := []byte{
		0x13, 0xff, 0x20, 0xfe, 0xfd,
		0x60, 0x01, 0x7d, 0xf5, 0xc2, 0x9a, 0x38,
		0x60, 0x01, 0x67, 0x8b, 0xa3, 0x78, 0xaf,
	}
	got, consumed, err := decodeRDP6RLEPlane(encoded, 6, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		255, 255, 255, 255, 254, 253,
		254, 192, 132, 96, 75, 25,
		253, 140, 62, 14, 135, 193,
	}
	if consumed != len(encoded) || string(got) != string(want) {
		t.Fatalf("decoded=%v consumed=%d, want %v consumed=%d", got, consumed, want, len(encoded))
	}
}

func TestDecodeRDP6BitmapDecodesRLEARGBPlanes(t *testing.T) {
	plane := func(first byte) []byte {
		// First row is absolute; second row encodes +4 deltas (zig-zag 8).
		return []byte{0x40, first, first + 1, first + 2, first + 3, 0x40, 8, 8, 8, 8}
	}
	stream := []byte{0x10} // CLL=0, CS=0, RLE=1, alpha present.
	stream = append(stream, plane(240)...)
	stream = append(stream, plane(10)...)
	stream = append(stream, plane(20)...)
	stream = append(stream, plane(30)...)
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 2, stream), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		14, 24, 34, 255, 15, 25, 35, 255, 16, 26, 36, 255, 17, 27, 37, 255,
		10, 20, 30, 255, 11, 21, 31, 255, 12, 22, 32, 255, 13, 23, 33, 255,
	}
	if string(got) != string(want) {
		t.Fatalf("decoded RGBA = %v, want %v", got, want)
	}
	const shareID = uint32(0x000103ea)
	bitmapData := mcsTestRDP6BitmapData(4, 2, stream)
	packet := mcsTestBitmapUpdatePacket(shareID, mcsTestBitmapRectangle(0, 0, 4, 2, 32, rdpBitmapCompressed, bitmapData))
	update, err := parseRDPBitmapUpdate(packet, mcsGlobalChannelID, shareID, 1280, 720)
	if err != nil || len(update.Rectangles) != 1 || string(update.Rectangles[0].Pixels) != string(want) {
		t.Fatalf("Bitmap Update RLE decode = %+v, err=%v", update, err)
	}
}

func TestDecodeRDP6BitmapDecodesRLEWithoutAlpha(t *testing.T) {
	stream := []byte{0x30} // CLL=0, CS=0, RLE=1, no alpha plane.
	stream = append(stream, 0x40, 10, 11, 12, 13)
	stream = append(stream, 0x40, 20, 21, 22, 23)
	stream = append(stream, 0x40, 30, 31, 32, 33)
	got, err := decodeRDP6BitmapWithHeader(mcsTestRDP6BitmapData(4, 1, stream), 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		10, 20, 30, 0xff, 11, 21, 31, 0xff,
		12, 22, 32, 0xff, 13, 23, 33, 0xff,
	}
	if string(got) != string(want) {
		t.Fatalf("decoded RGBA = %v, want %v", got, want)
	}
}

func TestDecodeRDP6RLEPlaneSupportsRunOnlyAndExtendedRuns(t *testing.T) {
	cases := []struct {
		name  string
		src   []byte
		width int
		want  []byte
	}{
		{name: "run only zero base", src: []byte{0x03}, width: 3, want: []byte{0, 0, 0}},
		{name: "extended run 16", src: []byte{0x01}, width: 16, want: make([]byte, 16)},
		{name: "extended run 32 plus nibble", src: []byte{0x22}, width: 34, want: make([]byte, 34)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, consumed, err := decodeRDP6RLEPlane(tc.src, tc.width, 1)
			if err != nil || consumed != len(tc.src) || string(got) != string(tc.want) {
				t.Fatalf("decode=%v consumed=%d err=%v", got, consumed, err)
			}
		})
	}
}

func TestDecodeRDP6RLEPlaneRejectsMalformedSegments(t *testing.T) {
	cases := map[string][]byte{
		"zero control":         {0x00},
		"truncated raw":        {0x40, 1, 2},
		"raw exceeds row":      {0x50, 1, 2, 3, 4, 5},
		"run exceeds row":      {0x17, 7},
		"extended run exceeds": {0x01},
		"empty row segment":    {0x00},
		"missing second row":   {0x40, 1, 2, 3, 4},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			width, height := 4, 1
			if name == "missing second row" {
				height = 2
			}
			if _, _, err := decodeRDP6RLEPlane(src, width, height); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestDecodeRDP6BitmapRejectsRLETrailingBytes(t *testing.T) {
	plane := []byte{0x40, 1, 2, 3, 4}
	stream := []byte{0x30} // RLE, no alpha.
	for range 3 {
		stream = append(stream, plane...)
	}
	stream = append(stream, 0)
	data := mcsTestRDP6BitmapData(4, 1, stream)
	if _, err := decodeRDP6BitmapWithHeader(data, 4, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("trailing RLE byte error = %v, want ErrMCSConnection", err)
	}
}

func FuzzDecodeRDP6RLEPlane(f *testing.F) {
	f.Add([]byte{0x13, 0xff, 0x20, 0xfe, 0xfd}, 6, 1)
	f.Add([]byte{0x00}, 4, 1)
	f.Add([]byte{0x01}, 16, 1)
	f.Fuzz(func(t *testing.T, src []byte, width, height int) {
		if width < 1 || width > 4096 || height < 1 || height > 4096 ||
			uint64(width)*uint64(height) > maxRDPDesktopArea {
			return
		}
		_, _, _ = decodeRDP6RLEPlane(src, width, height)
	})
}

func FuzzDecodeRDP6BitmapWithHeader(f *testing.F) {
	f.Add(mcsTestRDP6BitmapData(4, 1, []byte{0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
	f.Add(mcsTestRDP6BitmapData(4, 1, []byte{0x24, 128, 128, 128, 128, 64, 64, 64, 64, 32, 32, 32, 32}))
	f.Add(mcsTestRDP6BitmapData(4, 1, []byte{0x34, 128, 128, 128, 128, 64, 0, 0xc0, 0, 0, 0, 0, 0}))
	f.Add(mcsTestRDP6BitmapData(4, 1, []byte{0x3c, 0x40, 128, 128, 128, 128, 0x20, 64, 0, 0x20, 0, 0}))
	rleSeed := []byte{0x30}
	for i := 0; i < 3; i++ {
		rleSeed = append(rleSeed, 0x40, 1, 2, 3, 4)
	}
	f.Add(mcsTestRDP6BitmapData(4, 1, rleSeed))
	f.Add([]byte("invalid RDP6 bitmap"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = decodeRDP6BitmapWithHeader(data, 4, 1) })
}

func mcsTestRDP6BitmapData(width, height uint16, stream []byte) []byte {
	out := make([]byte, 8+len(stream))
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(stream)))
	binary.LittleEndian.PutUint16(out[4:6], width)
	binary.LittleEndian.PutUint16(out[6:8], width*height*4)
	copy(out[8:], stream)
	return out
}

func mutateRDP6Data(data []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), data...)
	mutate(out)
	return out
}

func TestDescribeRDPBitmapRectangles_NamesWhereEachGoes(t *testing.T) {
	rect := []byte{10, 0, 20, 0, 30, 0, 40, 0, 50, 0, 16, 0, 16, 0, 0, 0, 2, 0, 0xaa, 0xbb}
	got := describeRDPBitmapRectangles(append([]byte{1, 0}, rect...))
	if got != "1 rectangle(s); [0] dest 10,20-30,40 size 50x16 16 bpp flags 0x0000 length 2" {
		t.Fatalf("%q", got)
	}
	if got := describeRDPBitmapRectangles([]byte{2, 0, 1}); got != "2 rectangle(s), cut short" {
		t.Fatalf("%q", got)
	}
}

// edgeTileUpdate is a TS_UPDATE_BITMAP_DATA of one raw 16-bpp 64 x 64 tile at left, top: what
// Windows Server 2019 sends at the edges of a desktop that is not a multiple of 64 wide or high.
func edgeTileUpdate(left, top uint16) []byte { return edgeTileUpdateOf(left, top, 64) }

func edgeTileUpdateOf(left, top, side uint16) []byte {
	out := []byte{1, 0}
	header := make([]byte, 18)
	binary.LittleEndian.PutUint16(header[0:2], left)
	binary.LittleEndian.PutUint16(header[2:4], top)
	binary.LittleEndian.PutUint16(header[4:6], left+side-1)
	binary.LittleEndian.PutUint16(header[6:8], top+side-1)
	binary.LittleEndian.PutUint16(header[8:10], side)
	binary.LittleEndian.PutUint16(header[10:12], side)
	binary.LittleEndian.PutUint16(header[12:14], 16)
	binary.LittleEndian.PutUint16(header[16:18], side*side*2)
	out = append(out, header...)
	return append(out, make([]byte, int(side)*int(side)*2)...)
}

// A tile that starts on the desktop and goes past its right or bottom edge by less than a tile is
// clipped to the desktop, as a client does (CI of PR #157: Windows Server 2019 sent a 64 x 64 tile
// at 1088 on a 1102-wide desktop after a resize, and the session ended). Past that, still refused.
func TestBitmapUpdate_ClipsAnEdgeTileToTheDesktop(t *testing.T) {
	update, err := parseRDPBitmapUpdateDataAt(edgeTileUpdate(1088, 832), 1102, 888, 16)
	if err != nil {
		t.Fatalf("an edge tile refused: %v", err)
	}
	r := update.Rectangles[0]
	if r.X != 1088 || r.Y != 832 || r.Width != 14 || r.Height != 56 || len(r.Pixels) != 14*56*4 {
		t.Fatalf("clipped to %d,%d %dx%d (%d bytes), want 1088,832 14x56", r.X, r.Y, r.Width, r.Height, len(r.Pixels))
	}
	for name, at := range map[string][2]uint16{
		"starting past the right edge": {1102, 0},
		"starting past the bottom":     {0, 888},
	} {
		if _, err := parseRDPBitmapUpdateDataAt(edgeTileUpdate(at[0], at[1]), 1102, 888, 16); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	// 64 pixels past the edge or more: not a tile cut at the edge.
	if _, err := parseRDPBitmapUpdateDataAt(edgeTileUpdateOf(1000, 0, 128), 1064, 888, 16); err == nil {
		t.Error("a bitmap 64 pixels past the right edge taken")
	}
	if _, err := parseRDPBitmapUpdateDataAt(edgeTileUpdateOf(1000, 0, 128), 1065, 888, 16); err != nil {
		t.Errorf("a bitmap 63 pixels past the right edge refused: %v", err)
	}
}

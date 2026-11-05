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
	stream := []byte{0x04, 0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff}
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
	stream := []byte{0x04}
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
	want := []byte{1, 5, 9, 0x80, 2, 6, 10, 0xff, 3, 7, 11, 0x40, 4, 8, 12, 0}
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
		"RLE unsupported":                mutateRDP6Data(base, func(data []byte) { data[8] = 0x0c }),
		"AYCoCg unsupported":             mutateRDP6Data(base, func(data []byte) { data[8] = 0x24 }),
		"chroma subsampling unsupported": mutateRDP6Data(base, func(data []byte) { data[8] = 0x14 }),
		"reserved format bits":           mutateRDP6Data(base, func(data []byte) { data[8] = 0x07 }),
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

func FuzzDecodeRDP6BitmapWithHeader(f *testing.F) {
	f.Add(mcsTestRDP6BitmapData(4, 1, []byte{0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
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

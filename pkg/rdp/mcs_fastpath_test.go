package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseRDPFastPathBitmapUpdate(t *testing.T) {
	pixels := []byte{0, 0, 0xff, 0}
	bitmapData := make([]byte, 2)
	binary.LittleEndian.PutUint16(bitmapData, 1)
	bitmapData = append(bitmapData, mcsTestBitmapRectangle(2, 3, 1, 1, 32, 0, pixels)...)
	packet := mcsTestFastPathBitmapPacket(bitmapData)

	got, err := parseRDPFastPathBitmapUpdate(packet, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rectangles) != 1 {
		t.Fatalf("rectangle count = %d, want 1", len(got.Rectangles))
	}
	rect := got.Rectangles[0]
	if rect.X != 2 || rect.Y != 3 || rect.Width != 1 || rect.Height != 1 ||
		!bytes.Equal(rect.Pixels, []byte{0xff, 0, 0, 0xff}) {
		t.Fatalf("decoded rectangle = %+v, pixels %v", rect, rect.Pixels)
	}

	largePixels := make([]byte, 8*8*4)
	largeData := []byte{1, 0}
	largeData = append(largeData, mcsTestBitmapRectangle(0, 0, 8, 8, 32, 0, largePixels)...)
	largePacket := mcsTestFastPathBitmapPacket(largeData)
	if _, err := parseRDPFastPathBitmapUpdate(largePacket, 8, 8); err != nil {
		t.Fatalf("extended-length Fast-Path bitmap: %v", err)
	}
}

func TestParseRDPFastPathBitmapUpdateRejectsUnsupportedForms(t *testing.T) {
	bitmapData := make([]byte, 2)
	binary.LittleEndian.PutUint16(bitmapData, 1)
	bitmapData = append(bitmapData, mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 0, 0})...)
	valid := mcsTestFastPathBitmapPacket(bitmapData)
	tests := map[string][]byte{
		"outer security flags": func() []byte { p := append([]byte(nil), valid...); p[0] = 4; return p }(),
		"wrong update type":    func() []byte { p := append([]byte(nil), valid...); p[2] = 0; return p }(),
		"fragmented":           func() []byte { p := append([]byte(nil), valid...); p[2] = 0x21; return p }(),
		"compressed":           func() []byte { p := append([]byte(nil), valid...); p[2] = 0x81; return p }(),
		"wrong payload size":   func() []byte { p := append([]byte(nil), valid...); binary.LittleEndian.PutUint16(p[3:5], 1); return p }(),
		"trailing data":        append(append([]byte(nil), valid...), 0),
		"truncated":            valid[:len(valid)-1],
		"bad packet length":    func() []byte { p := append([]byte(nil), valid...); p[1]--; return p }(),
	}
	for name, packet := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRDPFastPathBitmapUpdate(packet, 8, 8); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestParseRDPFastPathOrdersUpdateUsesSharedOrderState(t *testing.T) {
	cacheOrder := mcsTestRDPRev2BitmapCacheOrder(0, 2, 2, mcsTestRDP2x2RawBitmap())
	cacheData := mcsTestOrdersUpdateData(1, cacheOrder, 0, 0)
	fastCacheData := append(append([]byte(nil), cacheData[2:4]...), cacheData[6:]...)
	cacheUpdate, state, err := parseRDPFastPathOrdersUpdateAt(fastCacheData, 8, 8, 32, rdpPrimaryOrderState{})
	if err != nil || len(cacheUpdate.Rectangles) != 0 || state.cache == nil || state.cache.bytes != 16 {
		t.Fatalf("Fast-Path cache update=%+v state=%+v err=%v", cacheUpdate, state, err)
	}
	memBlt := mcsTestRDPMemBltOrder(0, 0, 3, 2, 2, 2, 0xcc, 0, 0)
	memData := mcsTestOrdersUpdateData(1, memBlt, 0, 0)
	fastMemData := append(append([]byte(nil), memData[2:4]...), memData[6:]...)
	update, next, err := parseRDPFastPathOrdersUpdateAt(fastMemData, 8, 8, 32, state)
	if err != nil || !next.memBltUsed || len(update.Rectangles) != 1 {
		t.Fatalf("Fast-Path MemBlt update=%+v state=%+v err=%v", update, next, err)
	}
	mem3Blt := mcsTestRDPMem3BltOrder(0, 0, 0, 0, 2, 2, 0xf0, 0, 0, [3]byte{0x12, 0x34, 0x56}, 0)
	mem3Data := mcsTestOrdersUpdateData(1, mem3Blt, 0, 0)
	fastMem3Data := append(append([]byte(nil), mem3Data[2:4]...), mem3Data[6:]...)
	mem3Update, mem3State, err := parseRDPFastPathOrdersUpdateAt(fastMem3Data, 8, 8, 32, next)
	if err != nil || !mem3State.mem3BltUsed || len(mem3Update.Rectangles) != 1 {
		t.Fatalf("Fast-Path Mem3Blt update=%+v state=%+v err=%v", mem3Update, mem3State, err)
	}
	brushOrder := mcsTestRDPCacheBrushOrder(4, rdpBrushFormat24BPP, mcsTestRDPCompressed24BrushData())
	brushData := mcsTestOrdersUpdateData(1, brushOrder, 0, 0)
	fastBrushData := append(append([]byte(nil), brushData[2:4]...), brushData[6:]...)
	brushUpdate, brushState, err := parseRDPFastPathOrdersUpdateAt(fastBrushData, 8, 8, 32, mem3State)
	if err != nil || len(brushUpdate.Rectangles) != 0 || brushState.brushCache == nil {
		t.Fatalf("Fast-Path Cache Brush update=%+v state=%+v err=%v", brushUpdate, brushState, err)
	}
	patBlt := mcsTestRDPPatBltCachedBrushOrder(0, 0, 1, 1, rdpPatBltPatCopy, rdpBrushFormat24BPP, 4, 0, 0)
	patData := mcsTestOrdersUpdateData(1, patBlt, 0, 0)
	fastPatData := append(append([]byte(nil), patData[2:4]...), patData[6:]...)
	patUpdate, patState, err := parseRDPFastPathOrdersUpdateAt(fastPatData, 8, 8, 32, brushState)
	if err != nil || len(patUpdate.Rectangles) != 1 || !patState.patBltOpaqueRectUsed {
		t.Fatalf("Fast-Path cached PatBlt update=%+v state=%+v err=%v", patUpdate, patState, err)
	}
}

func TestParseRDPFastPathOrdersUpdateRejectsMalformedCountsAndOrders(t *testing.T) {
	valid := mcsTestFastPathOrdersPacket(mcsTestOrdersUpdateData(1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, rdpDstBltWhiteness), 0, 0))
	_, _, body, err := splitRDPFastPathUpdate(valid)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"short count":     nil,
		"zero count":      {0, 0},
		"truncated order": {1, 0, rdpOrderStandard | rdpOrderTypeChange},
		"trailing byte":   append(append([]byte(nil), body...), 0),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRDPFastPathOrdersUpdateAt(data, 8, 8, 32, rdpPrimaryOrderState{}); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error=%v, want ErrMCSConnection", err)
			}
		})
	}
}

func FuzzParseRDPFastPathOrdersUpdate(f *testing.F) {
	f.Add(mcsTestFastPathOrdersPacket(mcsTestOrdersUpdateData(1, mcsTestDstBltOrder(0x09, true, 0, 0, 1, 1, rdpDstBltWhiteness), 0, 0))[3:])
	f.Add([]byte{0, 0})
	f.Add([]byte("not a fast-path orders update"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseRDPFastPathOrdersUpdateAt(data, 64, 64, 32, rdpPrimaryOrderState{})
	})
}

func TestReadBitmapUpdateOverTLSAcceptsFastPathOrdersAndCarriesCache(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cacheOrder := mcsTestRDPRev2BitmapCacheOrder(0, 2, 2, mcsTestRDP2x2RawBitmap())
	memBlt := mcsTestRDPMemBltOrder(0, 0, 3, 2, 2, 2, 0xcc, 0, 0)
	cachePacket := mcsTestFastPathOrdersPacket(mcsTestOrdersUpdateData(1, cacheOrder, 0, 0))
	memPacket := mcsTestFastPathOrdersPacket(mcsTestOrdersUpdateData(1, memBlt, 0, 0))
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
			acceptErr = writeFull(tlsConn, append(cachePacket, memPacket...))
		}
		serverResult <- acceptErr
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
		primaryOrdersEnabled: true, memBltEnabled: true,
		mcsResponse:        MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32},
	}
	update, readErr := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
	if readErr != nil || len(update.Rectangles) != 1 || update.Rectangles[0].X != 3 || update.Rectangles[0].Y != 2 ||
		session.primaryOrderState.cache == nil || !session.primaryOrderState.memBltUsed {
		t.Fatalf("ReadBitmapUpdate=%+v state=%+v err=%v", update, session.primaryOrderState, readErr)
	}
	session.Close()
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func mcsTestFastPathOrdersPacket(slowPathOrderData []byte) []byte {
	if len(slowPathOrderData) < 6 {
		return nil
	}
	fastPathData := make([]byte, 2, 2+len(slowPathOrderData)-6)
	copy(fastPathData, slowPathOrderData[2:4])
	fastPathData = append(fastPathData, slowPathOrderData[6:]...)
	update := []byte{rdpFastPathUpdateOrders, 0, 0}
	binary.LittleEndian.PutUint16(update[1:3], uint16(len(fastPathData)))
	update = append(update, fastPathData...)
	packetLength := len(update) + 2
	if packetLength < 128 {
		return append([]byte{0, byte(packetLength)}, update...)
	}
	packetLength++
	return append([]byte{0, 0x80 | byte(packetLength>>8), byte(packetLength)}, update...)
}

func TestReadRDPServerUpdatePacketSupportsBothFramings(t *testing.T) {
	bitmapData := []byte{1, 0, 0, 0}
	fastPath := mcsTestFastPathBitmapPacket(bitmapData)
	got, isFastPath, err := readRDPServerUpdatePacket(bytes.NewReader(fastPath), maxRDPBitmapTPKTPacket)
	if err != nil || !isFastPath || !bytes.Equal(got, fastPath) {
		t.Fatalf("fast-path read = %x, fastPath=%v, err=%v", got, isFastPath, err)
	}

	slowPath := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 0, 0}))
	got, isFastPath, err = readRDPServerUpdatePacket(bytes.NewReader(slowPath), maxRDPBitmapTPKTPacket)
	if err != nil || isFastPath || !bytes.Equal(got, slowPath) {
		t.Fatalf("slow-path read = %x, fastPath=%v, err=%v", got, isFastPath, err)
	}

	// Exercise the two-octet Fast-Path length determinant without relying on
	// bitmap parsing; the packet reader must preserve every byte exactly.
	largeFastPath := mcsTestFastPathBitmapPacket(make([]byte, 200))
	got, isFastPath, err = readRDPServerUpdatePacket(bytes.NewReader(largeFastPath), maxRDPBitmapTPKTPacket)
	if err != nil || !isFastPath || !bytes.Equal(got, largeFastPath) {
		t.Fatalf("extended fast-path read = %d bytes, fastPath=%v, err=%v", len(got), isFastPath, err)
	}

	// FreeRDP uses the long form for small packets too.
	longForm := []byte{0, 0x80, 7, 1, 0, 2, 0}
	if got, isFastPath, err := readRDPServerUpdatePacket(bytes.NewReader(longForm), maxRDPBitmapTPKTPacket); err != nil || !isFastPath || !bytes.Equal(got, longForm) {
		t.Fatalf("long form of a small length: %x, %v, %v", got, isFastPath, err)
	}
}

func TestReadBitmapUpdateOverTLSAcceptsFastPathBitmap(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	const shareID = uint32(0x000103ea)
	bitmapData := []byte{1, 0}
	bitmapData = append(bitmapData, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0})...)
	packet := mcsTestFastPathBitmapPacket(bitmapData)
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
			// A pointer update comes first: the bitmap behind it is what the read returns.
			acceptErr = writeFull(tlsConn, append(fastPathUpdate(0x9, []byte{1, 2}), packet...))
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
		serverCapabilities:    RDPServerCapabilities{ShareID: shareID, DesktopWidth: 8, DesktopHeight: 8},
	}
	got, err := session.ReadBitmapUpdate(context.Background(), time.Second)
	if err != nil || len(got.Rectangles) != 1 || !bytes.Equal(got.Rectangles[0].Pixels, []byte{0xff, 0, 0, 0xff}) {
		t.Fatalf("ReadBitmapUpdate = %+v, err %v", got, err)
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	session.Close()
}

// A refused update says what it was, and keeps its identity (ADR-0071, CI run #38): here a 16-bpp
// rectangle in a 32-bpp session.
func TestReadBitmapUpdateDescribesTheRefusedUpdate(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	bitmapData := []byte{1, 0}
	bitmapData = append(bitmapData, mcsTestBitmapRectangle(1, 2, 1, 1, 16, 0, []byte{0, 0, 0, 0})...)
	packet := mcsTestFastPathBitmapPacket(bitmapData)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if tlsConn.Handshake() == nil {
			_ = writeFull(tlsConn, packet)
		}
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
		transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
		mcsResponse:        MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32},
	}
	defer session.Close()
	_, err = session.ReadBitmapUpdate(context.Background(), time.Second)
	if !errors.Is(err, ErrMCSConnection) || !strings.Contains(err.Error(), "update refused: Fast-Path action 0") ||
		!strings.Contains(err.Error(), "code 1 frag 0 comp 0") {
		t.Fatalf("ReadBitmapUpdate error = %v", err)
	}
}

func FuzzParseRDPFastPathBitmapUpdate(f *testing.F) {
	bitmapData := []byte{1, 0}
	bitmapData = append(bitmapData, mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 0, 0})...)
	f.Add(mcsTestFastPathBitmapPacket(bitmapData))
	f.Add([]byte("not a fast-path packet"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseRDPFastPathBitmapUpdate(packet, 64, 64)
	})
}

func mcsTestFastPathBitmapPacket(bitmapData []byte) []byte {
	update := []byte{rdpFastPathUpdateBitmap, 0, 0, byte(rdpUpdateBitmap), 0}
	binary.LittleEndian.PutUint16(update[1:3], uint16(len(bitmapData)+2))
	update = append(update, bitmapData...)
	packetLength := len(update) + 2
	if packetLength < 128 {
		return append([]byte{0, byte(packetLength)}, update...)
	}
	packetLength++
	return append([]byte{0, 0x80 | byte(packetLength>>8), byte(packetLength)}, update...)
}

// Windows says when the user's session has opened (Save Session Info, MS-RDPBCGR 2.2.10.1.1:
// INFOTYPE_LOGON, _LOGON_LONG, _LOGON_PLAINNOTIFY). The session records it, so that a screen that
// stops at Windows' logon screen is told apart from an open session (ADR-0071, CI runs #39 to #42).
// Extended logon information (3) is not a logon; and without any, nothing is recorded.
func TestReadBitmapUpdateRecordsTheLogonNotification(t *testing.T) {
	saveSessionInfo := func(infoType uint32) []byte {
		share := make([]byte, 18+4+8)
		binary.LittleEndian.PutUint16(share[:2], uint16(len(share)))
		binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
		binary.LittleEndian.PutUint16(share[4:6], rdpServerChannelID)
		binary.LittleEndian.PutUint32(share[6:10], 0x000103ea)
		share[11] = 2
		binary.LittleEndian.PutUint16(share[12:14], uint16(len(share)))
		share[14] = 0x26
		binary.LittleEndian.PutUint32(share[18:22], infoType)
		mcs := []byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x70}
		mcs = appendPERLength(mcs, len(share))
		mcs = append(mcs, share...)
		packet := make([]byte, 7+len(mcs))
		packet[0] = 3
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[4:7], []byte{2, 0xf0, 0x80})
		copy(packet[7:], mcs)
		return packet
	}
	bitmap := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))
	for _, c := range []struct {
		name   string
		before []byte
		want   bool
	}{
		{"logon", saveSessionInfo(0), true},
		{"logon long", saveSessionInfo(1), true},
		{"logon plain notify", saveSessionInfo(2), true},
		{"extended logon information", saveSessionInfo(3), false},
		{"nothing", nil, false},
	} {
		certificate, roots, _ := rdpTestCertificate(t)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func(stream []byte) {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			defer conn.Close()
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			defer tlsConn.Close()
			if tlsConn.Handshake() == nil {
				_ = writeFull(tlsConn, stream)
				var one [1]byte
				_, _ = tlsConn.Read(one[:])
			}
		}(append(append([]byte(nil), c.before...), bitmap...))
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		session := &CredSSPClientSession{
			transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
			mcsResponse:        MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
			serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 8, DesktopHeight: 8, PreferredBitsPerPixel: 32},
		}
		if session.LogonNotified() {
			t.Fatalf("%s: notified before any packet", c.name)
		}
		if _, err := session.ReadBitmapUpdate(context.Background(), time.Second); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := session.LogonNotified(); got != c.want {
			t.Errorf("%s: LogonNotified %v, want %v", c.name, got, c.want)
		}
		session.Close()
		listener.Close()
	}
}

// A Fast-Path PDU is up to 0x7fff bytes (MS-RDPBCGR 2.2.9.1.2: a 15-bit length). Windows' 16-bpp
// raw tiles fill it past 16 383 (CI run #46); the read bounded it there, and refused the update.
// Past 0x7fff, the length cannot be said, and a TPKT of the stream stays bounded where it was.
func TestReadBitmapUpdateAcceptsAFullSizeFastPathPDU(t *testing.T) {
	// 64 x 80 at 32 bpp, raw: 20 480 bytes of pixels.
	pixels := make([]byte, 64*80*4)
	bitmapData := append([]byte{1, 0}, mcsTestBitmapRectangle(0, 0, 64, 80, 32, 0, pixels)...)
	packet := mcsTestFastPathBitmapPacket(bitmapData)
	if len(packet) <= 16_383 || len(packet) > 0x7fff {
		t.Fatalf("the packet is %d bytes", len(packet))
	}
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if tlsConn.Handshake() == nil {
			_ = writeFull(tlsConn, packet)
			var one [1]byte
			_, _ = tlsConn.Read(one[:])
		}
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
		transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
		mcsResponse:        MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 1280, DesktopHeight: 800, PreferredBitsPerPixel: 32},
	}
	defer session.Close()
	update, err := session.ReadBitmapUpdate(context.Background(), time.Second)
	if err != nil || len(update.Rectangles) != 1 {
		t.Fatalf("ReadBitmapUpdate: %v", err)
	}
	// A slow-path TPKT keeps its bound: the same size there is refused.
	tpkt := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(0, 0, 64, 80, 32, 0, pixels))
	if _, _, err := parseRDPBitmapMCSFragment(tpkt, mcsGlobalChannelID); err == nil || len(tpkt) <= maxRDPBitmapTPKTPacket {
		t.Fatalf("a TPKT of %d bytes: %v", len(tpkt), err)
	}
}

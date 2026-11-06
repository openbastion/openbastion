package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
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

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

func TestMarshalRDPInputBuildsBoundedSlowPathInputPDU(t *testing.T) {
	const userID, shareID = uint16(1007), uint32(0x000103ea)
	packet, err := marshalRDPInput(userID, shareID, []RDPInputEvent{
		{Type: RDPInputScancode, Scancode: 0x1d, Extended: true},
		{Type: RDPInputScancode, Scancode: 0x1d, Released: true},
		{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsMove | rdpPtrFlagsButton1 | rdpPtrFlagsDown, X: 0x1234, Y: 0x5678},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	if len(packet) < 7+7+18+4+3*12 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		t.Fatalf("invalid TPKT envelope: %x", packet)
	}
	mcs := packet[7:]
	if mcs[0] != mcsSendDataRequest || binary.BigEndian.Uint16(mcs[1:3]) != userID-mcsUserIDBase || binary.BigEndian.Uint16(mcs[3:5]) != mcsGlobalChannelID {
		t.Fatalf("invalid MCS Send Data Request: %x", mcs)
	}
	length, share, err := readPERLength(mcs[6:])
	if err != nil || length != len(share) || len(share) < 22 || share[14] != rdpPDU2Input ||
		binary.LittleEndian.Uint32(share[6:10]) != shareID || binary.LittleEndian.Uint16(share[18:20]) != 3 {
		t.Fatalf("invalid Share Data Input PDU: len=%d err=%v share=%x", length, err, share)
	}
	first := share[22:34]
	if binary.LittleEndian.Uint16(first[4:6]) != rdpInputEventScancode ||
		binary.LittleEndian.Uint16(first[6:8]) != rdpKBDFlagsDown|rdpKBDFlagsExtended || binary.LittleEndian.Uint16(first[8:10]) != 0x1d {
		t.Fatalf("extended scancode event = %x", first)
	}
	second := share[34:46]
	if binary.LittleEndian.Uint16(second[6:8]) != rdpKBDFlagsRelease {
		t.Fatalf("key release event = %x", second)
	}
	third := share[46:58]
	if binary.LittleEndian.Uint16(third[4:6]) != rdpInputEventMouse ||
		binary.LittleEndian.Uint16(third[6:8]) != rdpPtrFlagsMove|rdpPtrFlagsButton1|rdpPtrFlagsDown ||
		binary.LittleEndian.Uint16(third[8:10]) != 0x1234 || binary.LittleEndian.Uint16(third[10:12]) != 0x5678 {
		t.Fatalf("mouse event = %x", third)
	}
}

func TestMarshalRDPInputRejectsMalformedEventsAndBounds(t *testing.T) {
	cases := map[string][]RDPInputEvent{
		"empty":                     nil,
		"too many":                  make([]RDPInputEvent, maxRDPInputEvents+1),
		"unknown type":              {{Type: 99}},
		"zero scancode":             {{Type: RDPInputScancode}},
		"mouse without flags":       {{Type: RDPInputMouse}},
		"keyboard with coordinates": {{Type: RDPInputScancode, Scancode: 0x1e, X: 1}},
	}
	for name, events := range cases {
		t.Run(name, func(t *testing.T) {
			if packet, err := marshalRDPInput(1007, 0x000103ea, events); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
				t.Fatalf("packet len=%d error=%v", len(packet), err)
			}
		})
	}
}

func TestSendInputCanWriteWhileBitmapReaderIsBlocked(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
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
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		input, readErr := readTPKTPacket(tlsConn, maxTPKTPacket)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		if len(input) < 7+7+18+4+12 || input[0] != 3 {
			serverResult <- ErrMCSConnection
			return
		}
		bitmap := mcsTestBitmapUpdatePacket(0x000103ea, mcsTestBitmapRectangle(0, 0, 1, 1, 32, 0, []byte{0, 0, 0, 0}))
		serverResult <- writeFull(tlsConn, bitmap)
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
		mcsResponse:   MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		userChannelID: 1007, serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 1, DesktopHeight: 1},
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := session.ReadBitmapUpdate(context.Background(), time.Second)
		readResult <- readErr
	}()
	if err := session.SendInput(context.Background(), []RDPInputEvent{{Type: RDPInputScancode, Scancode: 0x1e}}, time.Second); err != nil {
		t.Fatalf("SendInput while reader blocked: %v", err)
	}
	if err := <-readResult; err != nil {
		t.Fatalf("ReadBitmapUpdate: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("fake RDP server: %v", err)
	}
	session.Close()
}

func FuzzMarshalRDPInput(f *testing.F) {
	f.Add(byte(RDPInputScancode), byte(0x1e), false, false, uint16(0), uint16(0), uint16(0))
	f.Add(byte(RDPInputScancode), byte(0x1d), true, true, uint16(0), uint16(0), uint16(0))
	f.Add(byte(RDPInputMouse), byte(0), false, false, uint16(rdpPtrFlagsMove), uint16(1024), uint16(768))
	f.Add(byte(RDPInputMouse), byte(0), false, false, uint16(0xffff), uint16(0xffff), uint16(0xffff))
	f.Fuzz(func(t *testing.T, typ, code byte, extended, released bool, flags, x, y uint16) {
		packet, err := marshalRDPInput(1007, 0x000103ea, []RDPInputEvent{{
			Type: RDPInputEventType(typ), Scancode: code, Extended: extended, Released: released,
			PointerFlags: flags, X: x, Y: y,
		}})
		if err != nil {
			if len(packet) != 0 {
				t.Fatal("invalid event returned a packet")
			}
			return
		}
		defer clear(packet)
		if len(packet) < 7+7+18+4+12 || len(packet) > maxTPKTPacket ||
			int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			t.Fatalf("successful marshal returned invalid packet length %d", len(packet))
		}
	})
}

func TestCloseInterruptsBlockedBitmapRead(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
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
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		_, readErr := readTPKTPacket(tlsConn, maxRDPBitmapTPKTPacket)
		if readErr == nil {
			serverResult <- errors.New("unexpected client packet")
			return
		}
		serverResult <- nil
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
		mcsResponse:   MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		userChannelID: 1007, serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 1, DesktopHeight: 1},
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := session.ReadBitmapUpdate(context.Background(), 24*time.Hour)
		readResult <- readErr
	}()
	session.Close()
	select {
	case err := <-readResult:
		if !errors.Is(err, ErrMCSConnection) {
			t.Fatalf("blocked read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt blocked TLS bitmap read")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

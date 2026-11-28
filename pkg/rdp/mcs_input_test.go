package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
		// A press carries no KBDFLAGS_DOWN: that flag says the key was already down, a repeat
		// (MS-RDPBCGR 2.2.8.1.1.3.1.1.1). Sent on every press, Windows lost keys (CI run #48).
		binary.LittleEndian.Uint16(first[6:8]) != rdpKBDFlagsExtended || binary.LittleEndian.Uint16(first[8:10]) != 0x1d {
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

func TestMarshalRDPInputBuildsUnicodeKeyboardEvents(t *testing.T) {
	units := []uint16{0x0041, 0x6c34, 0xd83d, 0xde42}
	events := make([]RDPInputEvent, 0, len(units)*2)
	for _, unit := range units {
		events = append(events, RDPInputEvent{Type: RDPInputUnicode, Unicode: unit}, RDPInputEvent{Type: RDPInputUnicode, Unicode: unit, Released: true})
	}
	packet, err := marshalRDPInput(1007, 0x000103ea, events)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	_, share, err := readPERLength(packet[7+6:])
	if err != nil {
		t.Fatal(err)
	}
	if share[14] != rdpPDU2Input || binary.LittleEndian.Uint16(share[18:20]) != uint16(len(events)) {
		t.Fatalf("Unicode Input PDU header = %x", share[:22])
	}
	for i, event := range events {
		entry := share[22+i*12 : 34+i*12]
		wantFlags := uint16(0)
		if event.Released {
			wantFlags = rdpKBDFlagsRelease
		}
		if binary.LittleEndian.Uint16(entry[4:6]) != rdpInputEventUnicode ||
			binary.LittleEndian.Uint16(entry[6:8]) != wantFlags ||
			binary.LittleEndian.Uint16(entry[8:10]) != event.Unicode || binary.LittleEndian.Uint16(entry[10:12]) != 0 {
			t.Fatalf("Unicode event %d = %x", i, entry)
		}
	}
	for name, bad := range map[string]RDPInputEvent{
		"zero code unit":              {Type: RDPInputUnicode},
		"scancode mixed":              {Type: RDPInputUnicode, Unicode: 'a', Scancode: 0x1e},
		"pointer mixed":               {Type: RDPInputUnicode, Unicode: 'a', PointerFlags: rdpPtrFlagsMove},
		"Unicode mixed into sync":     {Type: RDPInputSync, Unicode: 'a'},
		"Unicode mixed into scancode": {Type: RDPInputScancode, Scancode: 0x1e, Unicode: 'a'},
		"Unicode mixed into mouse":    {Type: RDPInputMouse, Unicode: 'a', PointerFlags: rdpPtrFlagsMove},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := marshalRDPInput(1007, 0x000103ea, []RDPInputEvent{bad}); !errors.Is(err, ErrMCSConnection) || len(got) != 0 {
				t.Fatalf("packet len=%d err=%v", len(got), err)
			}
		})
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

func TestMarshalRDPFastPathInputEncodesSupportedEvents(t *testing.T) {
	events := []RDPInputEvent{
		{Type: RDPInputScancode, Scancode: 0x1d, Extended: true},
		{Type: RDPInputScancode, Scancode: 0x1d, Released: true},
		{Type: RDPInputUnicode, Unicode: 0x6c34},
		{Type: RDPInputUnicode, Unicode: 0x6c34, Released: true},
		{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsMove | rdpPtrFlagsButton1 | rdpPtrFlagsDown, X: 0x1234, Y: 0x5678},
		{Type: RDPInputSync, ToggleFlags: 0x2},
	}
	packet, err := marshalRDPFastPathInput(events)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	if packet[0] != byte(len(events)<<2) || int(packet[1]) != len(packet) || len(packet) != 20 {
		t.Fatalf("Fast-Path header/length = %x", packet)
	}
	want := []byte{
		0x10, 0x1d, // extended scancode
		0x08, 0x1d, // release scancode
		0x04, 0x34, 0x6c, // Unicode
		0x0c, 0x34, 0x6c, // Unicode release
		0x01, 0x00, 0x98, 0x34, 0x12, 0x78, 0x56, // absolute mouse
		0x13, // synchronize: toggle flags are in the five event-header flag bits
	}
	if !bytes.Equal(packet[2:], want) {
		t.Fatalf("Fast-Path events = %x, want %x", packet[2:], want)
	}
}

func TestMarshalRDPFastPathInputUsesNegotiatedCapabilities(t *testing.T) {
	unicode := []RDPInputEvent{{Type: RDPInputUnicode, Unicode: 'A'}}
	if fastPathInputEventsSupported(unicode, rdpInputFlagFastPathInput2) {
		t.Fatal("Unicode accepted without negotiated Unicode capability")
	}
	if !fastPathInputEventsSupported(unicode, rdpInputFlagFastPathInput2|rdpInputFlagUnicode) {
		t.Fatal("Unicode rejected despite negotiated capabilities")
	}
	if fastPathInputEventsSupported([]RDPInputEvent{{Type: RDPInputScancode, Scancode: 0x1e}}, rdpInputFlagScancodes) {
		t.Fatal("Fast-Path accepted without FASTPATH_INPUT2")
	}
	if fastPathInputEventsSupported([]RDPInputEvent{{Type: RDPInputEventType(99)}}, rdpInputFlagFastPathInput2) {
		t.Fatal("unknown event accepted")
	}
}

func TestMarshalRDPFastPathInputRejectsMalformedEvents(t *testing.T) {
	cases := map[string]RDPInputEvent{
		"zero scancode":       {Type: RDPInputScancode},
		"scancode mixed":      {Type: RDPInputScancode, Scancode: 0x1e, Unicode: 'A'},
		"zero Unicode":        {Type: RDPInputUnicode},
		"Unicode extended":    {Type: RDPInputUnicode, Unicode: 'A', Extended: true},
		"mouse without flags": {Type: RDPInputMouse},
		"sync unknown toggle": {Type: RDPInputSync, ToggleFlags: 0x10},
		"unknown type":        {Type: RDPInputEventType(99)},
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			if packet, err := marshalRDPFastPathInput([]RDPInputEvent{event}); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
				t.Fatalf("packet=%x err=%v", packet, err)
			}
		})
	}
	if packet, err := marshalRDPFastPathInput(nil); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
		t.Fatalf("empty: packet=%x err=%v", packet, err)
	}
}

func TestMarshalRDPFastPathInputLengthAndEventCountBoundaries(t *testing.T) {
	for _, count := range []int{1, 15, 16, 128} {
		events := make([]byte, count)
		packet, err := marshalRDPFastPathInputPDU(events, count)
		if err != nil {
			t.Fatalf("count %d: %v", count, err)
		}
		if count <= 15 && packet[0] != byte(count<<2) {
			t.Fatalf("count %d inline header = %#x", count, packet[0])
		}
		if count > 15 && (packet[0] != 0 || packet[2+boolInt(len(packet) > 127)] != byte(count)) {
			t.Fatalf("count %d extended header = %x", count, packet[:4])
		}
		clear(packet)
	}
	// Exercise both legal length encodings directly, including the 16,383-byte cap.
	for _, tc := range []struct {
		name          string
		payload, want int
	}{
		{name: "short maximum", payload: 125, want: 127},
		{name: "first extended encoding", payload: 126, want: 129},
		{name: "maximum PDU", payload: rdpFastPathInputMaxPDU - 3, want: rdpFastPathInputMaxPDU},
	} {
		encoded, err := marshalRDPFastPathInputPDU(make([]byte, tc.payload), 1)
		if err != nil || len(encoded) != tc.want {
			t.Fatalf("%s: len=%d want=%d err=%v", tc.name, len(encoded), tc.want, err)
		}
		clear(encoded)
	}
	if packet, err := marshalRDPFastPathInputPDU(make([]byte, rdpFastPathInputMaxPDU), 1); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
		t.Fatalf("oversize: len=%d err=%v", len(packet), err)
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestSendInputUsesFastPathOnlyAfterNegotiation(t *testing.T) {
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
		header := make([]byte, 2)
		if _, acceptErr = io.ReadFull(tlsConn, header); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if header[0] != 0x04 || header[1] != 4 {
			serverResult <- fmt.Errorf("unexpected Fast-Path header %x", header)
			return
		}
		event := make([]byte, 2)
		if _, acceptErr = io.ReadFull(tlsConn, event); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if !bytes.Equal(event, []byte{0, 0x1e}) {
			serverResult <- fmt.Errorf("unexpected Fast-Path event %x", event)
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
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, userChannelID: 1007,
		serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, InputFlags: rdpInputFlagScancodes | rdpInputFlagUnicode | rdpInputFlagFastPathInput2},
	}
	if err := session.SendInput(context.Background(), []RDPInputEvent{{Type: RDPInputScancode, Scancode: 0x1e}}, time.Second); err != nil {
		t.Fatalf("SendInput: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	session.Close()
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
	cachePixels := []byte{1, 2, 3, 0xff}
	cacheState := rdpPrimaryOrderState{}
	if err := storeRDPBitmapCache(&cacheState, 0, 1, 1, cachePixels); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: tlsConn}, connectionFinalized: true, capabilitiesExchanged: true,
		mcsResponse:   MCSConnectResponse{IOChannelID: mcsGlobalChannelID},
		userChannelID: 1007, serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea, DesktopWidth: 1, DesktopHeight: 1},
		primaryOrderState: cacheState,
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
	if session.primaryOrderState.cache != nil || cachePixels[0] != 0 {
		t.Fatalf("blocked read did not release and erase its cache: state=%+v pixels=%v", session.primaryOrderState, cachePixels)
	}
}

// TS_SYNC_EVENT (MS-RDPBCGR 2.2.8.1.1.3.1.1.5): messageType 0, two pad bytes, the toggle keys'
// state (scroll, num, caps, kana lock in the low four bits). Anything else in the event is refused.
func TestMarshalRDPInputSynchronize(t *testing.T) {
	packet, err := marshalRDPInput(1007, 0x000103ea, []RDPInputEvent{{Type: RDPInputSync, ToggleFlags: 0x2}})
	if err != nil {
		t.Fatal(err)
	}
	_, share, err := readPERLength(packet[7+6:])
	if err != nil {
		t.Fatal(err)
	}
	event := share[22:34]
	if binary.LittleEndian.Uint16(event[4:6]) != 0 || binary.LittleEndian.Uint16(event[6:8]) != 0 ||
		binary.LittleEndian.Uint32(event[8:12]) != 0x2 {
		t.Fatalf("sync event = %x", event)
	}
	for name, bad := range map[string]RDPInputEvent{
		"unknown toggle bit": {Type: RDPInputSync, ToggleFlags: 0x10},
		"with a scancode":    {Type: RDPInputSync, Scancode: 0x0f},
		"with pointer flags": {Type: RDPInputSync, PointerFlags: rdpPtrFlagsMove},
		"released":           {Type: RDPInputSync, Released: true},
		"toggle on a key":    {Type: RDPInputScancode, Scancode: 0x0f, ToggleFlags: 1},
	} {
		if _, err := marshalRDPInput(1007, 0x000103ea, []RDPInputEvent{bad}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

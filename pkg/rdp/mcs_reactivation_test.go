package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	reactivationOldShare = uint32(0x000103ea)
	reactivationNewShare = uint32(0x000203ea)
)

// mcsTestServerShare wraps a Share Control PDU as the server sends it on the I/O channel.
func mcsTestServerShare(share []byte) []byte {
	mcs := appendPERLength([]byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x70}, len(share))
	mcs = append(mcs, share...)
	packet := append([]byte{3, 0, 0, 0, 2, 0xf0, 0x80}, mcs...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	return packet
}

// testDeactivateAll is a TS_DEACTIVATE_ALL_PDU as FreeRDP sends it: a one-byte source descriptor.
func testDeactivateAll(shareID uint32) []byte {
	share := []byte{13, 0, 0x16, 0, 0xea, 0x03, 0, 0, 0, 0, 1, 0, 0}
	binary.LittleEndian.PutUint32(share[6:10], shareID)
	return share
}

// testReactivationDemandActive is a Demand Active of another share and another desktop size.
func testReactivationDemandActive(shareID uint32, width, height uint16) []byte {
	sets := mcsTestCapabilitySets()
	binary.LittleEndian.PutUint16(sets[1][12:14], width)
	binary.LittleEndian.PutUint16(sets[1][14:16], height)
	return mutateDemandActiveShare(mcsTestDemandActiveWithCaps(sets), func(share []byte) {
		binary.LittleEndian.PutUint32(share[6:10], shareID)
	})
}

func testFinalizationResponses(shareID uint32) []byte {
	var out []byte
	for _, r := range []struct {
		typ, stream byte
		payload     []byte
	}{
		{rdpPDU2Synchronize, 0, []byte{1, 0, 0, 0}},
		{rdpPDU2Control, 2, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
		{rdpPDU2Control, 2, []byte{2, 0, 0xef, 0x03, 0xea, 0x03, 0, 0}},
		{rdpPDU2FontMap, 2, []byte{0, 0, 0, 0, 3, 0, 4, 0}},
	} {
		out = append(out, mcsTestFinalizationResponse(shareID, r.typ, r.stream, r.payload)...)
	}
	return out
}

// clientShareID reads a client PDU on the I/O channel and returns its share ID and Share Control type.
func clientShareID(conn net.Conn) (uint32, uint16, error) {
	packet, err := readTestTPKT(conn)
	if err != nil {
		return 0, 0, err
	}
	if len(packet) < 14 || packet[7] != mcsSendDataRequest {
		return 0, 0, errors.New("not a Send Data Request")
	}
	_, share, err := readPERLength(packet[13:])
	if err != nil || len(share) < 10 {
		return 0, 0, errors.New("no Share Control PDU")
	}
	return binary.LittleEndian.Uint32(share[6:10]), binary.LittleEndian.Uint16(share[2:4]), nil
}

// reactivationSession connects a session at the old share, 1280x720, to a server that runs script.
func reactivationSession(t *testing.T, script func(net.Conn) error) (*CredSSPClientSession, <-chan error) {
	t.Helper()
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			result <- err
			return
		}
		result <- script(tlsConn)
	}()
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: conn}, credentialsDelegated: true, mcsConnected: true, channelsConnected: true,
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, userChannelID: 1007,
		clientInfoSent: true, licensingComplete: true, capabilitiesExchanged: true, connectionFinalized: true,
		mcsSettings:        MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720},
		serverCapabilities: RDPServerCapabilities{ShareID: reactivationOldShare, DesktopWidth: 1280, DesktopHeight: 720, PreferredBitsPerPixel: 32},
	}
	t.Cleanup(func() { session.Close() })
	return session, result
}

// The sequence of MS-RDPBCGR 1.3.1.3, end to end over TLS: the client confirms the new share and
// finalizes under it, the next update is drawn on the new desktop, and input goes out under it.
func TestReadBitmapUpdateReactivates(t *testing.T) {
	bitmap := append(binary.LittleEndian.AppendUint16(nil, rdpUpdateBitmap), 1, 0)
	bitmap = append(bitmap, mcsTestBitmapRectangle(1000, 700, 1, 1, 32, 0, []byte{0, 0, 0xff, 0})...)
	session, result := reactivationSession(t, func(conn net.Conn) error {
		stream := append(mcsTestServerShare(testDeactivateAll(reactivationOldShare)), testReactivationDemandActive(reactivationNewShare, 1024, 768)...)
		if err := writeFull(conn, stream); err != nil {
			return err
		}
		for i, want := range []uint16{rdpConfirmActivePDU, rdpShareDataPDU, rdpShareDataPDU, rdpShareDataPDU, rdpShareDataPDU} {
			share, typ, err := clientShareID(conn)
			if err != nil || share != reactivationNewShare || typ != want {
				return fmt.Errorf("client PDU %d: share %#x, type %#x, %v", i, share, typ, err)
			}
		}
		if err := writeFull(conn, append(testFinalizationResponses(reactivationNewShare), fastPathPDU(1, 0, bitmap)...)); err != nil {
			return err
		}
		if share, _, err := clientShareID(conn); err != nil || share != reactivationNewShare {
			return fmt.Errorf("input under share %#x: %v", share, err)
		}
		return nil
	})
	// The primary-order state of the old share does not carry over to the new one.
	session.primaryOrderState = rdpPrimaryOrderState{orderType: rdpOrderPolyline, hasOrderType: true}
	update, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("ReadBitmapUpdate: %v", err)
	}
	if session.primaryOrderState.hasOrderType {
		t.Fatal("the primary-order state of the old share survived the reactivation")
	}
	if update.DesktopWidth != 1024 || update.DesktopHeight != 768 || len(update.Rectangles) != 1 || update.Rectangles[0].X != 1000 {
		t.Fatalf("update %dx%d, %d rectangle(s)", update.DesktopWidth, update.DesktopHeight, len(update.Rectangles))
	}
	if session.reactivations != 1 || session.serverCapabilities.ShareID != reactivationNewShare {
		t.Fatalf("%d reactivation(s), share %#x", session.reactivations, session.serverCapabilities.ShareID)
	}
	if err := session.SendInput(context.Background(), []RDPInputEvent{{Type: RDPInputScancode, Scancode: 0x1e}}, time.Second); err != nil {
		t.Fatalf("SendInput: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// What a server cannot make the client do: reactivate another share, skip the Demand Active, keep
// the old share past it, or reactivate without end. Each ends the session.
func TestReadBitmapUpdateRefusesReactivation(t *testing.T) {
	sets := mcsTestCapabilitySets()
	cases := map[string]struct {
		before int
		stream []byte
		want   string
	}{
		"another share": {stream: mcsTestServerShare(testDeactivateAll(0x0000dead)), want: "Deactivate All refused"},
		"no share ID":   {stream: mcsTestServerShare([]byte{6, 0, 0x16, 0, 0xea, 0x03}), want: "Deactivate All refused"},
		"a lying length": {stream: mcsTestServerShare(func() []byte {
			d := testDeactivateAll(reactivationOldShare)
			d[10] = 2
			return d
		}()), want: "Deactivate All refused"},
		"an update instead of the Demand Active": {stream: append(mcsTestServerShare(testDeactivateAll(reactivationOldShare)),
			mcsTestBitmapUpdatePacket(reactivationOldShare, mcsTestBitmapRectangle(1, 2, 1, 1, 32, 0, []byte{0, 0, 0xff, 0}))...), want: "Demand Active refused"},
		"a Demand Active without the input set": {stream: append(mcsTestServerShare(testDeactivateAll(reactivationOldShare)),
			mcsTestDemandActiveWithCaps(sets[:4])...), want: "Demand Active refused"},
		"the finalization under the old share": {stream: append(append(mcsTestServerShare(testDeactivateAll(reactivationOldShare)),
			testReactivationDemandActive(reactivationNewShare, 1024, 768)...), testFinalizationResponses(reactivationOldShare)...), want: "finalization refused"},
		"one too many": {before: maxRDPReactivations, stream: mcsTestServerShare(testDeactivateAll(reactivationOldShare)), want: "reactivation refused"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			session, _ := reactivationSession(t, func(conn net.Conn) error {
				if err := writeFull(conn, c.stream); err != nil {
					return err
				}
				_, _ = conn.Read(make([]byte, 4096)) // until the client closes
				return nil
			})
			session.reactivations = c.before
			_, err := session.ReadBitmapUpdate(context.Background(), 2*time.Second)
			if !errors.Is(err, ErrMCSConnection) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want a refusal saying %q", err, c.want)
			}
			if session.transport != nil && session.transport.Conn != nil {
				if _, err := session.transport.Conn.Write([]byte{0}); err == nil {
					t.Fatal("the transport stays open after a refused reactivation")
				}
			}
		})
	}
}

func TestParseRDPDeactivateAll(t *testing.T) {
	// FreeRDP's shadow server, as recorded (realserver_bytes_test.go).
	real := realServerBytes(t, "0d001600ec03ec030100010000")
	if err := parseRDPDeactivateAll(real, 0x000103ec); err != nil {
		t.Fatalf("FreeRDP's Deactivate All: %v", err)
	}
	if !rdpIsDeactivateAll(real) || rdpIsDeactivateAll(mcsTestFinalizationResponse(1, rdpPDU2Synchronize, 0, []byte{1, 0, 0, 0})[13:]) {
		t.Fatal("rdpIsDeactivateAll")
	}
	withSource := append(testDeactivateAll(reactivationOldShare)[:12:12], 'R', 'D', 'P', 0)
	withSource[0], withSource[10] = byte(len(withSource)), 4
	if err := parseRDPDeactivateAll(withSource, reactivationOldShare); err != nil {
		t.Fatalf("a source descriptor %q: %v", withSource[12:], err)
	}
	control := bytes.Clone(withSource)
	control[13] = 0x07
	for name, bad := range map[string][]byte{
		"another share":         testDeactivateAll(reactivationOldShare + 1),
		"header only":           real[:6],
		"a control character":   control,
		"a total length lie":    append(bytes.Clone(real), 0),
		"another PDU type":      func() []byte { b := bytes.Clone(real); b[2] = 0x11; return b }(),
		"a descriptor too long": func() []byte { b := make([]byte, 12+65); copy(b, real); b[0] = 77; b[10] = 65; return b }(),
	} {
		share := uint32(0x000103ec)
		if name == "another share" || name == "a control character" {
			share = reactivationOldShare
		}
		if parseRDPDeactivateAll(bad, share) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRDPFramebufferResizeKeepsTheSequence(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	first, err := framebuffer.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 7, Y: 7, Width: 1, Height: 1, Pixels: []byte{0xff, 0, 0, 0xff}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := framebuffer.Resize(4, 2); err != nil {
		t.Fatal(err)
	}
	if w, h := framebuffer.Dimensions(); w != 4 || h != 2 {
		t.Fatalf("%dx%d", w, h)
	}
	if _, err := framebuffer.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 7, Y: 7, Width: 1, Height: 1, Pixels: []byte{0xff, 0, 0, 0xff}}}}, time.Now()); err == nil {
		t.Fatal("a rectangle outside the new desktop was drawn")
	}
	next, err := framebuffer.Apply(RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 3, Y: 1, Width: 1, Height: 1, Pixels: []byte{0, 0xff, 0, 0xff}}}}, time.Now())
	if err != nil || next.Sequence != first.Sequence+1 || next.Width != 4 || next.Height != 2 {
		t.Fatalf("after the resize: sequence %d after %d, %dx%d, %v", next.Sequence, first.Sequence, next.Width, next.Height, err)
	}
	for _, bad := range [][2]uint16{{0, 2}, {4, 0}} {
		if framebuffer.Resize(bad[0], bad[1]) == nil {
			t.Errorf("resized to %dx%d", bad[0], bad[1])
		}
	}
}

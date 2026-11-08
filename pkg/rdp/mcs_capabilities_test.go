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

func TestParseRDPDemandActiveValidatesServerCapabilities(t *testing.T) {
	packet := mcsTestDemandActive()
	got, err := parseRDPDemandActive(packet, mcsGlobalChannelID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ShareID != 0x000103ea || got.DesktopWidth != 1280 || got.DesktopHeight != 720 || got.PreferredBitsPerPixel != 32 {
		t.Fatalf("capabilities = %+v", got)
	}
	if len(got.CapabilityTypes) != 5 {
		t.Fatalf("capability types = %v", got.CapabilityTypes)
	}
	// 15 and 16 bpp, which Windows offers when its maximum color depth is left as installed
	// (ADR-0086), are accepted and kept: the Confirm Active and the bitmaps follow them.
	for _, bpp := range []uint16{15, 16} {
		caps := mcsTestCapabilitySets()
		binary.LittleEndian.PutUint16(caps[1][4:6], bpp)
		got, err := parseRDPDemandActive(mcsTestDemandActiveWithCaps(caps), mcsGlobalChannelID)
		if err != nil || got.PreferredBitsPerPixel != bpp {
			t.Fatalf("%d bpp: %+v, %v", bpp, got, err)
		}
		confirm, err := marshalRDPConfirmActive(got, MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720}, 1007)
		if err != nil || !bytes.Contains(confirm, append([]byte{0x02, 0x00, 0x1c, 0x00}, byte(bpp), 0)) {
			t.Fatalf("%d bpp: the Confirm Active does not echo the depth: %v", bpp, err)
		}
	}
	withUnknown := append(mcsTestCapabilitySets(), []byte{0x99, 0x99, 0x04, 0x00})
	unknown, err := parseRDPDemandActive(mcsTestDemandActiveWithCaps(withUnknown), mcsGlobalChannelID)
	if err != nil || len(unknown.CapabilityTypes) != 6 || unknown.CapabilityTypes[5] != 0x9999 {
		t.Fatalf("bounded opaque capability was not retained: %+v, %v", unknown, err)
	}
}

func TestParseRDPDemandActiveRejectsMalformedAndUnsupportedProfile(t *testing.T) {
	base := mcsTestDemandActive()
	cases := map[string][]byte{}
	cases["truncated"] = append([]byte(nil), base[:len(base)-1]...)
	cases["wrong TPKT version"] = append([]byte{4}, base[1:]...)
	cases["wrong X224"] = append([]byte{base[0], base[1], base[2], base[3], 2, 0, 0x81}, base[7:]...)
	cases["wrong MCS PDU"] = mutateDemandActive(base, func(mcs []byte) { mcs[0] = 0x64 })
	cases["wrong channel"] = mutateDemandActive(base, func(mcs []byte) { mcs[4]++ })
	cases["wrong segmentation"] = mutateDemandActive(base, func(mcs []byte) { mcs[5] = 0x71 })
	cases["wrong share control type"] = mutateDemandActiveShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[2:4], 0x12) })
	cases["zero share id"] = mutateDemandActiveShare(base, func(share []byte) { binary.LittleEndian.PutUint32(share[6:10], 0) })
	cases["bad source descriptor"] = mutateDemandActiveShare(base, func(share []byte) { share[14] = 0 })
	cases["bad combined length"] = mutateDemandActiveShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[12:14], 3) })
	duplicateCaps := append(mcsTestCapabilitySets(), []byte{0x99, 0x99, 0x04, 0x00}, []byte{0x99, 0x99, 0x04, 0x00})
	cases["duplicate capability"] = mcsTestDemandActiveWithCaps(duplicateCaps)
	cases["missing required capability"] = mcsTestDemandActiveWithCaps(mcsTestCapabilitySets()[:4])
	cases["oversized capability length"] = mutateDemandActiveShare(base, func(share []byte) {
		caps := share[14+3+4:]
		binary.LittleEndian.PutUint16(caps[2:4], 0xffff)
	})
	cases["invalid bitmap dimensions"] = mcsTestDemandActiveWithCaps(func() [][]byte {
		caps := mcsTestCapabilitySets()
		binary.LittleEndian.PutUint16(caps[1][12:14], 0xffff)
		binary.LittleEndian.PutUint16(caps[1][14:16], 0xffff)
		return caps
	}())
	cases["invalid order boolean"] = mcsTestDemandActiveWithCaps(func() [][]byte {
		caps := mcsTestCapabilitySets()
		caps[2][4+32] = 2
		return caps
	}())
	cases["server selected non-32-bpp session"] = mcsTestDemandActiveWithCaps(func() [][]byte {
		caps := mcsTestCapabilitySets()
		binary.LittleEndian.PutUint16(caps[1][4:6], 24)
		return caps
	}())
	// 15 and 16 bpp are decoded (ADR-0086); 8 bpp is not, and is refused as 24 bpp is.
	for _, bpp := range []uint16{8, 0, 1} {
		cases[fmt.Sprintf("server selected a %d-bpp session", bpp)] = mcsTestDemandActiveWithCaps(func() [][]byte {
			caps := mcsTestCapabilitySets()
			binary.LittleEndian.PutUint16(caps[1][4:6], bpp)
			return caps
		}())
	}
	cases["bitmap compression absent"] = mcsTestDemandActiveWithCaps(func() [][]byte {
		caps := mcsTestCapabilitySets()
		binary.LittleEndian.PutUint16(caps[1][20:22], 0)
		return caps
	}())
	cases["multiple bitmap rectangles absent"] = mcsTestDemandActiveWithCaps(func() [][]byte {
		caps := mcsTestCapabilitySets()
		binary.LittleEndian.PutUint16(caps[1][24:26], 0)
		return caps
	}())
	cases["server scancode input absent"] = mcsTestDemandActiveWithCaps(func() [][]byte {
		caps := mcsTestCapabilitySets()
		binary.LittleEndian.PutUint16(caps[4][4:6], 0)
		return caps
	}())
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRDPDemandActive(packet, mcsGlobalChannelID); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
	if _, err := parseRDPDemandActive(base, 1004); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("unexpected channel accepted: %v", err)
	}
}

func TestMarshalRDPConfirmActiveBuildsMinimalClientProfile(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1600, DesktopHeight: 900, ClientName: "OpenBastion"}
	packet, err := marshalRDPConfirmActive(RDPServerCapabilities{ShareID: 0x000103ea}, settings, 1007)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) < 20 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!bytes.Equal(packet[4:7], []byte{2, 0xf0, 0x80}) {
		t.Fatalf("invalid TPKT/X.224 packet: %x", packet)
	}
	mcs := packet[7:]
	if mcs[0] != mcsSendDataRequest || binary.BigEndian.Uint16(mcs[1:3]) != 6 ||
		binary.BigEndian.Uint16(mcs[3:5]) != mcsGlobalChannelID || mcs[5] != 0x70 {
		t.Fatalf("MCS SendDataRequest header = %x", mcs[:6])
	}
	length, share, err := readPERLength(mcs[6:])
	if err != nil || length != len(share) {
		t.Fatalf("MCS userData length=%d actual=%d err=%v", length, len(share), err)
	}
	if binary.LittleEndian.Uint16(share[0:2]) != uint16(len(share)) ||
		binary.LittleEndian.Uint16(share[2:4]) != rdpConfirmActivePDU ||
		binary.LittleEndian.Uint16(share[4:6]) != 1007 ||
		binary.LittleEndian.Uint32(share[6:10]) != 0x000103ea ||
		binary.LittleEndian.Uint16(share[10:12]) != rdpServerChannelID {
		t.Fatalf("Confirm Active Share Control header = %x", share[:12])
	}
	sourceLength := int(binary.LittleEndian.Uint16(share[12:14]))
	combinedLength := int(binary.LittleEndian.Uint16(share[14:16]))
	if string(share[16:16+sourceLength]) != "OpenBastion" || combinedLength != 242 {
		t.Fatalf("Confirm Active descriptor/combined length invalid: %x", share[16:])
	}
	combined := share[16+sourceLength:]
	if binary.LittleEndian.Uint16(combined[:2]) != 5 || binary.LittleEndian.Uint16(combined[2:4]) != 0 {
		t.Fatalf("Confirm Active capability count/padding = %x", combined[:4])
	}
	caps := combined[4:]
	if binary.LittleEndian.Uint16(caps[:2]) != rdpCapGeneral || binary.LittleEndian.Uint16(caps[2:4]) != 24 ||
		binary.LittleEndian.Uint16(caps[8:10]) != 0x0200 {
		t.Fatalf("client General capability = %x", caps[:24])
	}
	bitmap := caps[24:52]
	if binary.LittleEndian.Uint16(bitmap[:2]) != rdpCapBitmap || binary.LittleEndian.Uint16(bitmap[2:4]) != 28 ||
		binary.LittleEndian.Uint16(bitmap[4:6]) != 32 || binary.LittleEndian.Uint16(bitmap[6:8]) != 1 ||
		binary.LittleEndian.Uint16(bitmap[8:10]) != 1 || binary.LittleEndian.Uint16(bitmap[10:12]) != 1 ||
		binary.LittleEndian.Uint16(bitmap[12:14]) != 1600 || binary.LittleEndian.Uint16(bitmap[14:16]) != 900 ||
		binary.LittleEndian.Uint16(bitmap[20:22]) != 1 || binary.LittleEndian.Uint16(bitmap[24:26]) != 1 {
		t.Fatalf("client Bitmap capability = %x", bitmap)
	}
	// DstBlt index 0 and the shared PatBlt/OpaqueRect index 1 remain disabled:
	// these strict subsets do not cover every normative order variant.
	if binary.LittleEndian.Uint16(caps[52:54]) != rdpCapOrder || binary.LittleEndian.Uint16(caps[54:56]) != 88 ||
		binary.LittleEndian.Uint16(caps[82:84]) != 1 || binary.LittleEndian.Uint16(caps[86:88]) != 0x000a ||
		!bytes.Equal(caps[88:120], make([]byte, 32)) ||
		binary.LittleEndian.Uint16(caps[140:142]) != rdpCapPointer || binary.LittleEndian.Uint16(caps[144:146]) != 1 ||
		binary.LittleEndian.Uint16(caps[150:152]) != rdpCapInput || binary.LittleEndian.Uint16(caps[154:156]) != 1 ||
		binary.LittleEndian.Uint32(caps[162:166]) != rdpKeyboardEnhanced ||
		binary.LittleEndian.Uint32(caps[170:174]) != rdpKeyboardFunctionKeys {
		t.Fatalf("client advertised invalid mandatory baseline capabilities: %x", caps[52:])
	}
}

func TestCredSSPSessionExchangeCapabilitiesOverTLS(t *testing.T) {
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
		initial, acceptErr := readTestTPKT(tlsConn)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if _, acceptErr = parseMCSClientConnectInitialForTest(initial); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestConnectResponse(protocolHybrid, 0, 0, 0)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		want := [][]byte{
			{3, 0, 0, 12, 2, 0xf0, 0x80, 0x04, 1, 0, 1, 0},
			{3, 0, 0, 8, 2, 0xf0, 0x80, 0x28},
			{3, 0, 0, 12, 2, 0xf0, 0x80, 0x38, 0, 6, 3, 0xef},
			{3, 0, 0, 12, 2, 0xf0, 0x80, 0x38, 0, 6, 3, 0xeb},
		}
		for i, expected := range want {
			got, readErr := readTestTPKT(tlsConn)
			if readErr != nil || !bytes.Equal(got, expected) {
				serverResult <- errors.New("unexpected MCS channel request")
				return
			}
			switch i {
			case 1:
				readErr = writeFull(tlsConn, mcsTestAttachUserConfirm(1007))
			case 2:
				readErr = writeFull(tlsConn, mcsTestChannelJoinConfirm(1007, 1007))
			case 3:
				readErr = writeFull(tlsConn, mcsTestChannelJoinConfirm(1007, mcsGlobalChannelID))
			}
			if readErr != nil {
				serverResult <- readErr
				return
			}
		}
		clientInfo, readErr := readTestTPKT(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		if _, readErr = parseMCSClientInfoForTest(clientInfo, 1007); readErr != nil {
			serverResult <- readErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestDemandActive()); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		confirm, readErr := readTestTPKT(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		if _, readErr = parseMCSConfirmActiveForTest(confirm, 1007); readErr != nil {
			serverResult <- errors.New("Confirm Active parse: " + readErr.Error() + "; packet=" + fmt.Sprintf("%x", confirm))
			return
		}
		serverResult <- nil
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{transport: &Transport{Conn: clientTLS}, credentialsDelegated: true}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second}
	if _, err := session.ConnectMCS(context.Background(), settings); err != nil {
		t.Fatalf("ConnectMCS: %v", err)
	}
	if _, err := session.ConnectMCSChannels(context.Background(), time.Second); err != nil {
		t.Fatalf("ConnectMCSChannels: %v", err)
	}
	if err := session.SendClientInfo(context.Background(), RDPClientInfo{Domain: "EXAMPLE", Username: "alice", Password: []byte("p@ssword")}, time.Second); err != nil {
		t.Fatalf("SendClientInfo: %v", err)
	}
	// This test isolates the post-Licensing capability codec. The licensing
	// exchange itself is implemented in the following increment.
	session.licensingComplete = true
	got, err := session.ExchangeCapabilities(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("ExchangeCapabilities: %v", err)
	}
	if got.ShareID != 0x000103ea || !session.capabilitiesExchanged || session.serverCapabilities.ShareID != got.ShareID {
		t.Fatalf("capability transition not persisted: got=%+v session=%+v", got, session.serverCapabilities)
	}
	got.CapabilityTypes[0] = 0xffff
	if session.serverCapabilities.CapabilityTypes[0] == 0xffff {
		t.Fatal("returned capability types alias session state")
	}
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("second capability exchange error = %v", err)
	}
	session.Close()
	if err := <-serverResult; err != nil {
		t.Fatalf("fake RDP server: %v", err)
	}
}

func TestCredSSPSessionExchangeCapabilitiesClosesOnInvalidDemandActive(t *testing.T) {
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
		bad := mcsTestDemandActive()
		bad[7] = 0x64
		if acceptErr = writeFull(tlsConn, bad); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		serverResult <- nil
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: clientTLS}, credentialsDelegated: true, mcsConnected: true,
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, channelsConnected: true,
		userChannelID: 1007, clientInfoSent: true, licensingComplete: true,
		mcsSettings: MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion"},
	}
	// The refusal keeps its identity (the refusal code does not change) and says what came: a bare
	// error left Windows' behaviour unknown (ADR-0071, CI run #38).
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) ||
		!strings.Contains(err.Error(), "Demand Active refused: TPKT of") {
		t.Fatalf("ExchangeCapabilities error = %v", err)
	}
	if session.transport != nil || session.capabilitiesExchanged {
		t.Fatalf("invalid Demand Active did not terminate session: %+v", session)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestCredSSPSessionExchangeCapabilitiesRequiresCompletedChannelConnection(t *testing.T) {
	session := &CredSSPClientSession{credentialsDelegated: true, mcsConnected: true, licensingComplete: true}
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("ExchangeCapabilities error = %v, want ErrMCSConnection", err)
	}
	if session.capabilitiesExchanged {
		t.Fatal("capabilities transition succeeded without a connected MCS channel set")
	}
}

func parseMCSConfirmActiveForTest(packet []byte, expectedUserID uint16) ([]byte, error) {
	if len(packet) < 14 || packet[7] != mcsSendDataRequest ||
		binary.BigEndian.Uint16(packet[8:10]) != expectedUserID-mcsUserIDBase ||
		binary.BigEndian.Uint16(packet[10:12]) != mcsGlobalChannelID || packet[12] != 0x70 {
		return nil, ErrMCSConnection
	}
	length, data, err := readPERLength(packet[13:])
	if err != nil || length != len(data) {
		return nil, ErrMCSConnection
	}
	if len(data) < 14 || binary.LittleEndian.Uint16(data[2:4]) != rdpConfirmActivePDU {
		return nil, ErrMCSConnection
	}
	return data, nil
}

func mcsTestDemandActive() []byte {
	return mcsTestDemandActiveWithCaps(mcsTestCapabilitySets())
}

func mcsTestDemandActiveWithCaps(capabilities [][]byte) []byte {
	var caps []byte
	for _, capability := range capabilities {
		caps = append(caps, capability...)
	}
	source := []byte("RDP")
	combined := make([]byte, 4+len(caps))
	binary.LittleEndian.PutUint16(combined[:2], uint16(len(capabilities)))
	copy(combined[4:], caps)
	share := make([]byte, 6+4+2+2+len(source)+len(combined)+4)
	binary.LittleEndian.PutUint16(share[:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpDemandActivePDU)
	binary.LittleEndian.PutUint16(share[4:6], rdpServerChannelID)
	binary.LittleEndian.PutUint32(share[6:10], 0x000103ea)
	binary.LittleEndian.PutUint16(share[10:12], uint16(len(source)))
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(combined)))
	copy(share[14:], source)
	copy(share[14+len(source):], combined)
	mcs := []byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x70}
	mcs = appendPERLength(mcs, len(share))
	mcs = append(mcs, share...)
	packet := make([]byte, 7+len(mcs))
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
}

func mcsTestCapabilitySets() [][]byte {
	general := make([]byte, 24)
	binary.LittleEndian.PutUint16(general[:2], rdpCapGeneral)
	binary.LittleEndian.PutUint16(general[2:4], uint16(len(general)))
	binary.LittleEndian.PutUint16(general[8:10], 0x0200)
	binary.LittleEndian.PutUint16(general[10:12], 0xffff) // pad2OctetsA is ignored by the protocol.

	bitmap := make([]byte, 28)
	binary.LittleEndian.PutUint16(bitmap[:2], rdpCapBitmap)
	binary.LittleEndian.PutUint16(bitmap[2:4], uint16(len(bitmap)))
	binary.LittleEndian.PutUint16(bitmap[4:6], 32)
	binary.LittleEndian.PutUint16(bitmap[6:8], 0)   // Ignored legacy receive-depth field.
	binary.LittleEndian.PutUint16(bitmap[8:10], 0)  // Ignored legacy receive-depth field.
	binary.LittleEndian.PutUint16(bitmap[10:12], 0) // Ignored legacy receive-depth field.
	binary.LittleEndian.PutUint16(bitmap[12:14], 1280)
	binary.LittleEndian.PutUint16(bitmap[14:16], 720)
	binary.LittleEndian.PutUint16(bitmap[16:18], 0xffff) // pad2octets is ignored.
	binary.LittleEndian.PutUint16(bitmap[20:22], 1)
	binary.LittleEndian.PutUint16(bitmap[24:26], 1)
	binary.LittleEndian.PutUint16(bitmap[26:28], 0xffff) // pad2octetsB is ignored.

	order := make([]byte, 88)
	binary.LittleEndian.PutUint16(order[:2], rdpCapOrder)
	binary.LittleEndian.PutUint16(order[2:4], uint16(len(order)))
	binary.LittleEndian.PutUint16(order[30:32], 1)

	pointer := make([]byte, 10)
	binary.LittleEndian.PutUint16(pointer[:2], rdpCapPointer)
	binary.LittleEndian.PutUint16(pointer[2:4], uint16(len(pointer)))
	binary.LittleEndian.PutUint16(pointer[4:6], 1)
	binary.LittleEndian.PutUint16(pointer[6:8], 25)
	binary.LittleEndian.PutUint16(pointer[8:10], 25)

	input := make([]byte, 88)
	binary.LittleEndian.PutUint16(input[:2], rdpCapInput)
	binary.LittleEndian.PutUint16(input[2:4], uint16(len(input)))
	binary.LittleEndian.PutUint16(input[4:6], 1)
	return [][]byte{general, bitmap, order, pointer, input}
}

func mutateDemandActive(packet []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), packet...)
	mutate(out[7:])
	return out
}

func mutateDemandActiveShare(packet []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), packet...)
	mcs := out[7:]
	length, share, err := readPERLength(mcs[6:])
	if err != nil || length != len(share) {
		return out
	}
	mutate(share)
	return out
}

func FuzzParseRDPDemandActive(f *testing.F) {
	f.Add(mcsTestDemandActive())
	f.Add([]byte("not a Demand Active PDU"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxTPKTPacket*2 {
			return
		}
		_, _ = parseRDPDemandActive(packet, mcsGlobalChannelID)
	})
}

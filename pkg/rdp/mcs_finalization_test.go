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

func TestMarshalRDPClientFinalizationPDUs(t *testing.T) {
	shareID := uint32(0x000103ea)
	userID := uint16(1007)
	cases := []struct {
		name   string
		packet []byte
		typ    byte
		want   []byte
	}{
		{"synchronize", marshalRDPClientSynchronize(shareID, userID), rdpPDU2Synchronize, []byte{1, 0, 0xea, 0x03}},
		{"cooperate", marshalRDPClientControl(shareID, userID, rdpControlCooperate), rdpPDU2Control, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
		{"request control", marshalRDPClientControl(shareID, userID, rdpControlRequest), rdpPDU2Control, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{"font list", marshalRDPClientFontList(shareID, userID), rdpPDU2FontList, []byte{0, 0, 0, 0, 3, 0, 50, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.packet) < 25 || tc.packet[0] != 3 || tc.packet[1] != 0 ||
				int(binary.BigEndian.Uint16(tc.packet[2:4])) != len(tc.packet) ||
				!bytes.Equal(tc.packet[4:7], []byte{2, 0xf0, 0x80}) {
				t.Fatalf("invalid TPKT/X.224: %x", tc.packet)
			}
			mcs := tc.packet[7:]
			if mcs[0] != mcsSendDataRequest || binary.BigEndian.Uint16(mcs[1:3]) != 6 ||
				binary.BigEndian.Uint16(mcs[3:5]) != mcsGlobalChannelID || mcs[5] != 0x70 {
				t.Fatalf("invalid MCS Send Data Request: %x", mcs)
			}
			length, share, err := readPERLength(mcs[6:])
			if err != nil || length != len(share) || len(share) != 18+len(tc.want) ||
				binary.LittleEndian.Uint16(share[:2]) != uint16(len(share)) ||
				binary.LittleEndian.Uint16(share[2:4]) != rdpShareDataPDU ||
				binary.LittleEndian.Uint16(share[4:6]) != userID ||
				binary.LittleEndian.Uint32(share[6:10]) != shareID || share[11] != 1 ||
				binary.LittleEndian.Uint16(share[12:14]) != uint16(len(share)) || share[14] != tc.typ ||
				share[15] != 0 || binary.LittleEndian.Uint16(share[16:18]) != 0 ||
				!bytes.Equal(share[18:], tc.want) {
				t.Fatalf("invalid Share Data PDU: %x, err=%v", share, err)
			}
		})
	}
	if got := marshalRDPClientControl(shareID, userID, 0xffff); got != nil {
		t.Fatalf("unsupported control action produced a packet: %x", got)
	}
	if got := marshalRDPClientSynchronize(0, userID); got != nil {
		t.Fatalf("zero Share ID produced a packet: %x", got)
	}
}

func TestParseRDPFinalizationResponsesStrictly(t *testing.T) {
	const shareID = uint32(0x000103ea)
	const userID = uint16(1007)
	valid := []struct {
		name    string
		typ     byte
		stream  byte
		action  uint16
		payload []byte
	}{
		{"server synchronize", rdpPDU2Synchronize, 0, 0, []byte{1, 0, 0, 0}},
		{"server cooperate", rdpPDU2Control, 2, rdpControlCooperate, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
		{"server granted control", rdpPDU2Control, 2, rdpControlGranted, []byte{2, 0, 0xef, 0x03, 0xea, 0x03, 0, 0}},
		{"server font map", rdpPDU2FontMap, 2, 0, []byte{0, 0, 0, 0, 3, 0, 4, 0}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			packet := mcsTestFinalizationResponse(shareID, tc.typ, tc.stream, tc.payload)
			if _, err := parseRDPFinalizationResponse(packet, mcsGlobalChannelID, shareID, userID, tc.typ, tc.stream, tc.action); err != nil {
				t.Fatalf("valid response rejected: %v", err)
			}
		})
	}
	base := mcsTestFinalizationResponse(shareID, rdpPDU2Control, 2, []byte{4, 0, 0, 0, 0, 0, 0, 0})
	badSyncTarget := mcsTestFinalizationResponse(shareID, rdpPDU2Synchronize, 0, []byte{1, 0, 0xef, 0x03})
	badGrantID := mcsTestFinalizationResponse(shareID, rdpPDU2Control, 2, []byte{2, 0, 0, 0, 0xea, 0x03, 0, 0})
	badControlID := mcsTestFinalizationResponse(shareID, rdpPDU2Control, 2, []byte{2, 0, 0xef, 0x03, 0xeb, 0x03, 0, 0})
	badFontMap := mcsTestFinalizationResponse(shareID, rdpPDU2FontMap, 2, []byte{1, 0, 1, 0, 3, 0, 4, 0})
	cases := map[string][]byte{
		"truncated":                             append([]byte(nil), base[:len(base)-1]...),
		"wrong TPKT":                            append([]byte{4}, base[1:]...),
		"wrong initiator":                       mutateFinalizationMCS(base, func(mcs []byte) { mcs[2]++ }),
		"wrong channel":                         mutateFinalizationMCS(base, func(mcs []byte) { mcs[4]++ }),
		"wrong segmentation":                    mutateFinalizationMCS(base, func(mcs []byte) { mcs[5] = 0x71 }),
		"wrong share type":                      mutateFinalizationShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[2:4], 0x11) }),
		"wrong share source":                    mutateFinalizationShare(base, func(share []byte) { binary.LittleEndian.PutUint16(share[4:6], 1003) }),
		"wrong share ID":                        mutateFinalizationShare(base, func(share []byte) { binary.LittleEndian.PutUint32(share[6:10], 1) }),
		"wrong PDU type":                        mutateFinalizationShare(base, func(share []byte) { share[14] = rdpPDU2FontList }),
		"compressed PDU":                        mutateFinalizationShare(base, func(share []byte) { share[15] = 1 }),
		"trailing payload":                      append(append([]byte(nil), base...), 0),
		"wrong control action":                  mcsTestFinalizationResponse(shareID, rdpPDU2Control, 2, []byte{2, 0, 0xef, 0x03, 0xea, 0x03, 0, 0}),
		"wrong server synchronize target":       badSyncTarget,
		"wrong granted user":                    badGrantID,
		"wrong granted server":                  badControlID,
		"nonempty font map for empty font list": badFontMap,
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			typ, action := rdpPDU2Control, rdpControlCooperate
			stream := byte(2)
			if name == "wrong server synchronize target" {
				typ, action, stream = rdpPDU2Synchronize, 0, 0
			}
			if name == "wrong granted user" || name == "wrong granted server" {
				action = rdpControlGranted
			}
			if name == "nonempty font map for empty font list" {
				typ, action = rdpPDU2FontMap, 0
			}
			if _, err := parseRDPFinalizationResponse(packet, mcsGlobalChannelID, shareID, userID, typ, stream, action); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
	if _, err := parseRDPFinalizationResponse(base, 1004, shareID, userID, rdpPDU2Control, 2, rdpControlCooperate); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("unexpected MCS channel accepted: %v", err)
	}
}

func TestCredSSPSessionFinalizeConnectionOverTLS(t *testing.T) {
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
		for i, expected := range []struct {
			typ     byte
			payload []byte
		}{
			{rdpPDU2Synchronize, []byte{1, 0, 0xea, 0x03}},
			{rdpPDU2Control, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
			{rdpPDU2Control, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
			{rdpPDU2FontList, []byte{0, 0, 0, 0, 3, 0, 50, 0}},
		} {
			packet, readErr := readTestTPKT(tlsConn)
			if readErr != nil {
				serverResult <- readErr
				return
			}
			mcs := packet[7:]
			_, share, readErr := readPERLength(mcs[6:])
			if readErr != nil || len(share) != 18+len(expected.payload) || share[14] != expected.typ || !bytes.Equal(share[18:], expected.payload) {
				serverResult <- errors.New("unexpected client finalization PDU")
				return
			}
			if i == 0 && binary.LittleEndian.Uint16(share[4:6]) != 1007 {
				serverResult <- errors.New("client Synchronize has wrong source")
				return
			}
		}
		responses := []struct {
			typ     byte
			stream  byte
			payload []byte
		}{
			{rdpPDU2Synchronize, 0, []byte{1, 0, 0, 0}},
			{rdpPDU2Control, 2, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
			{rdpPDU2Control, 2, []byte{2, 0, 0xef, 0x03, 0xea, 0x03, 0, 0}},
			{rdpPDU2FontMap, 2, []byte{0, 0, 0, 0, 3, 0, 4, 0}},
		}
		for _, response := range responses {
			if writeErr := writeFull(tlsConn, mcsTestFinalizationResponse(0x000103ea, response.typ, response.stream, response.payload)); writeErr != nil {
				serverResult <- writeErr
				return
			}
		}
		serverResult <- nil
	}()

	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: clientConn}, credentialsDelegated: true, mcsConnected: true,
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, channelsConnected: true,
		userChannelID: 1007, clientInfoSent: true, licensingComplete: true,
		capabilitiesExchanged: true, serverCapabilities: RDPServerCapabilities{ShareID: 0x000103ea},
	}
	got, err := session.FinalizeConnection(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("FinalizeConnection: %v", err)
	}
	if !got.ServerSynchronized || !got.ServerCooperated || !got.ControlGranted || got.FontMapEntries != 0 || !session.connectionFinalized {
		t.Fatalf("finalization result/state = %+v / %v", got, session.connectionFinalized)
	}
	if _, err := session.FinalizeConnection(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("second finalization = %v, want ErrMCSConnection", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestCredSSPSessionFinalizeConnectionRequiresCapabilities(t *testing.T) {
	for name, session := range map[string]*CredSSPClientSession{
		"not delegated":           {mcsConnected: true, channelsConnected: true, clientInfoSent: true, licensingComplete: true, capabilitiesExchanged: true},
		"licensing incomplete":    {credentialsDelegated: true, mcsConnected: true, channelsConnected: true, clientInfoSent: true},
		"capabilities incomplete": {credentialsDelegated: true, mcsConnected: true, channelsConnected: true, clientInfoSent: true, licensingComplete: true},
		"zero share ID":           {credentialsDelegated: true, mcsConnected: true, channelsConnected: true, clientInfoSent: true, licensingComplete: true, capabilitiesExchanged: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.FinalizeConnection(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("FinalizeConnection = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func mcsTestFinalizationResponse(shareID uint32, typ, stream byte, payload []byte) []byte {
	share := make([]byte, 18+len(payload))
	binary.LittleEndian.PutUint16(share[:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint16(share[4:6], rdpServerChannelID)
	binary.LittleEndian.PutUint32(share[6:10], shareID)
	share[11] = stream
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(share)))
	share[14] = typ
	copy(share[18:], payload)
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

func mutateFinalizationMCS(packet []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), packet...)
	mutate(out[7:])
	return out
}

func mutateFinalizationShare(packet []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), packet...)
	mcs := out[7:]
	_, share, err := readPERLength(mcs[6:])
	if err == nil {
		mutate(share)
	}
	return out
}

func FuzzParseRDPFinalizationResponse(f *testing.F) {
	f.Add(mcsTestFinalizationResponse(0x000103ea, rdpPDU2Synchronize, 1, []byte{1, 0, 0x00, 0x00}))
	f.Add([]byte("not an RDP finalization PDU"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseRDPFinalizationResponse(packet, mcsGlobalChannelID, 0x000103ea, 1007, rdpPDU2Synchronize, 1, 0)
	})
}

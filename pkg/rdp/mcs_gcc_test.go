package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadTPKTPacketPreservesTransportDiagnostics(t *testing.T) {
	t.Run("closed connection", func(t *testing.T) {
		_, err := readTPKTPacket(bytes.NewReader(nil), maxTPKTPacket)
		if !errors.Is(err, ErrMCSConnection) || !errors.Is(err, io.EOF) {
			t.Fatalf("readTPKTPacket() error = %v, want ErrMCSConnection and io.EOF", err)
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		_, err := readTPKTPacket(bytes.NewReader([]byte{3, 0}), maxTPKTPacket)
		if !errors.Is(err, ErrMCSConnection) || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("readTPKTPacket() error = %v, want ErrMCSConnection and io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("unexpected protocol response", func(t *testing.T) {
		_, err := readTPKTPacket(bytes.NewReader([]byte{0x30, 0x82, 0x00, 0x10}), maxTPKTPacket)
		if !errors.Is(err, ErrMCSConnection) || !strings.Contains(err.Error(), "30 82 00 10") {
			t.Fatalf("readTPKTPacket() error = %v, want unexpected response header", err)
		}
	})
}

func TestMarshalMCSConnectInitialBuildsStrictHybridProfile(t *testing.T) {
	packet, err := MarshalMCSConnectInitial(MCSClientSettings{DesktopWidth: 1920, DesktopHeight: 1080, ClientName: "OpenBastion"})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) < 16 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		t.Fatalf("invalid TPKT framing: %x", packet[:min(len(packet), 8)])
	}
	if !bytes.Equal(packet[4:7], []byte{2, 0xf0, 0x80}) {
		t.Fatalf("X.224 data header = %x", packet[4:7])
	}
	outer, rest, err := readMCSBER(packet[7:], []byte{0x7f, mcsConnectInitialTag})
	if err != nil || len(rest) != 0 {
		t.Fatalf("MCS Connect-Initial BER: %v", err)
	}
	for _, expected := range [][]byte{{1}, {1}, {0xff}} {
		var tag []byte
		if len(expected) == 1 && expected[0] == 0xff {
			tag = []byte{1}
		} else {
			tag = []byte{4}
		}
		value, tail, readErr := readMCSBER(outer, tag)
		if readErr != nil || !bytes.Equal(value, expected) {
			t.Fatalf("MCS selector/flag = %x, %v; want %x", value, readErr, expected)
		}
		outer = tail
	}
	for i := 0; i < 3; i++ {
		params, tail, readErr := readMCSBER(outer, []byte{0x30})
		if readErr != nil || !validMCSBERDomainParameters(params) {
			t.Fatalf("domain parameters %d invalid: %v", i, readErr)
		}
		outer = tail
	}
	gcc, tail, err := readMCSBER(outer, []byte{0x04})
	if err != nil || len(tail) != 0 {
		t.Fatalf("MCS userData: %v", err)
	}
	if len(gcc) < 20 || !bytes.Equal(gcc[:7], []byte{0, 5, 0, 0x14, 0x7c, 0, 1}) {
		t.Fatalf("GCC ConnectData prefix = %x", gcc[:min(len(gcc), 7)])
	}
	if !bytes.Contains(gcc, []byte("Duca")) {
		t.Fatal("GCC request omitted client-to-server H.221 key")
	}
	coreHeader := []byte{0x01, 0xc0, 0xd8, 0x00}
	coreOffset := bytes.Index(gcc, coreHeader)
	if coreOffset < 0 || coreOffset+4+212 > len(gcc) {
		t.Fatal("GCC request CS_CORE block must be 216 bytes and omit optional DPI fields")
	}
	core := gcc[coreOffset+4 : coreOffset+4+212]
	if binary.LittleEndian.Uint32(core[0:4]) != rdpClientVersion ||
		binary.LittleEndian.Uint16(core[4:6]) != 1920 || binary.LittleEndian.Uint16(core[6:8]) != 1080 ||
		binary.LittleEndian.Uint16(core[136:138]) != rdpHighColor24BPP ||
		binary.LittleEndian.Uint16(core[138:140]) != rdpSupported32BPP ||
		binary.LittleEndian.Uint16(core[140:142]) != rdpClientErrInfo|rdpClientWant32BPP ||
		binary.LittleEndian.Uint32(core[208:212]) != protocolHybrid {
		t.Fatalf("CS_CORE fields do not match the HYBRID/32-bpp profile: %x", core)
	}
	if binary.LittleEndian.Uint16(core[20:22]) != 'O' || binary.LittleEndian.Uint16(core[22:24]) != 'p' ||
		binary.LittleEndian.Uint16(core[42:44]) != 0 {
		t.Fatal("CS_CORE clientName is not a bounded, NUL-terminated UTF-16LE name")
	}
	securityHeader := []byte{0x02, 0xc0, 0x0c, 0x00}
	securityOffset := bytes.Index(gcc, securityHeader)
	if securityOffset < 0 || securityOffset+12 > len(gcc) ||
		binary.LittleEndian.Uint32(gcc[securityOffset+4:securityOffset+8]) != rdpEncryption128Bit ||
		binary.LittleEndian.Uint32(gcc[securityOffset+8:securityOffset+12]) != 0 {
		t.Fatal("GCC request must advertise 128-bit security capability with no French extension")
	}
	if bytes.Contains(gcc, []byte{0x03, 0xc0}) {
		t.Fatal("GCC request unexpectedly advertised a virtual channel")
	}
}

func TestMarshalMCSConnectInitialUsesFrenchSecurityExtensionWhenRequested(t *testing.T) {
	packet, err := MarshalMCSConnectInitial(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", FrenchLocale: true})
	if err != nil {
		t.Fatal(err)
	}
	gcc, err := parseMCSClientConnectInitialForTest(packet)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{0x02, 0xc0, 0x0c, 0x00}
	offset := bytes.Index(gcc, header)
	if offset < 0 || offset+12 > len(gcc) ||
		binary.LittleEndian.Uint32(gcc[offset+4:offset+8]) != 0 ||
		binary.LittleEndian.Uint32(gcc[offset+8:offset+12]) != rdpEncryption128Bit {
		t.Fatal("French-locale CS_SECURITY must move the advertised method to extEncryptionMethods")
	}
}

func TestMarshalMCSConnectInitialRejectsInvalidDesktopAndClientIdentity(t *testing.T) {
	valid := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion"}
	cases := map[string]MCSClientSettings{
		"zero width":       {DesktopHeight: 720, ClientName: valid.ClientName},
		"zero height":      {DesktopWidth: 1280, ClientName: valid.ClientName},
		"too many pixels":  {DesktopWidth: 8192, DesktopHeight: 8192, ClientName: valid.ClientName},
		"empty name":       {DesktopWidth: 1280, DesktopHeight: 720},
		"too long name":    {DesktopWidth: 1280, DesktopHeight: 720, ClientName: "1234567890123456"},
		"embedded NUL":     {DesktopWidth: 1280, DesktopHeight: 720, ClientName: "Open\x00Bastion"},
		"invalid UTF-8":    {DesktopWidth: 1280, DesktopHeight: 720, ClientName: string([]byte{0xff})},
		"negative timeout": {DesktopWidth: 1280, DesktopHeight: 720, ClientName: valid.ClientName, Timeout: -time.Second},
	}
	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := MarshalMCSConnectInitial(settings); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestParseMCSConnectResponseAcceptsOnlyPinnedHybridNoChannelResponse(t *testing.T) {
	packet := mcsTestConnectResponse(protocolHybrid, 0, 0, 0)
	got, err := ParseMCSConnectResponse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerVersion != rdpClientVersion || got.IOChannelID != mcsGlobalChannelID {
		t.Fatalf("response = %+v", got)
	}
}

func TestParseMCSConnectResponseAcceptsOptionalEarlyCapabilityFlagsOmission(t *testing.T) {
	packet := mcsTestConnectResponseWithoutEarlyFlags(protocolHybrid, 0, 0, 0)
	got, err := ParseMCSConnectResponse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerVersion != rdpClientVersion || got.IOChannelID != mcsGlobalChannelID {
		t.Fatalf("response = %+v", got)
	}
}

func TestParseMCSConnectResponseIgnoresMCSAndGCCMetadataAsSpecified(t *testing.T) {
	packet := mcsTestConnectResponseWithDomainParameters(protocolHybrid, 0, 0, 0, []uint32{65536, 0, 65536, 0, 65536, 0, 1, 0})
	metadata := []byte{0x14, 0x79, 0xf3, 0x01, 0x01, 0x00, 0x01, 0xc0}
	offset := bytes.Index(packet, metadata)
	if offset < 0 {
		t.Fatal("test response has no GCC Conference-Create-Response metadata")
	}
	// The node ID, tag, result and set count are ignored by the client.
	packet[offset+1] = 0
	packet[offset+2] = 0
	packet[offset+3] = 7
	packet[offset+4] = 7
	packet[offset+5] = 0
	got, err := ParseMCSConnectResponse(packet)
	if err != nil {
		t.Fatalf("ignored metadata rejected: %v", err)
	}
	if got.IOChannelID != mcsGlobalChannelID {
		t.Fatalf("response = %+v", got)
	}
}

func TestParseMCSConnectResponseRejectsMalformedOrUnsupportedData(t *testing.T) {
	base := mcsTestConnectResponse(protocolHybrid, 0, 0, 0)
	cases := map[string][]byte{
		"truncated":          append([]byte(nil), base[:len(base)-1]...),
		"wrong TPKT version": append([]byte{4}, base[1:]...),
		"wrong X224":         append([]byte{base[0], base[1], base[2], base[3], 2, 0, 0x80}, base[7:]...),
		"wrong protocol":     mcsTestConnectResponse(protocolHybrid|1, 0, 0, 0),
		"nonzero RDP crypto": mcsTestConnectResponse(protocolHybrid, 1, 0, 0),
		"virtual channels":   mcsTestConnectResponse(protocolHybrid, 0, 0, 1),
		"wrong IO channel":   mcsTestConnectResponse(protocolHybrid, 0, 0, 0x03e8),
	}
	unknownBlock := append([]byte(nil), base...)
	networkOffset := bytes.Index(unknownBlock, []byte{0x03, 0x0c, 0x08, 0x00})
	if networkOffset < 0 {
		t.Fatal("test response has no SC_NET block")
	}
	unknownBlock[networkOffset] = 0x04
	cases["unknown server data block"] = unknownBlock
	duplicateBlock := append([]byte(nil), base...)
	networkOffset = bytes.Index(duplicateBlock, []byte{0x03, 0x0c, 0x08, 0x00})
	duplicateBlock[networkOffset] = 0x01 // SC_CORE appears twice; SC_NET is absent.
	duplicateBlock[networkOffset+1] = 0x0c
	cases["duplicate server data block"] = duplicateBlock
	wrongKey := append([]byte(nil), base...)
	keyOffset := bytes.Index(wrongKey, []byte("McDn"))
	wrongKey[keyOffset] = 'X'
	cases["wrong server H.221 key"] = wrongKey
	wrongVersion := append([]byte(nil), base...)
	coreOffset := bytes.Index(wrongVersion, []byte{0x01, 0x0c, 0x10, 0x00})
	if coreOffset < 0 {
		t.Fatal("test response has no SC_CORE block")
	}
	wrongVersion[coreOffset+4] = 0x03
	cases["unsupported server version"] = wrongVersion
	wrongResult := append([]byte(nil), base...)
	resultOffset := bytes.Index(wrongResult, []byte{0x0a, 0x01, 0x00})
	if resultOffset < 0 {
		t.Fatal("test response has no MCS result")
	}
	wrongResult[resultOffset+2] = 1
	cases["MCS connection rejected"] = wrongResult
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMCSConnectResponse(packet); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("error = %v, want ErrMCSConnection", err)
			}
		})
	}
}

func TestCredSSPSessionConnectMCSRequiresDelegatedCredentials(t *testing.T) {
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
		_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		n, readErr := tlsConn.Read(one[:])
		if n != 0 || readErr == nil {
			serverResult <- errors.New("client sent MCS data before CredSSP credential delegation")
			return
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			serverResult <- errors.New("client did not close the unused CredSSP transport")
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
	session := &CredSSPClientSession{transport: &Transport{Conn: clientTLS}}
	_, err = session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second})
	if !errors.Is(err, ErrMCSConnection) || session.transport == nil {
		t.Fatalf("ConnectMCS error=%v transportPreserved=%v", err, session.transport != nil)
	}
	session.Close()
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatalf("fake MCS server: %v", serverErr)
	}
}

func TestCredSSPSessionConnectMCSOverTLS(t *testing.T) {
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
		request, readErr := readTestTPKT(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		if _, readErr = parseMCSClientConnectInitialForTest(request); readErr != nil {
			serverResult <- readErr
			return
		}
		response := mcsTestConnectResponse(protocolHybrid, 0, 0, 0)
		if readErr = writeFull(tlsConn, response); readErr != nil {
			serverResult <- readErr
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
	transport := &Transport{Conn: clientTLS}
	session := &CredSSPClientSession{transport: transport, credentialsDelegated: true}
	response, err := session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second})
	if err != nil {
		t.Fatalf("ConnectMCS: %v", err)
	}
	if response.IOChannelID != mcsGlobalChannelID || !session.mcsConnected {
		t.Fatalf("MCS session state = %+v, connected=%v", response, session.mcsConnected)
	}
	if _, err := session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion"}); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("second ConnectMCS error = %v, want ErrMCSConnection", err)
	}
	session.Close()
	if err := <-serverResult; err != nil {
		t.Fatalf("fake MCS server: %v", err)
	}
}

func TestCredSSPSessionConnectMCSClosesOnInvalidServerResponse(t *testing.T) {
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
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(tlsConn, mcsTestConnectResponse(protocolHybrid|1, 0, 0, 0)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		_ = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		n, readErr := tlsConn.Read(one[:])
		if n != 0 || readErr == nil {
			serverResult <- errors.New("client kept the transport open after an invalid MCS response")
			return
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			serverResult <- errors.New("client did not close after an invalid MCS response")
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
	_, err = session.ConnectMCS(context.Background(), MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: time.Second})
	if !errors.Is(err, ErrMCSConnection) || session.transport != nil {
		t.Fatalf("ConnectMCS error=%v transportClosed=%v", err, session.transport == nil)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("fake MCS server: %v", err)
	}
}

func TestCredSSPSessionConnectMCSClosesOnContextCancellation(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestReceived := make(chan struct{})
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
		if _, acceptErr = readTestTPKT(tlsConn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		close(requestReceived)
		_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		n, readErr := tlsConn.Read(one[:])
		if n != 0 || readErr == nil {
			serverResult <- errors.New("client kept the transport open after context cancellation")
			return
		}
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			serverResult <- errors.New("client did not close after context cancellation")
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
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, connectErr := session.ConnectMCS(ctx, MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Timeout: 2 * time.Second})
		result <- connectErr
	}()
	select {
	case <-requestReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not send the MCS Connect-Initial request")
	}
	cancel()
	select {
	case connectErr := <-result:
		if !errors.Is(connectErr, ErrMCSConnection) || session.transport != nil {
			t.Fatalf("ConnectMCS error=%v transportClosed=%v", connectErr, session.transport == nil)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ConnectMCS did not stop after context cancellation")
	}
	select {
	case serverErr := <-serverResult:
		if serverErr != nil {
			t.Fatalf("fake MCS server: %v", serverErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake MCS server did not observe transport closure")
	}
}

func parseMCSClientConnectInitialForTest(packet []byte) ([]byte, error) {
	if len(packet) < 9 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!bytes.Equal(packet[4:7], []byte{2, 0xf0, 0x80}) {
		return nil, ErrMCSConnection
	}
	body, rest, err := readMCSBER(packet[7:], []byte{0x7f, mcsConnectInitialTag})
	if err != nil || len(rest) != 0 {
		return nil, ErrMCSConnection
	}
	for _, tag := range [][]byte{{0x04}, {0x04}, {0x01}, {0x30}, {0x30}, {0x30}} {
		_, body, err = readMCSBER(body, tag)
		if err != nil {
			return nil, err
		}
	}
	userData, rest, err := readMCSBER(body, []byte{0x04})
	if err != nil || len(rest) != 0 {
		return nil, ErrMCSConnection
	}
	return userData, nil
}

func mcsTestConnectResponse(requestedProtocol uint32, encryptionMethod, encryptionLevel uint32, channelCount uint16) []byte {
	return mcsTestConnectResponseWithDomainParameters(requestedProtocol, encryptionMethod, encryptionLevel, channelCount, []uint32{34, 2, 0, 1, 0, 1, 65535, 2})
}

func mcsTestConnectResponseWithDomainParameters(requestedProtocol uint32, encryptionMethod, encryptionLevel uint32, channelCount uint16, domainParameters []uint32) []byte {
	return mcsTestConnectResponseWithOptions(requestedProtocol, encryptionMethod, encryptionLevel, channelCount, domainParameters, true)
}

func mcsTestConnectResponseWithoutEarlyFlags(requestedProtocol uint32, encryptionMethod, encryptionLevel uint32, channelCount uint16) []byte {
	return mcsTestConnectResponseWithOptions(requestedProtocol, encryptionMethod, encryptionLevel, channelCount, []uint32{34, 2, 0, 1, 0, 1, 65535, 2}, false)
}

func mcsTestConnectResponseWithOptions(requestedProtocol uint32, encryptionMethod, encryptionLevel uint32, channelCount uint16, domainParameters []uint32, includeEarlyFlags bool) []byte {
	coreLength := 8
	if includeEarlyFlags {
		coreLength = 12
	}
	core := make([]byte, coreLength)
	binary.LittleEndian.PutUint32(core[0:4], rdpClientVersion)
	binary.LittleEndian.PutUint32(core[4:8], requestedProtocol)
	blocks := appendGCCBlock(nil, gccServerCoreType, core)
	security := make([]byte, 8)
	binary.LittleEndian.PutUint32(security[0:4], encryptionMethod)
	binary.LittleEndian.PutUint32(security[4:8], encryptionLevel)
	blocks = appendGCCBlock(blocks, gccServerSecurityType, security)
	network := make([]byte, 4)
	binary.LittleEndian.PutUint16(network[0:2], mcsGlobalChannelID)
	binary.LittleEndian.PutUint16(network[2:4], channelCount)
	if channelCount != 0 {
		network = append(network, make([]byte, int(channelCount)*2)...)
	}
	blocks = appendGCCBlock(blocks, gccServerNetworkType, network)
	gcc := []byte{0, 5, 0, 0x14, 0x7c, 0, 1, 0x2a, 0x14, 0x79, 0xf3, 1, 1, 0, 1, 0xc0, 0, 'M', 'c', 'D', 'n'}
	gcc = appendPERLength(gcc, len(blocks))
	gcc = append(gcc, blocks...)
	var mcsBody []byte
	mcsBody = appendBER(mcsBody, 0x0a, []byte{0})
	mcsBody = appendBER(mcsBody, 0x02, []byte{0})
	mcsBody = appendBER(mcsBody, 0x30, marshalMCSDomainParameters(domainParameters))
	mcsBody = appendBER(mcsBody, 0x04, gcc)
	mcs := appendBERHighTag(nil, []byte{0x7f, mcsConnectResponseTag}, mcsBody)
	packet := make([]byte, 7+len(mcs))
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
}

func FuzzParseMCSConnectResponse(f *testing.F) {
	f.Add(mcsTestConnectResponse(protocolHybrid, 0, 0, 0))
	f.Add([]byte("not an MCS response"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxTPKTPacket*2 {
			return
		}
		_, _ = ParseMCSConnectResponse(data)
	})
}

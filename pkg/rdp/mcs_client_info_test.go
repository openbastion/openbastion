package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

func TestMarshalRDPClientInfoUsesUnicodeAndKeepsSecretInPasswordField(t *testing.T) {
	packet, err := marshalRDPClientInfo(1007, mcsGlobalChannelID, RDPClientInfo{Domain: "SAINT-GOBAIN", Username: "élodie", Password: []byte("p@ssword")})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	info, err := parseMCSClientInfoForTest(packet, 1007)
	if err != nil {
		t.Fatal(err)
	}
	if info.CodePage != 0 || info.Flags != rdpInfoUnicode|rdpInfoAutoLogon|rdpInfoForceEncryptedCSPDU|rdpInfoEnableWindowsKey ||
		info.Domain != "SAINT-GOBAIN" || info.Username != "élodie" || info.Password != "p@ssword" {
		t.Fatalf("Client Info identity/flags/password mismatch: codePage=%d flags=%#x domain=%q username=%q",
			info.CodePage, info.Flags, info.Domain, info.Username)
	}
	if info.PasswordLength == 0 || info.Flags&rdpInfoAutoLogon == 0 {
		t.Fatal("Client Info did not request auto-logon with its password field")
	}
}

func TestMarshalRDPClientInfoRejectsInvalidIdentityAndOversizeFields(t *testing.T) {
	for name, info := range map[string]RDPClientInfo{
		"missing username":  {Domain: "EXAMPLE", Password: []byte("secret")},
		"missing password":  {Username: "alice"},
		"invalid utf8":      {Username: string([]byte{0xff}), Password: []byte("secret")},
		"embedded nul":      {Username: "alice\x00admin", Password: []byte("secret")},
		"control character": {Username: "alice\nadmin", Password: []byte("secret")},
		"invalid password":  {Username: "alice", Password: []byte{0xff}},
		"password nul":      {Username: "alice", Password: []byte("sec\x00ret")},
		"domain too long":   {Domain: string(bytes.Repeat([]byte("a"), 256)), Username: "alice", Password: []byte("secret")},
		"username too long": {Username: string(bytes.Repeat([]byte("a"), 256)), Password: []byte("secret")},
		"password too long": {Username: "alice", Password: bytes.Repeat([]byte("p"), 256)},
	} {
		t.Run(name, func(t *testing.T) {
			if packet, err := marshalRDPClientInfo(1007, mcsGlobalChannelID, info); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
				t.Fatalf("marshal = %x, %v; want empty packet and ErrMCSConnection", packet, err)
			}
		})
	}
	if packet, err := marshalRDPClientInfo(1007, 1007, RDPClientInfo{Username: "alice"}); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
		t.Fatalf("invalid I/O channel marshal = %x, %v", packet, err)
	}
	if packet, err := marshalMCSSendDataRequest(1007, 1008, []byte{1}); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
		t.Fatalf("unjoined channel marshal = %x, %v", packet, err)
	}
}

func TestCredSSPSessionSendClientInfoAndCapabilitiesAreGated(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	licenseComplete := make(chan struct{})
	var licenseCompleteOnce sync.Once
	releaseLicense := func() { licenseCompleteOnce.Do(func() { close(licenseComplete) }) }
	t.Cleanup(releaseLicense)
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
		packet, readErr := readTestTPKT(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		info, parseErr := parseMCSClientInfoForTest(packet, 1007)
		if parseErr != nil || info.Username != "alice" || info.Domain != "EXAMPLE" || info.Password != "p@ssword" {
			serverResult <- errors.New("invalid Client Info PDU")
			return
		}
		// Simulate the server only after the test explicitly marks Licensing complete.
		<-licenseComplete
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
	session := &CredSSPClientSession{
		transport: &Transport{Conn: clientTLS}, credentialsDelegated: true, mcsConnected: true,
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, channelsConnected: true,
		userChannelID: 1007, licensingComplete: true,
		mcsSettings: MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion"},
	}
	defer session.Close()
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("ExchangeCapabilities before Client Info = %v", err)
	}
	if session.transport == nil || session.capabilitiesExchanged {
		t.Fatal("premature capability exchange changed the active session")
	}
	session.licensingComplete = false
	if err := session.SendClientInfo(context.Background(), RDPClientInfo{Username: "alice\x00admin", Password: []byte("p@ssword")}, time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("invalid Client Info error = %v", err)
	}
	if session.clientInfoSent || session.transport == nil {
		t.Fatal("invalid local Client Info input changed the session state")
	}
	clientPassword := []byte("p@ssword")
	if err := session.SendClientInfo(context.Background(), RDPClientInfo{Domain: "EXAMPLE", Username: "alice", Password: clientPassword}, time.Second); err != nil {
		t.Fatalf("SendClientInfo: %v", err)
	}
	if !bytes.Equal(clientPassword, []byte("p@ssword")) {
		t.Fatal("SendClientInfo unexpectedly modified the caller-owned password buffer")
	}
	clear(clientPassword)
	if !session.clientInfoSent {
		t.Fatal("Client Info transition was not persisted")
	}
	if session.licensingComplete {
		t.Fatal("Client Info must not mark Licensing complete")
	}
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("ExchangeCapabilities before Licensing = %v", err)
	}
	if session.transport == nil || session.capabilitiesExchanged {
		t.Fatal("capability exchange bypassed Licensing")
	}
	if err := session.SendClientInfo(context.Background(), RDPClientInfo{Username: "alice", Password: []byte("p@ssword")}, time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("second Client Info send error = %v", err)
	}
	session.licensingComplete = true
	releaseLicense()
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); err != nil {
		t.Fatalf("ExchangeCapabilities after synthetic Licensing completion: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("fake RDP server: %v", err)
	}
}

func TestCredSSPSessionCannotExchangeCapabilitiesBeforeClientInfo(t *testing.T) {
	session := &CredSSPClientSession{
		credentialsDelegated: true, mcsConnected: true,
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, channelsConnected: true,
		userChannelID: 1007, licensingComplete: true,
	}
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("ExchangeCapabilities before Client Info = %v", err)
	}
	if session.capabilitiesExchanged {
		t.Fatal("capabilities advanced before Client Info")
	}
}

func TestMarshalRDPClientInfoUsesUTF16CodeUnitLengths(t *testing.T) {
	packet, err := marshalRDPClientInfo(1007, mcsGlobalChannelID, RDPClientInfo{Username: "user-😀", Password: []byte("pw-😀")})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	info, err := parseMCSClientInfoForTest(packet, 1007)
	if err != nil {
		t.Fatal(err)
	}
	wantLength := len(utf16.Encode([]rune("user-😀"))) * 2
	if info.UsernameLength != uint16(wantLength) {
		t.Fatalf("username length = %d, want %d", info.UsernameLength, wantLength)
	}
	wantPasswordLength := len(utf16.Encode([]rune("pw-😀"))) * 2
	if info.PasswordLength != uint16(wantPasswordLength) || info.Password != "pw-😀" {
		t.Fatalf("password field length = %d, want %d", info.PasswordLength, wantPasswordLength)
	}
}

type parsedRDPClientInfo struct {
	CodePage       uint32
	Flags          uint32
	Domain         string
	Username       string
	Password       string
	DomainLength   uint16
	UsernameLength uint16
	PasswordLength uint16
}

func parseMCSClientInfoForTest(packet []byte, userID uint16) (parsedRDPClientInfo, error) {
	var result parsedRDPClientInfo
	if len(packet) < 7+6 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!bytes.Equal(packet[4:7], []byte{2, 0xf0, 0x80}) || packet[7] != mcsSendDataRequest ||
		binary.BigEndian.Uint16(packet[8:10]) != userID-mcsUserIDBase || binary.BigEndian.Uint16(packet[10:12]) != mcsGlobalChannelID || packet[12] != 0x70 {
		return result, ErrMCSConnection
	}
	length, payload, err := readPERLength(packet[13:])
	if err != nil || length != len(payload) || len(payload) < 22 || binary.LittleEndian.Uint16(payload[:2]) != rdpSecInfoPacket ||
		binary.LittleEndian.Uint16(payload[2:4]) != 0 {
		return result, ErrMCSConnection
	}
	info := payload[4:]
	result.CodePage = binary.LittleEndian.Uint32(info[:4])
	result.Flags = binary.LittleEndian.Uint32(info[4:8])
	result.DomainLength = binary.LittleEndian.Uint16(info[8:10])
	result.UsernameLength = binary.LittleEndian.Uint16(info[10:12])
	result.PasswordLength = binary.LittleEndian.Uint16(info[12:14])
	alternateLength := int(binary.LittleEndian.Uint16(info[14:16]))
	workingLength := int(binary.LittleEndian.Uint16(info[16:18]))
	offset := 18
	readString := func(length uint16) (string, error) {
		fieldLength := int(length) + 2
		if fieldLength < 2 || fieldLength > len(info)-offset || fieldLength%2 != 0 ||
			info[offset+fieldLength-2] != 0 || info[offset+fieldLength-1] != 0 {
			return "", ErrMCSConnection
		}
		units := make([]uint16, 0, fieldLength/2-1)
		for i := 0; i < fieldLength-2; i += 2 {
			units = append(units, binary.LittleEndian.Uint16(info[offset+i:offset+i+2]))
		}
		offset += fieldLength
		return string(utf16.Decode(units)), nil
	}
	var readErr error
	if result.Domain, readErr = readString(result.DomainLength); readErr != nil {
		return result, readErr
	}
	if result.Username, readErr = readString(result.UsernameLength); readErr != nil {
		return result, readErr
	}
	if result.Password, readErr = readString(result.PasswordLength); readErr != nil || result.Password == "" {
		return result, ErrMCSConnection
	}
	if alternateLength != 0 || workingLength != 0 ||
		!bytes.Equal(info[offset:], append([]byte{0, 0, 0, 0}, rdpExtendedInfoPacket()...)) {
		return result, ErrMCSConnection
	}
	return result, nil
}

func TestCredSSPSessionSendClientInfoRequiresDelegationAndChannels(t *testing.T) {
	for name, session := range map[string]*CredSSPClientSession{
		"no delegation": {mcsConnected: true, channelsConnected: true, userChannelID: 1007},
		"no MCS":        {credentialsDelegated: true, channelsConnected: true, userChannelID: 1007},
		"no channels":   {credentialsDelegated: true, mcsConnected: true, userChannelID: 1007},
		"no user ID":    {credentialsDelegated: true, mcsConnected: true, channelsConnected: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := session.SendClientInfo(context.Background(), RDPClientInfo{Username: "alice", Password: []byte("p@ssword")}, time.Second); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("SendClientInfo error = %v", err)
			}
			if session.clientInfoSent {
				t.Fatal("Client Info state advanced without all prerequisites")
			}
		})
	}
}

func FuzzMarshalRDPClientInfo(f *testing.F) {
	f.Add("EXAMPLE", "alice", []byte("p@ssword"))
	f.Add("", "user-😀", []byte("sëcret"))
	f.Add(string([]byte{0xff}), "alice", []byte("secret"))
	f.Fuzz(func(t *testing.T, domain, username string, password []byte) {
		packet, err := marshalRDPClientInfo(1007, mcsGlobalChannelID, RDPClientInfo{Domain: domain, Username: username, Password: password})
		if err != nil {
			if len(packet) != 0 {
				t.Fatal("failed marshal returned a packet")
			}
			return
		}
		defer clear(packet)
		if len(packet) > maxTPKTPacket {
			t.Fatalf("packet length %d exceeds TPKT maximum", len(packet))
		}
	})
}

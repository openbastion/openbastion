package rdp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
	"unicode/utf16"
)

func TestMarshalRDPClientNewLicenseRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := marshalRDPClientNewLicenseRequest(1007, mcsGlobalChannelID, &key.PublicKey, "alice", "OpenBastion")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	body := parseTestClientLicenseRequest(t, packet, 1007)
	if body.username != "alice" || body.machine != "OpenBastion" || len(body.clientRandom) != 32 {
		t.Fatalf("unexpected new license request: %+v", body)
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, key, body.encryptedPreMaster)
	if err != nil || len(plain) != 48 {
		t.Fatalf("encrypted premaster decrypt length=%d err=%v", len(plain), err)
	}
	clear(plain)
}

func TestMarshalRDPClientNewLicenseRequestRejectsInvalidInputs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range []struct {
		userID, channel   uint16
		username, machine string
		key               *rsa.PublicKey
	}{
		{1007, mcsGlobalChannelID, "", "OpenBastion", &key.PublicKey},
		{1007, mcsGlobalChannelID, "alice\nroot", "OpenBastion", &key.PublicKey},
		{1007, mcsGlobalChannelID, "alice", "machine-name-too-long", &key.PublicKey},
		{1007, 1007, "alice", "OpenBastion", &key.PublicKey},
		{1000, mcsGlobalChannelID, "alice", "OpenBastion", &key.PublicKey},
		{1007, mcsGlobalChannelID, "alice", "OpenBastion", nil},
	} {
		t.Run(string(rune('a'+name)), func(t *testing.T) {
			if packet, err := marshalRDPClientNewLicenseRequest(tc.userID, tc.channel, tc.key, tc.username, tc.machine); !errors.Is(err, ErrMCSConnection) || len(packet) != 0 {
				t.Fatalf("packet=%x err=%v", packet, err)
			}
		})
	}
}

func TestParseRDPServerLicenseCertificateUsesTLSBoundX509Key(t *testing.T) {
	licenseCertificate, _, _ := rdpTestRSACertificate(t)
	key, err := parseRDPServerLicenseCertificate(mcsTestLicenseCertificateBlob(licenseCertificate.Certificate[0]), nil)
	if err != nil {
		t.Fatalf("parseRDPServerLicenseCertificate: %v", err)
	}
	if key.N.Cmp(licenseCertificate.PrivateKey.(*rsa.PrivateKey).N) != 0 || key.E != licenseCertificate.PrivateKey.(*rsa.PrivateKey).E {
		t.Fatal("licensing RSA key does not match the authenticated TLS-bound certificate payload")
	}
	for _, blob := range [][]byte{
		{1, 0, 0, 0},
		{2, 0, 0, 0x80, 1, 0, 0, 0, 1, 0, 0, 0, 0xff},
	} {
		if _, err := parseRDPServerLicenseCertificate(blob, nil); !errors.Is(err, ErrMCSConnection) {
			t.Fatalf("malformed certificate blob %x error=%v", blob, err)
		}
	}
}

func TestParseRDPServerLicenseRequestRejectsMalformedMessages(t *testing.T) {
	valid := mcsTestServerLicenseRequest()
	cases := map[string][]byte{
		"truncated":          valid[:len(valid)-1],
		"bad MCS channel":    func() []byte { p := bytes.Clone(valid); binary.BigEndian.PutUint16(p[10:12], 1007); return p }(),
		"bad initiator":      func() []byte { p := bytes.Clone(valid); binary.BigEndian.PutUint16(p[8:10], 0); return p }(),
		"bad security flags": func() []byte { p := bytes.Clone(valid); p[14] = 0; return p }(),
		"bad message type":   func() []byte { p := bytes.Clone(valid); p[18] = 0x02; return p }(),
		"bad message size":   func() []byte { p := bytes.Clone(valid); binary.LittleEndian.PutUint16(p[20:22], 1); return p }(),
		"trailing bytes":     append(bytes.Clone(valid), 0),
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRDPServerLicenseRequest(packet, mcsGlobalChannelID, nil); !errors.Is(err, ErrMCSConnection) {
				t.Fatalf("parse error=%v", err)
			}
		})
	}
	if _, err := parseRDPServerLicenseRequest(valid, 1007, nil); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("wrong expected channel error=%v", err)
	}
}

func TestParseRDPServerLicenseSuccessRequiresExactStatusAndTransition(t *testing.T) {
	valid := mcsTestServerLicenseSuccess(rdpLicenseStatusValid, rdpLicenseNoTransition, rdpLicenseBlobError, nil)
	if !parseRDPServerLicenseSuccess(valid, mcsGlobalChannelID) {
		t.Fatal("valid STATUS_VALID_CLIENT was rejected")
	}
	for name, packet := range map[string][]byte{
		"wrong status":         mcsTestServerLicenseSuccess(8, rdpLicenseNoTransition, rdpLicenseBlobError, nil),
		"abort transition":     mcsTestServerLicenseSuccess(rdpLicenseStatusValid, 1, rdpLicenseBlobError, nil),
		"wrong blob type":      mcsTestServerLicenseSuccess(rdpLicenseStatusValid, rdpLicenseNoTransition, 3, nil),
		"non-empty error blob": mcsTestServerLicenseSuccess(rdpLicenseStatusValid, rdpLicenseNoTransition, rdpLicenseBlobError, []byte{1}),
		"truncated":            valid[:len(valid)-1],
		"wrong channel":        func() []byte { p := bytes.Clone(valid); binary.BigEndian.PutUint16(p[10:12], 1007); return p }(),
	} {
		t.Run(name, func(t *testing.T) {
			if parseRDPServerLicenseSuccess(packet, mcsGlobalChannelID) {
				t.Fatal("malformed or unsuccessful licensing response was accepted")
			}
		})
	}
}

func TestCredSSPSessionCompletesPersonalServerLicensingBeforeCapabilities(t *testing.T) {
	licenseCertificate, _, key := rdpTestRSACertificate(t)
	tlsCertificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer raw.Close()
		tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{tlsCertificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
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
		if acceptErr = writeFull(tlsConn, mcsTestServerLicenseRequestWithCertificate(licenseCertificate.Certificate[0])); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		newLicense, readErr := readTestTPKT(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		parsed := parseTestClientLicenseRequest(t, newLicense, 1007)
		if parsed.username != "alice" || parsed.machine != "OpenBastion" {
			serverResult <- errors.New("unexpected client licensing identity")
			return
		}
		plain, decryptErr := rsa.DecryptPKCS1v15(rand.Reader, key, parsed.encryptedPreMaster)
		if decryptErr != nil || len(plain) != 48 {
			clear(plain)
			serverResult <- errors.New("client premaster secret was not valid RSA ciphertext")
			return
		}
		clear(plain)
		if acceptErr = writeFull(tlsConn, mcsTestServerLicenseSuccess(rdpLicenseStatusValid, rdpLicenseNoTransition, rdpLicenseBlobError, nil)); acceptErr != nil {
			serverResult <- acceptErr
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
		userChannelID: 1007,
		mcsSettings:   MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion"},
	}
	defer session.Close()
	if err := session.SendClientInfo(context.Background(), RDPClientInfo{Username: "alice", Password: []byte("secret")}, time.Second); err != nil {
		t.Fatalf("SendClientInfo: %v", err)
	}
	if err := session.CompleteLicensing(context.Background(), time.Second); err != nil {
		t.Fatalf("CompleteLicensing: %v", err)
	}
	if !session.licensingComplete || !session.licensingAttempted {
		t.Fatal("licensing state was not completed")
	}
	if _, err := session.ExchangeCapabilities(context.Background(), time.Second); err != nil {
		t.Fatalf("ExchangeCapabilities after actual Licensing: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("fake RDP server: %v", err)
	}
}

func TestCompleteLicensingRejectsNonRSAAndDoesNotMarkComplete(t *testing.T) {
	certificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer raw.Close()
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		_ = server.Handshake()
		_, _ = readTestTPKT(server)
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "rdp.test", MinVersion: tls.VersionTLS12})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &CredSSPClientSession{
		transport: &Transport{Conn: client}, credentialsDelegated: true, mcsConnected: true,
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, channelsConnected: true,
		userChannelID: 1007, clientInfoSent: true, licensingUsername: "alice",
		mcsSettings: MCSClientSettings{ClientName: "OpenBastion"},
	}
	defer session.Close()
	if err := session.CompleteLicensing(context.Background(), time.Second); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("CompleteLicensing with non-RSA certificate error=%v", err)
	}
	if session.licensingComplete || session.transport != nil {
		t.Fatal("unsupported key type must close session without completing Licensing")
	}
}

type parsedTestClientLicenseRequest struct {
	clientRandom       []byte
	encryptedPreMaster []byte
	username           string
	machine            string
}

func parseTestClientLicenseRequest(t *testing.T, packet []byte, userID uint16) parsedTestClientLicenseRequest {
	t.Helper()
	if len(packet) < 7+7+4 || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!bytes.Equal(packet[4:7], []byte{2, 0xf0, 0x80}) {
		t.Fatalf("invalid Client New License TPKT: %x", packet)
	}
	mcs := packet[7:]
	if mcs[0] != mcsSendDataRequest || binary.BigEndian.Uint16(mcs[1:3]) != userID-mcsUserIDBase ||
		binary.BigEndian.Uint16(mcs[3:5]) != mcsGlobalChannelID || mcs[5] != 0x70 {
		t.Fatalf("invalid Client New License MCS header: %x", mcs)
	}
	length, rest, err := readPERLength(mcs[6:])
	if err != nil || length != len(rest) || len(rest) < 4+4+8+32 {
		t.Fatalf("invalid Client New License userData: %x", rest)
	}
	if binary.LittleEndian.Uint16(rest[:2]) != rdpSecLicensePacket || binary.LittleEndian.Uint16(rest[2:4]) != 0 {
		t.Fatalf("invalid license security header: %x", rest[:4])
	}
	preamble := rest[4:]
	if preamble[0] != rdpLicenseNewRequest || preamble[1] != 0x83 ||
		int(binary.LittleEndian.Uint16(preamble[2:4])) != len(preamble) {
		t.Fatalf("invalid Client New License preamble: %x", preamble[:4])
	}
	body := preamble[4:]
	if binary.LittleEndian.Uint32(body[:4]) != rdpLicenseKeyExchangeRSA ||
		binary.LittleEndian.Uint32(body[4:8]) != rdpLicensePlatformWinNT {
		t.Fatalf("unexpected license key exchange/platform fields: %x", body[:8])
	}
	result := parsedTestClientLicenseRequest{clientRandom: bytes.Clone(body[8:40])}
	body = body[40:]
	typ, encrypted, rest, ok := readLicenseBlob(body)
	if !ok || typ != rdpLicenseBlobRandom {
		t.Fatalf("invalid encrypted premaster blob")
	}
	result.encryptedPreMaster = bytes.Clone(encrypted)
	typ, username, rest, ok := readLicenseBlob(rest)
	if !ok || typ != rdpLicenseBlobUsername || len(username) < 2 || username[len(username)-1] != 0 {
		t.Fatalf("invalid username blob")
	}
	result.username = string(username[:len(username)-1])
	typ, machine, rest, ok := readLicenseBlob(rest)
	if !ok || typ != rdpLicenseBlobMachineName || len(machine) < 2 || machine[len(machine)-1] != 0 || len(rest) != 0 {
		t.Fatalf("invalid machine-name blob")
	}
	result.machine = string(machine[:len(machine)-1])
	return result
}

func mcsTestLicenseCertificateBlob(certDER []byte) []byte {
	blob := []byte{0x02, 0x00, 0x00, 0x80, 1, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(certDER)))
	return append(blob, certDER...)
}

func mcsTestServerLicenseRequestWithCertificate(certDER []byte) []byte {
	var body []byte
	body = append(body, bytes.Repeat([]byte{0x42}, 32)...)
	body = append(body, 0, 0, 6, 0)
	body = appendLicenseUTF16(body, "OpenBastion")
	body = appendLicenseUTF16(body, "PAM1")
	body = appendLicenseBlob(body, rdpLicenseBlobKeyExchange, []byte{1, 0, 0, 0})
	body = appendLicenseBlob(body, rdpLicenseBlobCertificate, mcsTestLicenseCertificateBlob(certDER))
	body = append(body, 0, 0, 0, 0)
	preamble := []byte{rdpLicenseRequest, rdpLicenseProtocolVersion, 0, 0}
	preamble = append(preamble, body...)
	binary.LittleEndian.PutUint16(preamble[2:4], uint16(len(preamble)))
	userData := []byte{0x80, 0, 0, 0}
	userData = append(userData, preamble...)
	return mcsTestServerSendData(userData)
}

func mcsTestServerLicenseRequest() []byte {
	var body []byte
	body = append(body, bytes.Repeat([]byte{0x42}, 32)...)
	body = append(body, 0, 0, 6, 0) // ProductInfo.dwVersion = 0x00060000.
	body = appendLicenseUTF16(body, "OpenBastion")
	body = appendLicenseUTF16(body, "PAM1")
	body = appendLicenseBlob(body, rdpLicenseBlobKeyExchange, []byte{1, 0, 0, 0})
	body = appendLicenseBlob(body, rdpLicenseBlobCertificate, nil)
	body = append(body, 0, 0, 0, 0) // zero scopes.
	preamble := []byte{rdpLicenseRequest, rdpLicenseProtocolVersion, 0, 0}
	preamble = append(preamble, body...)
	binary.LittleEndian.PutUint16(preamble[2:4], uint16(len(preamble)))
	userData := []byte{0x80, 0, 0, 0}
	userData = append(userData, preamble...)
	return mcsTestServerSendData(userData)
}

func appendLicenseUTF16(dst []byte, value string) []byte {
	units := utf16.Encode([]rune(value + "\x00"))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:i*2+2], unit)
	}
	dst = append(dst, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(dst[len(dst)-4:], uint32(len(encoded)))
	return append(dst, encoded...)
}

func mcsTestServerLicenseSuccess(code, transition uint32, blobType uint16, blob []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[:4], code)
	binary.LittleEndian.PutUint32(body[4:8], transition)
	body = appendLicenseBlob(body, blobType, blob)
	preamble := []byte{rdpLicenseErrorAlert, rdpLicenseProtocolVersion, 0, 0}
	preamble = append(preamble, body...)
	binary.LittleEndian.PutUint16(preamble[2:4], uint16(len(preamble)))
	userData := []byte{0x80, 0, 0, 0}
	userData = append(userData, preamble...)
	return mcsTestServerSendData(userData)
}

func mcsTestServerSendData(userData []byte) []byte {
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

func rdpTestRSACertificate(t *testing.T) (tls.Certificate, *x509.CertPool, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "rdp.test"},
		DNSNames: []string{"rdp.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return cert, roots, key
}

func FuzzParseRDPServerLicenseRequest(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		f.Fatal(err)
	}
	fallbackKey := &key.PublicKey
	f.Add(mcsTestServerLicenseRequest())
	f.Add([]byte{3, 0, 0, 7, 2, 0xf0, 0x80})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxTPKTPacket {
			t.Skip()
		}
		_, _ = parseRDPServerLicenseRequest(packet, mcsGlobalChannelID, fallbackKey)
	})
}

func FuzzParseRDPServerLicenseSuccess(f *testing.F) {
	f.Add(mcsTestServerLicenseSuccess(rdpLicenseStatusValid, rdpLicenseNoTransition, rdpLicenseBlobError, nil))
	f.Add([]byte{3, 0, 0, 7, 2, 0xf0, 0x80})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxTPKTPacket {
			t.Skip()
		}
		_ = parseRDPServerLicenseSuccess(packet, mcsGlobalChannelID)
	})
}

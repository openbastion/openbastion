package rdp

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// The licensing exchange of a Remote Desktop Session Host (ADR-0099, option B) against a host of this
// test, over TLS: its keys derived on its side from the premaster secret it decrypts, its challenge and
// its license encrypted and MAC'd by its own code, the client's answers decrypted and checked there.

// licensingHost is the host's side of one connection.
type licensingHost struct {
	t              *testing.T
	conn           *tls.Conn
	key            *rsa.PrivateKey
	macSalt, rc4K  []byte
	clientRandom   []byte
	presented      []byte // the license the client presented, if it did
	serverRandom   []byte
	hwidOfResponse []byte
}

func testConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// testLicensingKeys: MS-RDPBCGR 5.3.5.1 as MS-RDPELE uses it, written apart from the client's.
func testLicensingKeys(preMaster, clientRandom, serverRandom []byte) (macSalt, encryption []byte) {
	salted := func(secret []byte, label string, first, second []byte) []byte {
		inner := sha1.Sum(testConcat([]byte(label), secret, first, second))
		outer := md5.Sum(testConcat(secret, inner[:]))
		return outer[:]
	}
	var master, blob []byte
	for _, label := range []string{"A", "BB", "CCC"} {
		master = append(master, salted(preMaster, label, clientRandom, serverRandom)...)
	}
	for _, label := range []string{"A", "BB", "CCC"} {
		blob = append(blob, salted(master, label, serverRandom, clientRandom)...)
	}
	key := md5.Sum(testConcat(blob[16:32], clientRandom, serverRandom))
	return blob[:16], key[:]
}

func testLicensingMAC(salt, data []byte) []byte {
	length := binary.LittleEndian.AppendUint32(nil, uint32(len(data)))
	inner := sha1.Sum(testConcat(salt, bytes.Repeat([]byte{0x36}, 40), length, data))
	outer := md5.Sum(testConcat(salt, bytes.Repeat([]byte{0x5c}, 48), inner[:]))
	return outer[:]
}

func testRC4(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

func testLicenseBlob(typ uint16, value []byte) []byte {
	return testConcat(binary.LittleEndian.AppendUint16(nil, typ), binary.LittleEndian.AppendUint16(nil, uint16(len(value))), value)
}

func testLicenseMessage(messageType byte, body []byte) []byte {
	preamble := []byte{messageType, rdpLicenseProtocolVersion, 0, 0}
	preamble = append(preamble, body...)
	binary.LittleEndian.PutUint16(preamble[2:4], uint16(len(preamble)))
	return mcsTestServerSendData(append([]byte{0x80, 0, 0, 0}, preamble...))
}

// readClientLicensing reads the client's licensing message: its type and body.
func (h *licensingHost) readClientLicensing() (byte, []byte) {
	h.t.Helper()
	packet, err := readTestTPKT(h.conn)
	if err != nil {
		h.t.Fatalf("the host read: %v", err)
	}
	mcs := packet[7:]
	_, rest, err := readPERLength(mcs[6:])
	if err != nil || binary.LittleEndian.Uint16(rest[:2]) != rdpSecLicensePacket {
		h.t.Fatalf("not a licensing packet: %x", packet)
	}
	preamble := rest[4:]
	if int(binary.LittleEndian.Uint16(preamble[2:4])) != len(preamble) {
		h.t.Fatal("the client's preamble length")
	}
	return preamble[0], preamble[4:]
}

// keysFrom decrypts the premaster secret the client sent and derives the keys.
func (h *licensingHost) keysFrom(encryptedPreMaster []byte) {
	h.t.Helper()
	preMaster, err := rsa.DecryptPKCS1v15(rand.Reader, h.key, encryptedPreMaster)
	if err != nil || len(preMaster) != 48 {
		h.t.Fatalf("the premaster secret: %v", err)
	}
	h.macSalt, h.rc4K = testLicensingKeys(preMaster, h.clientRandom, h.serverRandom)
}

// acceptFirst reads the client's first licensing message, a new license request or a license
// presented again, and derives the keys of the exchange from it.
func (h *licensingHost) acceptFirst() byte {
	h.t.Helper()
	typ, body := h.readClientLicensing()
	switch typ {
	case rdpLicenseNewRequest:
		h.clientRandom = append([]byte(nil), body[8:40]...)
		_, encrypted, _, ok := readLicenseBlob(body[40:])
		if !ok {
			h.t.Fatal("the new license request's premaster blob")
		}
		h.keysFrom(encrypted)
	case rdpLicenseInfo:
		if binary.LittleEndian.Uint32(body[0:4]) != rdpLicenseKeyExchangeRSA || binary.LittleEndian.Uint32(body[4:8]) != rdpLicensePlatformWinNT {
			h.t.Fatal("the license info's algorithm or platform")
		}
		h.clientRandom = append([]byte(nil), body[8:40]...)
		typ1, encrypted, rest, ok1 := readLicenseBlob(body[40:])
		typ2, license, rest, ok2 := readLicenseBlob(rest)
		typ3, encryptedHWID, rest, ok3 := readLicenseBlob(rest)
		if !ok1 || !ok2 || !ok3 || typ1 != rdpLicenseBlobRandom || typ2 != rdpLicenseBlobData || typ3 != rdpLicenseBlobEncryptedData || len(rest) != 16 {
			h.t.Fatal("the license info's blobs")
		}
		h.keysFrom(encrypted)
		hwid := testRC4(h.rc4K, encryptedHWID)
		if !bytes.Equal(testLicensingMAC(h.macSalt, hwid), rest) || len(hwid) != 20 || binary.LittleEndian.Uint32(hwid[:4]) != rdpLicensePlatformWinNT {
			h.t.Fatal("the license info's hardware ID or MAC")
		}
		h.presented = append([]byte(nil), license...)
	default:
		h.t.Fatalf("the client's first licensing message: type %#x", typ)
	}
	return typ
}

// challenge sends a platform challenge, its MAC forged when forge is set.
func (h *licensingHost) challenge(challenge []byte, forge bool) {
	h.t.Helper()
	mac := testLicensingMAC(h.macSalt, challenge)
	if forge {
		mac[0] ^= 0xff
	}
	body := testConcat([]byte{0, 0, 0, 0}, testLicenseBlob(rdpLicenseBlobEncryptedData, testRC4(h.rc4K, challenge)), mac)
	if err := writeFull(h.conn, testLicenseMessage(rdpLicensePlatformChallenge, body)); err != nil {
		h.t.Fatal(err)
	}
}

// readResponse reads the client's challenge response and checks it as the host would.
func (h *licensingHost) readResponse(challenge []byte) error {
	typ, body := h.readClientLicensing()
	if typ != rdpLicensePlatformChallengeResponse {
		return fmt.Errorf("the client answered with type %#x", typ)
	}
	typ1, encryptedResponse, rest, ok1 := readLicenseBlob(body)
	typ2, encryptedHWID, rest, ok2 := readLicenseBlob(rest)
	if !ok1 || !ok2 || typ1 != rdpLicenseBlobEncryptedData || typ2 != rdpLicenseBlobEncryptedData || len(rest) != 16 {
		return errors.New("the challenge response's blobs")
	}
	response, hwid := testRC4(h.rc4K, encryptedResponse), testRC4(h.rc4K, encryptedHWID)
	if !bytes.Equal(testLicensingMAC(h.macSalt, testConcat(response, hwid)), rest) {
		return errors.New("the challenge response's MAC")
	}
	if binary.LittleEndian.Uint16(response[0:2]) != 0x0100 || binary.LittleEndian.Uint16(response[2:4]) != 0xff00 ||
		binary.LittleEndian.Uint16(response[4:6]) != 3 || int(binary.LittleEndian.Uint16(response[6:8])) != len(challenge) ||
		!bytes.Equal(response[8:], challenge) {
		return fmt.Errorf("the challenge response's data: %x", response)
	}
	if len(hwid) != 20 || binary.LittleEndian.Uint32(hwid[:4]) != rdpLicensePlatformWinNT {
		return errors.New("the hardware ID")
	}
	h.hwidOfResponse = hwid
	return nil
}

func testNewLicenseInfo(license []byte) []byte {
	info := binary.LittleEndian.AppendUint32(nil, 0x00060000)
	for _, field := range [][]byte{[]byte("microsoft.com\x00"), appendLicenseUTF16(nil, "Microsoft Corporation")[4:], appendLicenseUTF16(nil, "A02")[4:], license} {
		info = binary.LittleEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	return info
}

// issue sends a new (or upgraded) license; forge breaks its MAC, info replaces NEW_LICENSE_INFO.
func (h *licensingHost) issue(messageType byte, license []byte, forge bool, info []byte) {
	h.t.Helper()
	if info == nil {
		info = testNewLicenseInfo(license)
	}
	mac := testLicensingMAC(h.macSalt, info)
	if forge {
		mac[15] ^= 1
	}
	body := testConcat(testLicenseBlob(rdpLicenseBlobEncryptedData, testRC4(h.rc4K, info)), mac)
	if err := writeFull(h.conn, testLicenseMessage(messageType, body)); err != nil {
		h.t.Fatal(err)
	}
}

func (h *licensingHost) alert(code, transition uint32) {
	h.t.Helper()
	if err := writeFull(h.conn, mcsTestServerLicenseSuccess(code, transition, rdpLicenseBlobError, nil)); err != nil {
		h.t.Fatal(err)
	}
}

// runLicensing runs one connection: the host side by script, the client's CompleteLicensing with cache.
func runLicensing(t *testing.T, cache *LicenseCache, scope string, script func(h *licensingHost) error) (error, error) {
	t.Helper()
	licenseCertificate, _, key := rdpTestRSACertificate(t)
	tlsCertificate, roots, _ := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	hostResult := make(chan error, 1)
	go func() {
		result := errors.New("the host stopped on a failure")
		defer func() { hostResult <- result }()
		result = func() error {
			raw, err := listener.Accept()
			if err != nil {
				return err
			}
			defer raw.Close()
			conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{tlsCertificate}, MinVersion: tls.VersionTLS12})
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := conn.Handshake(); err != nil {
				return err
			}
			if _, err := readTestTPKT(conn); err != nil { // Client Info
				return err
			}
			if err := writeFull(conn, mcsTestServerLicenseRequestWithCertificate(licenseCertificate.Certificate[0])); err != nil {
				return err
			}
			return script(&licensingHost{t: t, conn: conn, key: key, serverRandom: bytes.Repeat([]byte{0x42}, 32)})
		}()
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
		mcsResponse: MCSConnectResponse{IOChannelID: mcsGlobalChannelID}, channelsConnected: true, userChannelID: 1007,
		mcsSettings: MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 720, ClientName: "OpenBastion", Licenses: cache, LicenseScope: scope},
	}
	defer session.Close()
	if err := session.SendClientInfo(context.Background(), RDPClientInfo{Username: "alice", Password: []byte("secret")}, time.Second); err != nil {
		t.Fatalf("SendClientInfo: %v", err)
	}
	clientErr := session.CompleteLicensing(context.Background(), 2*time.Second)
	if clientErr != nil {
		session.Close()
	}
	return clientErr, <-hostResult
}

var testChallenge = []byte("a platform challenge from the host")

func TestLicensing_AHostIssuesALicense_ThenItIsPresentedAgain(t *testing.T) {
	cache, err := NewLicenseCache()
	if err != nil {
		t.Fatal(err)
	}
	// First connection: a new license request, a challenge, a license issued and kept.
	clientErr, hostErr := runLicensing(t, cache, "desk", func(h *licensingHost) error {
		if h.acceptFirst() != rdpLicenseNewRequest {
			return errors.New("a license request was expected")
		}
		h.challenge(testChallenge, false)
		if err := h.readResponse(testChallenge); err != nil {
			return err
		}
		h.issue(rdpLicenseNewLicense, []byte("LICENSE-1"), false, nil)
		return nil
	})
	if clientErr != nil || hostErr != nil {
		t.Fatalf("client %v, host %v", clientErr, hostErr)
	}
	if got := cache.get("desk"); string(got) != "LICENSE-1" {
		t.Fatalf("the license kept: %q", got)
	}
	// Second connection: the license presented again, challenged, upgraded.
	var presented []byte
	clientErr, hostErr = runLicensing(t, cache, "desk", func(h *licensingHost) error {
		if h.acceptFirst() != rdpLicenseInfo {
			return errors.New("the license kept was not presented")
		}
		presented = h.presented
		h.challenge(testChallenge, false)
		if err := h.readResponse(testChallenge); err != nil {
			return err
		}
		h.issue(rdpLicenseUpgradeLicense, []byte("LICENSE-2"), false, nil)
		return nil
	})
	if clientErr != nil || hostErr != nil || string(presented) != "LICENSE-1" {
		t.Fatalf("client %v, host %v, presented %q", clientErr, hostErr, presented)
	}
	if got := cache.get("desk"); string(got) != "LICENSE-2" {
		t.Fatalf("the upgraded license: %q", got)
	}
	if issued, presented, held := cache.Stats(); issued != 2 || presented != 1 || held != 1 {
		t.Fatalf("stats: issued %d, presented %d, held %d", issued, presented, held)
	}
	// Another target has its own scope: a new request, nothing presented.
	clientErr, hostErr = runLicensing(t, cache, "other", func(h *licensingHost) error {
		if h.acceptFirst() != rdpLicenseNewRequest {
			return errors.New("a license of another target was presented")
		}
		h.alert(rdpLicenseStatusValid, rdpLicenseNoTransition)
		return nil
	})
	if clientErr != nil || hostErr != nil {
		t.Fatalf("client %v, host %v", clientErr, hostErr)
	}
}

// A host in per-user mode may answer the challenge response with STATUS_VALID_CLIENT, issuing nothing.
func TestLicensing_AValidClientAfterTheChallenge(t *testing.T) {
	cache, _ := NewLicenseCache()
	clientErr, hostErr := runLicensing(t, cache, "desk", func(h *licensingHost) error {
		h.acceptFirst()
		h.challenge(testChallenge, false)
		if err := h.readResponse(testChallenge); err != nil {
			return err
		}
		h.alert(rdpLicenseStatusValid, rdpLicenseNoTransition)
		return nil
	})
	if clientErr != nil || hostErr != nil || cache.get("desk") != nil {
		t.Fatalf("client %v, host %v, kept %q", clientErr, hostErr, cache.get("desk"))
	}
}

func TestLicensing_RefusesWhatAHostMayNotSend(t *testing.T) {
	malformed := testNewLicenseInfo([]byte("LICENSE"))
	binary.LittleEndian.PutUint32(malformed[len(malformed)-len("LICENSE")-4:], 4096) // cbLicenseInfo past the end
	for name, script := range map[string]func(h *licensingHost) error{
		"a forged challenge MAC": func(h *licensingHost) error {
			h.acceptFirst()
			h.challenge(testChallenge, true)
			return nil
		},
		"a forged license MAC": func(h *licensingHost) error {
			h.acceptFirst()
			h.challenge(testChallenge, false)
			if err := h.readResponse(testChallenge); err != nil {
				return err
			}
			h.issue(rdpLicenseNewLicense, []byte("LICENSE"), true, nil)
			return nil
		},
		"a license info past its end": func(h *licensingHost) error {
			h.acceptFirst()
			h.challenge(testChallenge, false)
			if err := h.readResponse(testChallenge); err != nil {
				return err
			}
			h.issue(rdpLicenseNewLicense, nil, false, malformed)
			return nil
		},
		"an empty license": func(h *licensingHost) error {
			h.acceptFirst()
			h.issue(rdpLicenseNewLicense, nil, false, testNewLicenseInfo(nil))
			return nil
		},
		"three challenges": func(h *licensingHost) error {
			h.acceptFirst()
			for i := 0; i < 2; i++ {
				h.challenge(testChallenge, false)
				if err := h.readResponse(testChallenge); err != nil {
					return err
				}
			}
			h.challenge(testChallenge, false)
			// The client must not answer a third challenge: it ends the connection instead.
			if _, err := readTestTPKT(h.conn); err == nil {
				return errors.New("the client answered a third challenge")
			}
			return nil
		},
		"a license info with bytes after it": func(h *licensingHost) error {
			h.acceptFirst()
			h.issue(rdpLicenseNewLicense, nil, false, append(testNewLicenseInfo([]byte("LICENSE")), 0))
			return nil
		},
		"an error alert": func(h *licensingHost) error {
			h.acceptFirst()
			h.alert(0x00000008 /* ERR_NO_LICENSE_SERVER */, 0x00000001 /* ST_TOTAL_ABORT */)
			return nil
		},
		"another message": func(h *licensingHost) error {
			h.acceptFirst()
			return writeFull(h.conn, testLicenseMessage(rdpLicenseRequest, []byte{0, 0, 0, 0}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			cache, _ := NewLicenseCache()
			clientErr, hostErr := runLicensing(t, cache, "desk", script)
			if hostErr != nil {
				t.Fatalf("the host: %v", hostErr)
			}
			if !errors.Is(clientErr, ErrMCSConnection) || cache.get("desk") != nil {
				t.Fatalf("the client went on: %v, kept %q", clientErr, cache.get("desk"))
			}
			// What failed is said, never a secret (ADR-0099: for an operator, and for the CI).
			if !strings.Contains(clientErr.Error(), "licensing: ") {
				t.Fatalf("the refusal does not say what failed: %v", clientErr)
			}
			t.Logf("%v", clientErr)
		})
	}
}

// A license presented and refused is dropped: the next connection asks for a new one.
func TestLicensing_ALicenseRefusedIsNotPresentedAgain(t *testing.T) {
	cache, _ := NewLicenseCache()
	cache.put("desk", []byte("STALE"))
	clientErr, hostErr := runLicensing(t, cache, "desk", func(h *licensingHost) error {
		if h.acceptFirst() != rdpLicenseInfo || string(h.presented) != "STALE" {
			return errors.New("the kept license was not presented")
		}
		h.alert(0x00000003 /* ERR_INVALID_CLIENT */, 0x00000001)
		return nil
	})
	if hostErr != nil || !errors.Is(clientErr, ErrMCSConnection) {
		t.Fatalf("client %v, host %v", clientErr, hostErr)
	}
	if cache.get("desk") != nil {
		t.Fatal("a refused license is kept")
	}
}

// The keys are those of the protocol: the client's derivation and MAC match this test's, written apart.
func TestLicensing_TheKeysAndTheMAC(t *testing.T) {
	preMaster, clientRandom, serverRandom := bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	keys := deriveLicensingKeys(preMaster, clientRandom, serverRandom)
	salt, encryption := testLicensingKeys(preMaster, clientRandom, serverRandom)
	if !bytes.Equal(keys.macSalt[:], salt) || !bytes.Equal(keys.encryption[:], encryption) {
		t.Fatal("the derived keys differ")
	}
	mac := licensingMAC(keys.macSalt, []byte("data"))
	if !bytes.Equal(mac[:], testLicensingMAC(salt, []byte("data"))) {
		t.Fatal("the MAC differs")
	}
	// Swapping the randoms changes everything: their order is part of the derivation.
	if swapped := deriveLicensingKeys(preMaster, serverRandom, clientRandom); swapped.encryption == keys.encryption {
		t.Fatal("the randoms' order does not matter")
	}
}

func TestLicenseCache_IsBounded(t *testing.T) {
	cache, _ := NewLicenseCache()
	for i := 0; i < maxRDPLicenseCacheEntries+10; i++ {
		cache.put(fmt.Sprint(i), []byte("L"))
	}
	if len(cache.licenses) != maxRDPLicenseCacheEntries {
		t.Fatalf("%d entries", len(cache.licenses))
	}
	other, _ := NewLicenseCache()
	if cache.hardwareID() == other.hardwareID() {
		t.Fatal("two caches share a hardware ID")
	}
	var nilCache *LicenseCache
	if nilCache.get("x") != nil {
		t.Fatal("a nil cache holds a license")
	}
	nilCache.put("x", []byte("L")) // no panic
}

func FuzzParseRDPServerLicensingMessages(f *testing.F) {
	keys := deriveLicensingKeys(bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	f.Add([]byte{0, 0, 0, 0, 9, 0, 2, 0, 1, 2})
	f.Add(testConcat(testLicenseBlob(rdpLicenseBlobEncryptedData, testRC4(keys.encryption[:], testNewLicenseInfo([]byte("L")))), make([]byte, 16)))
	f.Fuzz(func(t *testing.T, body []byte) {
		if challenge, ok := parseRDPServerPlatformChallenge(body, keys); ok && (len(challenge) == 0 || len(challenge) > maxRDPLicenseChallenge) {
			t.Fatalf("a challenge of %d bytes", len(challenge))
		}
		if license, ok := parseRDPServerNewLicense(body, keys); ok && (len(license) == 0 || len(license) > maxRDPLicenseInfo) {
			t.Fatalf("a license of %d bytes", len(license))
		}
	})
}

// What a Remote Desktop Session Host sends (CI of PR #259): an X.509 chain whose key is the last
// certificate's, with its 8 + 4n bytes of padding, under SEC_LICENSE_ENCRYPT_CS.
func TestLicensing_TheChainOfASessionHost(t *testing.T) {
	issuer, _, issuerKey := rdpTestRSACertificate(t)
	leaf, _, leafKey := rdpTestRSACertificate(t)
	chain := func(padding int, certs ...[]byte) []byte {
		blob := binary.LittleEndian.AppendUint32(nil, 0x80000002)
		blob = binary.LittleEndian.AppendUint32(blob, uint32(len(certs)))
		for _, der := range certs {
			blob = binary.LittleEndian.AppendUint32(blob, uint32(len(der)))
			blob = append(blob, der...)
		}
		return append(blob, make([]byte, padding)...)
	}
	key, err := parseRDPServerLicenseCertificate(chain(16, issuer.Certificate[0], leaf.Certificate[0]), nil)
	if err != nil || key.N.Cmp(leafKey.N) != 0 || key.N.Cmp(issuerKey.N) == 0 {
		t.Fatalf("the key of the chain: %v", err)
	}
	for name, blob := range map[string][]byte{
		"a padding of another size": chain(15, issuer.Certificate[0], leaf.Certificate[0]),
		"nine certificates":         chain(0, leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0], leaf.Certificate[0]),
		"a proprietary certificate": binary.LittleEndian.AppendUint32(make([]byte, 0, 8), 1),
	} {
		if _, err := parseRDPServerLicenseCertificate(blob, nil); !errors.Is(err, ErrMCSConnection) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	// A certificate Go's parser refuses (here a validity that is not a time): its key is still read
	// from its SubjectPublicKeyInfo.
	spki, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seq := func(tag int, parts ...[]byte) []byte { return derWrap(byte(tag), testConcat(parts...)) }
	alg := seq(0x30, []byte{0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d}) // 1.3.14.3.2.29, as Microsoft signs
	name := seq(0x30)
	tbs := seq(0x30, seq(0xa0, []byte{0x02, 0x01, 0x02}), []byte{0x02, 0x01, 0x01}, alg, name, seq(0x30, []byte{0x04, 0x01, 0x00}), name, spki)
	odd := seq(0x30, tbs, alg, []byte{0x03, 0x01, 0x00})
	if _, err := x509.ParseCertificate(odd); err == nil {
		t.Fatal("the test's odd certificate parses: it proves nothing")
	}
	key, err = licenseCertificateRSAKey(odd)
	if err != nil || key.N.Cmp(leafKey.N) != 0 {
		t.Fatalf("the key of a certificate Go refuses: %v", err)
	}
}

func TestLicensing_TheSecurityHeaderOfASessionHost(t *testing.T) {
	packet := func(flags, flagsHi uint16) []byte {
		return mcsTestServerSendData(testConcat(binary.LittleEndian.AppendUint16(nil, flags), binary.LittleEndian.AppendUint16(nil, flagsHi),
			[]byte{rdpLicenseErrorAlert, rdpLicenseProtocolVersion, 4, 0}))
	}
	if _, err := parseMCSLicensingIndication(packet(0x0280, 0), mcsGlobalChannelID); err != nil {
		t.Fatalf("SEC_LICENSE_ENCRYPT_CS refused: %v", err)
	}
	// flagsHi as a session host of the CI filled it, ignored without SEC_FLAGSHI_VALID.
	for _, flagsHi := range []uint16{0x46, 0x1648, 0xafe2} {
		if _, err := parseMCSLicensingIndication(packet(0x0080, flagsHi), mcsGlobalChannelID); err != nil {
			t.Fatalf("flagsHi %#x refused: %v", flagsHi, err)
		}
	}
	for _, flags := range []uint16{0x0000, 0x0200, 0x0088, 0x0480, 0x8080} {
		if _, err := parseMCSLicensingIndication(packet(flags, 0), mcsGlobalChannelID); !errors.Is(err, ErrMCSConnection) {
			t.Errorf("flags %#x accepted", flags)
		}
	}
}

// A session host presents its proprietary certificate until it holds an X.509 one (CI of PR #259):
// the RSA key is read from its RSA1 blob, the signature checked for its shape alone.
func TestLicensing_TheProprietaryCertificateOfASessionHost(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	blob := func(n *big.Int, bits int, magic string, signature int) []byte {
		modulus := n.FillBytes(make([]byte, bits/8))
		little := make([]byte, len(modulus)+8)
		for i := range modulus {
			little[i] = modulus[len(modulus)-1-i]
		}
		rsa1 := testConcat([]byte(magic), binary.LittleEndian.AppendUint32(nil, uint32(len(little))), binary.LittleEndian.AppendUint32(nil, uint32(bits)),
			binary.LittleEndian.AppendUint32(nil, uint32(bits/8-1)), binary.LittleEndian.AppendUint32(nil, uint32(key.E)), little)
		out := binary.LittleEndian.AppendUint32(nil, 0x00000001)
		out = binary.LittleEndian.AppendUint32(out, 1)
		out = binary.LittleEndian.AppendUint32(out, 1)
		out = append(out, testLicenseBlob(0x0006, rsa1)...)
		return append(out, testLicenseBlob(0x0008, make([]byte, signature))...)
	}
	got, err := parseRDPServerLicenseCertificate(blob(key.N, 2048, "RSA1", 72), nil)
	if err != nil || got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatalf("the proprietary certificate's key: %v", err)
	}
	// A modulus of 512 bits, as old terminal servers had: refused (Go no longer makes such keys).
	small := new(big.Int).SetBytes(append([]byte{0xc5}, bytes.Repeat([]byte{0x11}, 63)...))
	for name, b := range map[string][]byte{
		"another magic":     blob(key.N, 2048, "RSA2", 72),
		"a signature of 64": blob(key.N, 2048, "RSA1", 64),
		"bytes after it":    append(blob(key.N, 2048, "RSA1", 72), 0),
		"a key of 512 bits": blob(small, 512, "RSA1", 72),
	} {
		if _, err := parseRDPServerLicenseCertificate(b, nil); !errors.Is(err, ErrMCSConnection) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

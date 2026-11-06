package rdp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialHybridNegotiatesTLSOnlyAfterHybridSelection(t *testing.T) {
	cert, roots, pin := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		request, err := readTestTPKT(conn)
		if err != nil {
			serverErr <- err
			return
		}
		if len(request) != 19 || request[5] != 0xe0 || request[11] != rdpNegReq || binary.LittleEndian.Uint32(request[15:19]) != protocolHybrid {
			serverErr <- errors.New("client did not request HYBRID exclusively")
			return
		}
		if err := writeFull(conn, connectionConfirm(protocolHybrid)); err != nil {
			serverErr <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		serverErr <- tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	transport, err := DialHybrid(context.Background(), TransportConfig{
		Address: listener.Addr().String(), TLSFingerprint: pin, TLSRoots: roots,
		TLSServerName: "rdp.test", DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("DialHybrid: %v", err)
	}
	if transport.Conn.ConnectionState().Version < tls.VersionTLS12 {
		t.Fatalf("TLS version too old: %x", transport.Conn.ConnectionState().Version)
	}
	targetName, channelBinding, err := transport.NTLMv2Bindings()
	if err != nil {
		t.Fatalf("NTLMv2Bindings: %v", err)
	}
	wantTargetName, err := NTLMv2TargetName("rdp.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(targetName, wantTargetName) {
		t.Fatalf("transport target SPN = %x, want %x", targetName, wantTargetName)
	}
	if channelBinding == ([16]byte{}) {
		t.Fatal("transport returned an empty TLS channel binding")
	}
	clear(targetName)
	clear(wantTargetName)
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("fake server: %v", err)
	}
}

func TestDialHybridRejectsDowngradeBeforeTLS(t *testing.T) {
	for _, protocol := range []uint32{0, 1, 8} {
		t.Run(strconvProtocol(protocol), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverErr := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				if _, err := readTestTPKT(conn); err != nil {
					serverErr <- err
					return
				}
				if err := writeFull(conn, connectionConfirm(protocol)); err != nil {
					serverErr <- err
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				n, readErr := conn.Read(b[:])
				if n != 0 || (readErr == nil) {
					serverErr <- errors.New("client sent TLS bytes after a downgraded negotiation")
					return
				}
				serverErr <- nil
			}()
			_, err = DialHybrid(context.Background(), TransportConfig{
				Address: listener.Addr().String(), TLSFingerprint: strings.Repeat("0", 64),
				TLSRoots: x509.NewCertPool(), TLSServerName: "rdp.test", DialTimeout: time.Second,
			})
			if !errors.Is(err, ErrUnsupportedProtocol) {
				t.Fatalf("protocol %d: got %v, want unsupported protocol", protocol, err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialHybridRejectsMissingTargetIdentity(t *testing.T) {
	cases := []TransportConfig{
		{Address: "rdp.test", TLSFingerprint: strings.Repeat("0", 64), TLSRoots: x509.NewCertPool()},
		{Address: "127.0.0.1:3389", TLSRoots: x509.NewCertPool()},
		{Address: "127.0.0.1:3389", TLSFingerprint: strings.Repeat("0", 64)},
		{Address: "127.0.0.1:3389", TLSFingerprint: strings.Repeat("0", 64), TLSRoots: x509.NewCertPool(), DialTimeout: -time.Second},
	}
	for i, cfg := range cases {
		if _, err := DialHybrid(context.Background(), cfg); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("case %d: got %v, want invalid target", i, err)
		}
	}
}

func connectionConfirm(protocol uint32) []byte {
	packet := []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, rdpNegResp, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(packet[15:19], protocol)
	return packet
}

func readTestTPKT(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if length < 4 || length > maxTPKTPacket {
		return nil, errors.New("bad test TPKT length")
	}
	packet := make([]byte, length)
	copy(packet, header[:])
	if _, err := io.ReadFull(conn, packet[4:]); err != nil {
		return nil, err
	}
	return packet, nil
}

func rdpTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "rdp.test"},
		DNSNames: []string{"rdp.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	sum := sha256.Sum256(der)
	return cert, roots, hex.EncodeToString(sum[:])
}

func strconvProtocol(protocol uint32) string {
	return map[uint32]string{0: "standard-security", 1: "tls-only", 8: "hybrid-ex"}[protocol]
}

func TestDialHybridRejectsCertificatePinMismatch(t *testing.T) {
	cert, roots, _ := rdpTestCertificate(t)
	_, _, impostorPin := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if _, err := readTestTPKT(conn); err != nil {
			serverErr <- err
			return
		}
		if err := writeFull(conn, connectionConfirm(protocolHybrid)); err != nil {
			serverErr <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		serverErr <- tlsConn.Handshake()
		_ = tlsConn.Close()
	}()
	_, err = DialHybrid(context.Background(), TransportConfig{
		Address: listener.Addr().String(), TLSFingerprint: impostorPin, TLSRoots: roots,
		TLSServerName: "rdp.test", DialTimeout: time.Second,
	})
	if !errors.Is(err, ErrTLSVerification) {
		t.Fatalf("got %v, want TLS pin verification failure", err)
	}
	if err := <-serverErr; err == nil {
		t.Fatal("server TLS handshake unexpectedly succeeded with a mismatched pin")
	}
}

func TestReadConnectionConfirmRejectsMalformedPackets(t *testing.T) {
	valid := connectionConfirm(protocolHybrid)
	cases := [][]byte{
		nil,
		{3, 0, 0, 19},
		append([]byte(nil), valid[:18]...),
		append([]byte(nil), valid...),
	}
	cases[3][5] = 0xe0 // a Connection Request is not a Connection Confirm
	for i, packet := range cases {
		if err := readConnectionConfirm(bytes.NewReader(packet)); err == nil {
			t.Errorf("case %d: malformed packet accepted", i)
		}
	}
}

func FuzzReadConnectionConfirm(f *testing.F) {
	f.Add(connectionConfirm(protocolHybrid))
	f.Add([]byte{3, 0, 0, 19, 14, 0xd0})
	f.Add([]byte("not a TPKT packet"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxTPKTPacket*2 {
			t.Skip()
		}
		_ = readConnectionConfirm(bytes.NewReader(data))
	})
}

// A real server announces its own abilities in the flags of RDP_NEG_RSP (MS-RDPBCGR 2.2.1.2.1):
// these are the bytes of FreeRDP 2.11, flags 0x03. They say nothing of the protocol chosen, which
// stays HYBRID or nothing.
func TestReadConnectionConfirm_TheFlagsOfARealServerAreNotADowngrade(t *testing.T) {
	confirm := func(flags byte, protocol byte) []byte {
		return []byte{3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0, rdpNegResp, flags, 8, 0, protocol, 0, 0, 0}
	}
	for _, flags := range []byte{0x01, 0x03, 0x1f} {
		if err := readConnectionConfirm(bytes.NewReader(confirm(flags, byte(protocolHybrid)))); err != nil {
			t.Fatalf("flags %#x: %v", flags, err)
		}
		if err := readConnectionConfirm(bytes.NewReader(confirm(flags, 1))); !errors.Is(err, ErrUnsupportedProtocol) {
			t.Fatalf("flags %#x with TLS alone: %v", flags, err)
		}
	}
}

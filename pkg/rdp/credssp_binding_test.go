package rdp

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"testing"

	"github.com/openbastion/openbastion/pkg/tlspin"
)

func TestCredSSPPublicKeyBindingHashesUsePinnedSubjectPublicKeyAndNonce(t *testing.T) {
	certificate, _, pinValue := rdpTestCertificate(t)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin, err := tlspin.ParseFingerprint(pinValue)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
	nonce := bytes.Repeat([]byte{0x5a}, credSSPClientNonceSize)
	binding, err := newCredSSPPublicKeyBinding(state, pin, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(binding.ClientNonce[:], nonce) {
		t.Fatal("client nonce was not preserved")
	}

	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(leaf.RawSubjectPublicKeyInfo, &info)
	if err != nil || len(rest) != 0 {
		t.Fatalf("parse SubjectPublicKeyInfo: rest=%d err=%v", len(rest), err)
	}
	clientInput := append(append(append([]byte(nil), credSSPClientBindingMagic...), nonce...), info.PublicKey.Bytes...)
	serverInput := append(append(append([]byte(nil), credSSPServerBindingMagic...), nonce...), info.PublicKey.Bytes...)
	wantClient := sha256.Sum256(clientInput)
	wantServer := sha256.Sum256(serverInput)
	if binding.ClientToServerHash != wantClient {
		t.Fatalf("client binding hash = %x, want %x", binding.ClientToServerHash, wantClient)
	}
	if binding.ServerToClientHash != wantServer {
		t.Fatalf("server binding hash = %x, want %x", binding.ServerToClientHash, wantServer)
	}
	if binding.ClientToServerHash == binding.ServerToClientHash {
		t.Fatal("client and server direction hashes must differ")
	}
	if err := binding.VerifyServerToClientHash(wantServer[:]); err != nil {
		t.Fatalf("valid server response rejected: %v", err)
	}
	wrong := append([]byte(nil), wantServer[:]...)
	wrong[0] ^= 1
	if err := binding.VerifyServerToClientHash(wrong); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("modified server response error = %v", err)
	}
	if err := binding.VerifyServerToClientHash(wrong[:len(wrong)-1]); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("short server response error = %v", err)
	}

	otherNonce := bytes.Repeat([]byte{0x5b}, credSSPClientNonceSize)
	otherBinding, err := newCredSSPPublicKeyBinding(state, pin, otherNonce)
	if err != nil {
		t.Fatal(err)
	}
	if binding.ClientToServerHash == otherBinding.ClientToServerHash || binding.ServerToClientHash == otherBinding.ServerToClientHash {
		t.Fatal("changing the nonce did not change both binding hashes")
	}
}

func TestTransportNewCredSSPPublicKeyBindingUsesFreshNonce(t *testing.T) {
	certificate, _, pinValue := rdpTestCertificate(t)
	pin, err := tlspin.ParseFingerprint(pinValue)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // Pin is asserted by the transport method under test.
	server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	transport := &Transport{Conn: client, expectedPin: pin}
	first, err := transport.NewCredSSPPublicKeyBinding()
	if err != nil {
		t.Fatal(err)
	}
	second, err := transport.NewCredSSPPublicKeyBinding()
	if err != nil {
		t.Fatal(err)
	}
	if allZero(first.ClientNonce[:]) || allZero(second.ClientNonce[:]) || first.ClientNonce == second.ClientNonce {
		t.Fatal("transport did not generate distinct, non-zero 32-byte nonces")
	}
	if first.ClientToServerHash == second.ClientToServerHash || first.ServerToClientHash == second.ServerToClientHash {
		t.Fatal("fresh nonce did not change both direction hashes")
	}
}

func TestCredSSPPublicKeyBindingRejectsUnpinnedOrIncompleteTLS(t *testing.T) {
	certificate, _, pinValue := rdpTestCertificate(t)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin, err := tlspin.ParseFingerprint(pinValue)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x33}, credSSPClientNonceSize)
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
	if _, err := newCredSSPPublicKeyBinding(state, tlspin.Fingerprint{}, nonce); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("empty pin error = %v", err)
	}
	_, _, otherPinValue := rdpTestCertificate(t)
	otherPin, err := tlspin.ParseFingerprint(otherPinValue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCredSSPPublicKeyBinding(state, otherPin, nonce); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("wrong pin error = %v", err)
	}
	if _, err := newCredSSPPublicKeyBinding(tls.ConnectionState{}, pin, nonce); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("incomplete handshake error = %v", err)
	}
	if _, err := newCredSSPPublicKeyBinding(state, pin, nonce[:len(nonce)-1]); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("short nonce error = %v", err)
	}
}

func TestCredSSPPublicKeyBindingCannotVerifyFromZeroValue(t *testing.T) {
	if err := (CredSSPPublicKeyBinding{}).VerifyServerToClientHash(make([]byte, 32)); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
		t.Fatalf("zero-value binding error = %v", err)
	}
}

func TestCredSSPPublicKeyBindingRejectsMalformedSubjectPublicKeyInfo(t *testing.T) {
	for _, cert := range []*x509.Certificate{nil, {}, {RawSubjectPublicKeyInfo: []byte{0x30, 0x00}}} {
		if _, err := credSSPSubjectPublicKey(cert); !errors.Is(err, ErrCredSSPPublicKeyBinding) {
			t.Errorf("certificate %#v error = %v", cert, err)
		}
	}
}

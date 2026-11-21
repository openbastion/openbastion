package proxycore

import (
	"crypto/ecdh"
	"encoding/hex"
	"testing"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The known-answer vector of ADR-0133's encryption: fixed keys, token and nonce. The Admin UI's
// WebCrypto code (web/admin-ui/src/features/screen/pasteCrypto.test.ts) must produce the same
// ciphertext from the same inputs, and the proxy must open it: the browser and the proxy agree on
// every byte of the derivation and of the associated data.
const (
	vectorProxyScalar  = "0101010101010101010101010101010101010101010101010101010101010101"
	vectorClientScalar = "0202020202020202020202020202020202020202020202020202020202020202"
	vectorToken        = "0303030303030303030303030303030303030303030303030303030303030303"
	vectorNonce        = "040404040404040404040404"
	vectorSession      = "session-vector"
	vectorProtocol     = "rdp"
	vectorText         = "Correct-Horse-1"
)

func TestPaste_TheKnownAnswerVector(t *testing.T) {
	proxyScalar, _ := hex.DecodeString(vectorProxyScalar)
	clientScalar, _ := hex.DecodeString(vectorClientScalar)
	proxy, err := ecdh.P256().NewPrivateKey(proxyScalar)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().NewPrivateKey(clientScalar)
	if err != nil {
		t.Fatal(err)
	}
	var token [screenstream.PasteTokenSize]byte
	var nonce [screenstream.PasteNonceSize]byte
	raw, _ := hex.DecodeString(vectorToken)
	copy(token[:], raw)
	raw, _ = hex.DecodeString(vectorNonce)
	copy(nonce[:], raw)
	sealed, err := sealPasteWith(proxy.PublicKey().Bytes(), client, nonce, vectorSession, vectorProtocol, token, []byte(vectorText))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("proxy public key %x", proxy.PublicKey().Bytes())
	t.Logf("client public key %x", client.PublicKey().Bytes())
	t.Logf("ciphertext %x", sealed.Ciphertext)
	const wantCiphertext = "305c0501b12f9e69ccd392935fc1633995666b67d4c4a0050baaf697e8732b"
	if hex.EncodeToString(sealed.Ciphertext) != wantCiphertext {
		t.Fatalf("ciphertext %x, want %s", sealed.Ciphertext, wantCiphertext)
	}
	plain, err := (&PasteKey{private: proxy}).Open(vectorSession, vectorProtocol, sealed)
	if err != nil || string(plain) != vectorText {
		t.Fatalf("opened %q, %v", plain, err)
	}
}

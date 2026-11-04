package rdp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/openbastion/openbastion/pkg/tlspin"
)

const credSSPClientNonceSize = 32

var ErrCredSSPPublicKeyBinding = errors.New("rdp: cannot derive CredSSP public-key binding")

const (
	credSSPClientBindingMagic = "CredSSP Client-To-Server Binding Hash\x00"
	credSSPServerBindingMagic = "CredSSP Server-To-Client Binding Hash\x00"
)

// CredSSPPublicKeyBinding contains the version 5/6 public-key binding material
// before GSS_Wrap confidentiality protection. The hashes are NOT wire-ready
// pubKeyAuth values: callers must seal them with the negotiated SSP context.
type CredSSPPublicKeyBinding struct {
	ClientNonce        [credSSPClientNonceSize]byte
	ClientToServerHash [sha256.Size]byte
	ServerToClientHash [sha256.Size]byte
	valid              bool
}

// NewCredSSPPublicKeyBinding derives CredSSP v5/v6 binding hashes from the
// pinned certificate on this exact TLS transport and a fresh OS-generated
// 32-byte nonce. It does not seal the hashes or send a TSRequest.
func (t *Transport) NewCredSSPPublicKeyBinding() (CredSSPPublicKeyBinding, error) {
	var binding CredSSPPublicKeyBinding
	if t == nil || t.Conn == nil {
		return binding, ErrCredSSPPublicKeyBinding
	}
	state := t.Conn.ConnectionState()
	if verifyNTLMv2TLSPeer(state, t.expectedPin) != nil {
		return CredSSPPublicKeyBinding{}, ErrCredSSPPublicKeyBinding
	}
	if _, err := rand.Read(binding.ClientNonce[:]); err != nil {
		clear(binding.ClientNonce[:])
		return CredSSPPublicKeyBinding{}, ErrCredSSPPublicKeyBinding
	}
	result, err := newCredSSPPublicKeyBinding(state, t.expectedPin, binding.ClientNonce[:])
	if err != nil {
		clear(binding.ClientNonce[:])
		return CredSSPPublicKeyBinding{}, err
	}
	return result, nil
}

func newCredSSPPublicKeyBinding(state tls.ConnectionState, expectedPin tlspin.Fingerprint, nonce []byte) (CredSSPPublicKeyBinding, error) {
	var result CredSSPPublicKeyBinding
	if len(nonce) != credSSPClientNonceSize || verifyNTLMv2TLSPeer(state, expectedPin) != nil {
		return result, ErrCredSSPPublicKeyBinding
	}
	if len(state.PeerCertificates) == 0 {
		return result, ErrCredSSPPublicKeyBinding
	}
	publicKey, err := credSSPSubjectPublicKey(state.PeerCertificates[0])
	if err != nil {
		return result, err
	}
	defer clear(publicKey)
	copy(result.ClientNonce[:], nonce)
	result.ClientToServerHash = credSSPPublicKeyHash([]byte(credSSPClientBindingMagic), nonce, publicKey)
	result.ServerToClientHash = credSSPPublicKeyHash([]byte(credSSPServerBindingMagic), nonce, publicKey)
	result.valid = true
	return result, nil
}

// VerifyServerToClientHash checks the decrypted v5/v6 server pubKeyAuth hash.
// The input must already have been unsealed by the negotiated SSP context.
func (b CredSSPPublicKeyBinding) VerifyServerToClientHash(plaintext []byte) error {
	if !b.valid || len(plaintext) != sha256.Size || subtle.ConstantTimeCompare(plaintext, b.ServerToClientHash[:]) != 1 {
		return ErrCredSSPPublicKeyBinding
	}
	return nil
}

func credSSPPublicKeyHash(magic, nonce, publicKey []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(magic) // The protocol-defined trailing NUL is part of the magic.
	_, _ = h.Write(nonce)
	_, _ = h.Write(publicKey)
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

// credSSPSubjectPublicKey returns the SubjectPublicKey BIT STRING contents,
// not the certificate, full SubjectPublicKeyInfo, or DER wrapper. This is the
// public-key byte sequence consumed by CredSSP v5/v6 binding hashes.
func credSSPSubjectPublicKey(cert *x509.Certificate) ([]byte, error) {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return nil, ErrCredSSPPublicKeyBinding
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info)
	if err != nil || len(rest) != 0 || info.PublicKey.BitLength == 0 || info.PublicKey.BitLength%8 != 0 || info.PublicKey.BitLength != len(info.PublicKey.Bytes)*8 {
		return nil, ErrCredSSPPublicKeyBinding
	}
	return append([]byte(nil), info.PublicKey.Bytes...), nil
}

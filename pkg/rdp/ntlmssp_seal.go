package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"sync"
)

const (
	ntlmSSPMaxSealedMessage     = maxNTLMSSPMessage
	ntlmSSPMessageSignatureSize = 16
)

const (
	ntlmSSPClientToServerSigningMagic = "session key to client-to-server signing key magic constant\x00"
	ntlmSSPServerToClientSigningMagic = "session key to server-to-client signing key magic constant\x00"
	ntlmSSPClientToServerSealingMagic = "session key to client-to-server sealing key magic constant\x00"
	ntlmSSPServerToClientSealingMagic = "session key to server-to-client sealing key magic constant\x00"
)

var ErrNTLMSSPSecurity = errors.New("rdp: invalid NTLMSSP security context or protected message")

// NTLMSSPClientSecurityContext holds the connection-oriented NTLM confidentiality
// state used by CredSSP. WrapClientToServer and UnwrapServerToClient use distinct
// RC4 streams and sequence counters. Close invalidates both directions.
type NTLMSSPClientSecurityContext struct {
	mu       sync.Mutex
	outbound *ntlmSSPProtection
	inbound  *ntlmSSPProtection
	closed   bool
}

type ntlmSSPProtection struct {
	signKey  [md5.Size]byte
	sealKey  [md5.Size]byte
	stream   *rc4.Cipher
	seq      uint32
	poisoned bool
}

// NewNTLMSSPClientSecurityContext creates the client-side NTLM session security
// context after NTLMv2 authentication. The response must be the same validated
// response passed to MarshalNTLMSSPAuthenticate, and challenge must come from
// ParseNTLMSSPChallenge. KEY_EXCH is deliberately not negotiated: the
// NTLMv2 SessionBaseKey is the exported session key for this strict profile.
func NewNTLMSSPClientSecurityContext(response NTLMv2Response, challenge NTLMSSPChallenge) (*NTLMSSPClientSecurityContext, error) {
	if !challenge.valid ||
		!ntlmSSPConfidentialityFlagsValid(challenge.Flags) ||
		!response.valid ||
		response.serverChallenge != challenge.ServerChallenge ||
		len(response.NTResponse) < 16+32+4 || len(response.NTResponse) > maxNTLMSSPMessage ||
		allZero(response.SessionBaseKey[:]) ||
		allZero(response.NTProof[:]) ||
		!hmac.Equal(response.NTResponse[:16], response.NTProof[:]) {
		return nil, ErrNTLMSSPSecurity
	}
	proofTargetInfo, err := NTLMv2ServerTargetInfoForProof(challenge.TargetInfo)
	if err != nil {
		return nil, ErrNTLMSSPSecurity
	}
	defer clear(proofTargetInfo)
	responseTargetInfo := response.NTResponse[16+28 : len(response.NTResponse)-4]
	if !bytes.Equal(responseTargetInfo, proofTargetInfo) {
		return nil, ErrNTLMSSPSecurity
	}
	return newNTLMSSPSecurityContext(response.SessionBaseKey, challenge.Flags, true)
}

// newNTLMSSPSecurityContext is also used by protocol tests to model the peer.
// client selects the local role and therefore the direction of each key.
func newNTLMSSPSecurityContext(exportedSessionKey [16]byte, negotiatedFlags uint32, client bool) (*NTLMSSPClientSecurityContext, error) {
	if !ntlmSSPConfidentialityFlagsValid(negotiatedFlags) || allZero(exportedSessionKey[:]) {
		return nil, ErrNTLMSSPSecurity
	}

	clientSign := ntlmSSPDeriveSessionKey(exportedSessionKey, ntlmSSPClientToServerSigningMagic)
	serverSign := ntlmSSPDeriveSessionKey(exportedSessionKey, ntlmSSPServerToClientSigningMagic)
	clientSeal := ntlmSSPDeriveSessionKey(exportedSessionKey, ntlmSSPClientToServerSealingMagic)
	serverSeal := ntlmSSPDeriveSessionKey(exportedSessionKey, ntlmSSPServerToClientSealingMagic)

	outSign, outSeal := clientSign, clientSeal
	inSign, inSeal := serverSign, serverSeal
	if !client {
		outSign, inSign = serverSign, clientSign
		outSeal, inSeal = serverSeal, clientSeal
	}
	outbound, err := newNTLMSSPProtection(outSign, outSeal)
	if err != nil {
		clear(clientSign[:])
		clear(serverSign[:])
		clear(clientSeal[:])
		clear(serverSeal[:])
		return nil, ErrNTLMSSPSecurity
	}
	inbound, err := newNTLMSSPProtection(inSign, inSeal)
	clear(clientSign[:])
	clear(serverSign[:])
	clear(clientSeal[:])
	clear(serverSeal[:])
	if err != nil {
		outbound.close()
		return nil, ErrNTLMSSPSecurity
	}
	return &NTLMSSPClientSecurityContext{outbound: outbound, inbound: inbound}, nil
}

func ntlmSSPDeriveSessionKey(exportedSessionKey [16]byte, magic string) [md5.Size]byte {
	hash := md5.New()
	_, _ = hash.Write(exportedSessionKey[:])
	_, _ = hash.Write([]byte(magic))
	var key [md5.Size]byte
	copy(key[:], hash.Sum(nil))
	return key
}

func newNTLMSSPProtection(signKey, sealKey [md5.Size]byte) (*ntlmSSPProtection, error) {
	stream, err := rc4.NewCipher(sealKey[:])
	if err != nil {
		return nil, err
	}
	return &ntlmSSPProtection{signKey: signKey, sealKey: sealKey, stream: stream}, nil
}

// WrapClientToServer returns the NTLMSSP message signature followed by the
// RC4-sealed plaintext, matching CredSSP's pubKeyAuth/authInfo wire layout.
func (c *NTLMSSPClientSecurityContext) WrapClientToServer(plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNTLMSSPSecurity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.outbound == nil {
		return nil, ErrNTLMSSPSecurity
	}
	return c.outbound.wrap(plaintext)
}

// UnwrapServerToClient verifies the peer signature before returning plaintext.
// A malformed, replayed, out-of-order or tampered message poisons this direction:
// RC4 is stateful and cannot safely resume after a failed verification.
func (c *NTLMSSPClientSecurityContext) UnwrapServerToClient(message []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNTLMSSPSecurity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.inbound == nil {
		return nil, ErrNTLMSSPSecurity
	}
	return c.inbound.unwrap(message)
}

// Close clears key arrays and makes the context unusable. The standard-library
// RC4 implementation does not expose its internal permutation for zeroization;
// dropping the stream references lets the runtime reclaim them.
func (c *NTLMSSPClientSecurityContext) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.outbound != nil {
		c.outbound.close()
		c.outbound = nil
	}
	if c.inbound != nil {
		c.inbound.close()
		c.inbound = nil
	}
}

func (p *ntlmSSPProtection) wrap(plaintext []byte) ([]byte, error) {
	if p == nil || p.stream == nil || p.poisoned || p.seq == ^uint32(0) || len(plaintext) > ntlmSSPMaxSealedMessage {
		return nil, ErrNTLMSSPSecurity
	}
	signature := make([]byte, ntlmSSPMessageSignatureSize)
	binary.LittleEndian.PutUint32(signature[:4], 1)
	binary.LittleEndian.PutUint32(signature[12:16], p.seq)
	checksum := ntlmSSPHMAC(p.signKey, p.seq, plaintext)
	copy(signature[4:12], checksum[:8])
	clear(checksum[:])

	ciphertext := make([]byte, len(plaintext))
	p.stream.XORKeyStream(ciphertext, plaintext)
	p.seq++
	return append(signature, ciphertext...), nil
}

func (p *ntlmSSPProtection) unwrap(message []byte) ([]byte, error) {
	if p == nil || p.stream == nil || p.poisoned ||
		len(message) < ntlmSSPMessageSignatureSize ||
		len(message) > ntlmSSPMessageSignatureSize+ntlmSSPMaxSealedMessage ||
		binary.LittleEndian.Uint32(message[:4]) != 1 ||
		binary.LittleEndian.Uint32(message[12:16]) != p.seq ||
		p.seq == ^uint32(0) {
		if p != nil {
			p.poisoned = true
		}
		return nil, ErrNTLMSSPSecurity
	}
	plaintext := make([]byte, len(message)-ntlmSSPMessageSignatureSize)
	p.stream.XORKeyStream(plaintext, message[ntlmSSPMessageSignatureSize:])
	checksum := ntlmSSPHMAC(p.signKey, p.seq, plaintext)
	valid := hmac.Equal(message[4:12], checksum[:8])
	clear(checksum[:])
	if !valid {
		clear(plaintext)
		p.poisoned = true
		return nil, ErrNTLMSSPSecurity
	}
	p.seq++
	return plaintext, nil
}

func ntlmSSPHMAC(signKey [md5.Size]byte, sequence uint32, message []byte) [md5.Size]byte {
	mac := hmac.New(md5.New, signKey[:])
	var seq [4]byte
	binary.LittleEndian.PutUint32(seq[:], sequence)
	_, _ = mac.Write(seq[:])
	_, _ = mac.Write(message)
	var checksum [md5.Size]byte
	copy(checksum[:], mac.Sum(nil))
	return checksum
}

func (p *ntlmSSPProtection) close() {
	if p == nil {
		return
	}
	clear(p.signKey[:])
	clear(p.sealKey[:])
	p.stream = nil
	p.poisoned = true
}

func ntlmSSPConfidentialityFlagsValid(flags uint32) bool {
	required := uint32(ntlmSSPNegotiateUnicode | ntlmSSPNegotiateSign | ntlmSSPNegotiateSeal |
		ntlmSSPNegotiateNTLM | ntlmSSPNegotiateAlwaysSign |
		ntlmSSPNegotiateExtendedSessionSecurity | ntlmSSPNegotiateTargetInfo | ntlmSSPNegotiate128)
	allowed := uint32(ntlmSSPNegotiateFlags | ntlmSSPTargetTypeDomain | ntlmSSPTargetTypeServer)
	targetTypes := uint32(ntlmSSPTargetTypeDomain | ntlmSSPTargetTypeServer)
	return flags&required == required &&
		flags&^allowed == 0 &&
		flags&targetTypes != targetTypes
}

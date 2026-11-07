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
	// micInStream: this client sent its mechListMIC unasked, as a signature of this context — its
	// sequence and RC4 stream (MS-NLMP 3.4.4.2) — and checks the server's the same way.
	micInStream bool
}

type ntlmSSPProtection struct {
	signKey [md5.Size]byte
	sealKey [md5.Size]byte
	stream  *rc4.Cipher
	// keyExchange: the checksum is sealed as well, from the same stream (MS-NLMP 3.4.4.2).
	keyExchange bool
	seq         uint32
	poisoned    bool
}

// NewNTLMSSPClientSecurityContext creates the client-side NTLM session security
// context after NTLMv2 authentication. The response must be the same bound
// response passed to MarshalNTLMSSPAuthenticate, and challenge must come from
// ParseNTLMSSPChallenge. KEY_EXCH is negotiated: the session keys derive from
// the bound response's random exported key.
func NewNTLMSSPClientSecurityContext(response NTLMv2Response, challenge NTLMSSPChallenge) (*NTLMSSPClientSecurityContext, error) {
	if !challenge.valid ||
		!ntlmSSPConfidentialityFlagsValid(challenge.Flags) ||
		!response.valid ||
		response.serverChallenge != challenge.ServerChallenge ||
		len(response.NTResponse) < 16+32+4 || len(response.NTResponse) > maxNTLMSSPMessage ||
		allZero(response.SessionBaseKey[:]) ||
		allZero(response.ExportedSessionKey[:]) ||
		allZero(response.NTProof[:]) ||
		!hmac.Equal(response.NTResponse[:16], response.NTProof[:]) {
		return nil, ErrNTLMSSPSecurity
	}
	if !bytes.Equal(response.boundServerInfo, challenge.TargetInfo) {
		return nil, ErrNTLMSSPSecurity
	}
	return newNTLMSSPSecurityContext(response.ExportedSessionKey, challenge.Flags, true)
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
	outbound, err := newNTLMSSPProtection(outSign, outSeal, true)
	if err != nil {
		clear(clientSign[:])
		clear(serverSign[:])
		clear(clientSeal[:])
		clear(serverSeal[:])
		return nil, ErrNTLMSSPSecurity
	}
	inbound, err := newNTLMSSPProtection(inSign, inSeal, true)
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

func newNTLMSSPProtection(signKey, sealKey [md5.Size]byte, keyExchange bool) (*ntlmSSPProtection, error) {
	stream, err := rc4.NewCipher(sealKey[:])
	if err != nil {
		return nil, err
	}
	return &ntlmSSPProtection{signKey: signKey, sealKey: sealKey, stream: stream, keyExchange: keyExchange}, nil
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

// SignMechListMIC signs the SPNEGO mechanism list for the server (RFC 4178, mechListMIC), and
// VerifyMechListMIC checks the server's. Both are at sequence 0 and share no RC4 state with the
// confidentiality streams: each uses a fresh RC4 of the sealing key, as the peer restarts its own
// after this exchange. mechListMICExchanged then counts them: pubKeyAuth is at sequence 1, at the
// start of the stream (measured on FreeRDP 3.15, ADR-0071).
func (c *NTLMSSPClientSecurityContext) SignMechListMIC(mechTypes []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNTLMSSPSecurity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.outbound == nil || len(mechTypes) == 0 {
		return nil, ErrNTLMSSPSecurity
	}
	return ntlmSSPMICSignature(c.outbound.signKey, c.outbound.sealKey, mechTypes)
}

func (c *NTLMSSPClientSecurityContext) VerifyMechListMIC(mechTypes, mic []byte) error {
	if c == nil {
		return ErrNTLMSSPSecurity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.inbound == nil || len(mechTypes) == 0 || len(mic) != ntlmSSPMessageSignatureSize {
		return ErrNTLMSSPSecurity
	}
	if c.micInStream {
		return c.inbound.verifySignature(mechTypes, mic)
	}
	want, err := ntlmSSPMICSignature(c.inbound.signKey, c.inbound.sealKey, mechTypes)
	if err != nil {
		return err
	}
	defer clear(want)
	if !hmac.Equal(mic, want) {
		return ErrNTLMSSPSecurity
	}
	return nil
}

// SignMechListMICInStream signs the mechanism list unasked, when the server did not request it
// but the NTLM AUTHENTICATE carries a MIC (MS-SPNG: such an exchange is not complete without
// mechListMIC; Windows closes the connection otherwise — ADR-0071). It is an SSPI MakeSignature on
// this context: the outbound sequence (0) and RC4 stream, both advanced, so pubKeyAuth follows at
// sequence 1. The server's MIC is then checked the same way.
func (c *NTLMSSPClientSecurityContext) SignMechListMICInStream(mechTypes []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNTLMSSPSecurity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.outbound == nil || c.inbound == nil || len(mechTypes) == 0 || c.outbound.seq != 0 || c.inbound.seq != 0 {
		return nil, ErrNTLMSSPSecurity
	}
	signature, err := c.outbound.sign(mechTypes)
	if err != nil {
		return nil, err
	}
	c.micInStream = true
	return signature, nil
}

func (c *NTLMSSPClientSecurityContext) mechListMICExchanged() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.outbound == nil || c.inbound == nil || c.outbound.seq != 0 || c.inbound.seq != 0 {
		return ErrNTLMSSPSecurity
	}
	c.outbound.seq, c.inbound.seq = 1, 1
	return nil
}

func ntlmSSPMICSignature(signKey, sealKey [md5.Size]byte, message []byte) ([]byte, error) {
	stream, err := rc4.NewCipher(sealKey[:])
	if err != nil {
		return nil, ErrNTLMSSPSecurity
	}
	signature := make([]byte, ntlmSSPMessageSignatureSize)
	binary.LittleEndian.PutUint32(signature[:4], 1)
	checksum := ntlmSSPHMAC(signKey, 0, message)
	stream.XORKeyStream(signature[4:12], checksum[:8])
	clear(checksum[:])
	return signature, nil
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
	if p.keyExchange {
		p.stream.XORKeyStream(signature[4:12], signature[4:12])
	}
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
	received := append([]byte(nil), message[4:12]...)
	if p.keyExchange {
		p.stream.XORKeyStream(received, received)
	}
	checksum := ntlmSSPHMAC(p.signKey, p.seq, plaintext)
	valid := hmac.Equal(received, checksum[:8])
	clear(checksum[:])
	if !valid {
		clear(plaintext)
		p.poisoned = true
		return nil, ErrNTLMSSPSecurity
	}
	p.seq++
	return plaintext, nil
}

// sign is MakeSignature (MS-NLMP 3.4.4.2): the message is not sealed, only its checksum, from the
// same stream as sealing, and the sequence advances.
func (p *ntlmSSPProtection) sign(message []byte) ([]byte, error) {
	if p == nil || p.stream == nil || p.poisoned || p.seq == ^uint32(0) {
		return nil, ErrNTLMSSPSecurity
	}
	signature := make([]byte, ntlmSSPMessageSignatureSize)
	binary.LittleEndian.PutUint32(signature[:4], 1)
	binary.LittleEndian.PutUint32(signature[12:16], p.seq)
	checksum := ntlmSSPHMAC(p.signKey, p.seq, message)
	copy(signature[4:12], checksum[:8])
	clear(checksum[:])
	if p.keyExchange {
		p.stream.XORKeyStream(signature[4:12], signature[4:12])
	}
	p.seq++
	return signature, nil
}

// verifySignature is VerifySignature: the peer's sign, at this sequence and point of the stream.
func (p *ntlmSSPProtection) verifySignature(message, signature []byte) error {
	if p == nil || p.stream == nil || p.poisoned || len(signature) != ntlmSSPMessageSignatureSize ||
		binary.LittleEndian.Uint32(signature[:4]) != 1 || binary.LittleEndian.Uint32(signature[12:16]) != p.seq || p.seq == ^uint32(0) {
		if p != nil {
			p.poisoned = true
		}
		return ErrNTLMSSPSecurity
	}
	received := append([]byte(nil), signature[4:12]...)
	if p.keyExchange {
		p.stream.XORKeyStream(received, received)
	}
	checksum := ntlmSSPHMAC(p.signKey, p.seq, message)
	valid := hmac.Equal(received, checksum[:8])
	clear(checksum[:])
	if !valid {
		p.poisoned = true
		return ErrNTLMSSPSecurity
	}
	p.seq++
	return nil
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
		ntlmSSPNegotiateExtendedSessionSecurity | ntlmSSPNegotiateTargetInfo | ntlmSSPNegotiate128 |
		ntlmSSPNegotiateKeyExchange)
	allowed := uint32(ntlmSSPNegotiateFlags | ntlmSSPTargetTypeDomain | ntlmSSPTargetTypeServer)
	targetTypes := uint32(ntlmSSPTargetTypeDomain | ntlmSSPTargetTypeServer)
	return flags&required == required &&
		flags&^allowed == 0 &&
		flags&targetTypes != targetTypes
}

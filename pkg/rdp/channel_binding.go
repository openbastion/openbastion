package rdp

import (
	"bytes"
	"crypto"
	"crypto/md5"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf16"

	"github.com/openbastion/openbastion/pkg/tlspin"
)

var ErrNTLMv2ChannelBinding = errors.New("rdp: cannot derive NTLMv2 TLS channel binding")

// NTLMv2ClientBindings contains values derived from the selected target and
// the exact pinned TLS connection. TargetName is UTF-16LE without a NUL.
type NTLMv2ClientBindings struct {
	TargetName      []byte
	ChannelBindings [16]byte
}

// NTLMv2TargetName returns the RDP service principal for the DNS name or IP
// address already used for TLS server-name verification. It is UTF-16LE and
// deliberately has no trailing NUL, as required by MsvAvTargetName.
func NTLMv2TargetName(serverName string) ([]byte, error) {
	name := strings.TrimSuffix(serverName, ".")
	if name == "" || strings.TrimSpace(name) != name || !validNTLMv2Identity(name) {
		return nil, ErrNTLMv2Input
	}
	// DNS names are case-insensitive. Keep IP literals in their canonical form
	// too, so the SPN is deterministic across equivalent input spellings.
	if ip := net.ParseIP(name); ip != nil {
		name = ip.String()
	} else {
		if !validNTLMv2DNSName(name) {
			return nil, ErrNTLMv2Input
		}
		name = strings.ToLower(name)
	}
	encoded, ok := utf16LEFromUTF8([]byte("TERMSRV/" + name))
	if !ok || len(encoded) == 0 || len(encoded) > maxNTLMv2TargetInfo {
		clear(encoded)
		return nil, ErrNTLMv2Input
	}
	return encoded, nil
}

func validNTLMv2DNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isASCIIAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

// NTLMv2TargetInfoWithMICFlag creates the TargetInfo carried in AUTHENTICATE
// and sets MsvAvFlags.MIC_PRESENT after NTProof has been computed over the
// original server TargetInfo. Unsupported server flag bits are rejected.
func NTLMv2TargetInfoWithMICFlag(serverTargetInfo []byte) ([]byte, error) {
	pairs, err := ParseNTLMv2AVPairs(serverTargetInfo)
	if err != nil {
		return nil, err
	}
	flagsFound := false
	for _, pair := range pairs {
		if pair.ID == ntlmAvFlags {
			flagsFound = true
			if binary.LittleEndian.Uint32(pair.Value)&^uint32(0x00000002) != 0 {
				return nil, ErrNTLMv2Input
			}
		}
	}
	result := make([]byte, 0, len(serverTargetInfo)+8)
	for _, pair := range pairs {
		if pair.ID == ntlmAvFlags {
			result = appendNTLMv2AVPair(result, pair.ID, []byte{0x02, 0, 0, 0})
		} else {
			result = appendNTLMv2AVPair(result, pair.ID, pair.Value)
		}
	}
	if !flagsFound {
		result = appendNTLMv2AVPair(result, ntlmAvFlags, []byte{0x02, 0, 0, 0})
	}
	result = append(result, 0, 0, 0, 0)
	if len(result) > maxNTLMv2TargetInfo {
		clear(result)
		return nil, ErrNTLMv2Input
	}
	return result, nil
}

// NTLMv2TargetInfoWithClientBindings creates the TargetInfo carried in the
// NTLMv2 AUTHENTICATE response. NTProof is calculated over the server's
// original TargetInfo; MIC_PRESENT and the client channel/target AV_PAIRs are
// added only after ComputeNTLMv2Response, as required by MS-NLMP §3.1.5.1.2.
func NTLMv2TargetInfoWithClientBindings(serverTargetInfo []byte, bindings NTLMv2ClientBindings) ([]byte, error) {
	if !validNTLMv2TargetNameValue(bindings.TargetName) || allZero(bindings.ChannelBindings[:]) {
		return nil, ErrNTLMv2Input
	}
	pairs, err := ParseNTLMv2AVPairs(serverTargetInfo)
	if err != nil {
		return nil, err
	}
	for _, pair := range pairs {
		if pair.ID == ntlmAvTargetName || pair.ID == ntlmAvChannelBindings {
			return nil, ErrNTLMv2Input
		}
	}
	withMIC, err := NTLMv2TargetInfoWithMICFlag(serverTargetInfo)
	if err != nil {
		return nil, err
	}
	defer clear(withMIC)
	result := append([]byte(nil), withMIC[:len(withMIC)-4]...)
	result = appendNTLMv2AVPair(result, ntlmAvChannelBindings, bindings.ChannelBindings[:])
	result = appendNTLMv2AVPair(result, ntlmAvTargetName, bindings.TargetName)
	result = append(result, 0, 0, 0, 0)
	if len(result) > maxNTLMv2TargetInfo {
		clear(result)
		return nil, ErrNTLMv2Input
	}
	return result, nil
}

func appendNTLMv2AVPair(dst []byte, id uint16, value []byte) []byte {
	dst = append(dst, byte(id), byte(id>>8), byte(len(value)), byte(len(value)>>8))
	return append(dst, value...)
}

func validNTLMv2TargetNameValue(value []byte) bool {
	if len(value) == 0 || !validUTF16LE(value) {
		return false
	}
	units := make([]uint16, len(value)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(value[i*2:])
	}
	name := string(utf16.Decode(units))
	clear(units)
	if !strings.HasPrefix(name, "TERMSRV/") {
		return false
	}
	expected, err := NTLMv2TargetName(strings.TrimPrefix(name, "TERMSRV/"))
	if err != nil {
		return false
	}
	defer clear(expected)
	return bytes.Equal(expected, value)
}

// NTLMv2ChannelBindings derives MsvAvChannelBindings from the peer certificate
// in a completed TLS handshake. It implements tls-server-end-point (RFC 5929)
// and the NTLM/GSS channel-bindings MD5 serialization (MS-NLMP §2.2.2.1).
// Callers must pass the ConnectionState from the same pinned TLS connection
// that will carry CredSSP; an empty or certificate-less state fails closed.
func NTLMv2ChannelBindings(state tls.ConnectionState) ([16]byte, error) {
	var result [16]byte
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return result, ErrNTLMv2ChannelBinding
	}
	cert := state.PeerCertificates[0]
	hash, ok := tlsServerEndpointHash(cert.SignatureAlgorithm)
	if !ok || !hash.Available() {
		return result, ErrNTLMv2ChannelBinding
	}
	certificateHash := hash.New()
	_, _ = certificateHash.Write(cert.Raw)
	endpoint := append([]byte("tls-server-end-point:"), certificateHash.Sum(nil)...)

	// RFC 4121 hashes the GSS channel-bindings integer and length fields in
	// declaration order (little-endian), including zero address lengths, then
	// the non-empty application data. Windows Schannel exposes the same
	// application data as tls-server-end-point in SEC_CHANNEL_BINDINGS.
	if uint64(len(endpoint)) > uint64(^uint32(0)) {
		clear(endpoint)
		return result, ErrNTLMv2ChannelBinding
	}
	unhashed := make([]byte, 20+len(endpoint))
	binary.LittleEndian.PutUint32(unhashed[16:20], uint32(len(endpoint)))
	copy(unhashed[20:], endpoint)
	result = md5.Sum(unhashed)
	clear(endpoint)
	clear(unhashed)
	return result, nil
}

func verifyNTLMv2TLSPeer(state tls.ConnectionState, expected tlspin.Fingerprint) error {
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return ErrNTLMv2ChannelBinding
	}
	if err := tlspin.VerifyCertificate(state.PeerCertificates[0].Raw, expected); err != nil {
		return ErrNTLMv2ChannelBinding
	}
	return nil
}

func tlsServerEndpointHash(algorithm x509.SignatureAlgorithm) (crypto.Hash, bool) {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return crypto.SHA256, true
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256,
		x509.SHA256WithRSAPSS:
		return crypto.SHA256, true
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384, true
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512, true
	default:
		// Ed25519, unknown, and algorithms without one unambiguous hash are
		// intentionally unsupported by RFC 5929 tls-server-end-point.
		return 0, false
	}
}

// NTLMv2Bindings returns both values tied to the target selected during
// DialHybrid. The TLS channel binding always comes from this exact connection.
func (t *Transport) NTLMv2Bindings() (targetName []byte, channelBindings [16]byte, err error) {
	if t == nil || t.Conn == nil || t.targetServerName == "" {
		return nil, channelBindings, fmt.Errorf("%w: transport is not established", ErrNTLMv2ChannelBinding)
	}
	state := t.Conn.ConnectionState()
	if err := verifyNTLMv2TLSPeer(state, t.expectedPin); err != nil {
		return nil, channelBindings, err
	}
	targetName, err = NTLMv2TargetName(t.targetServerName)
	if err != nil {
		return nil, channelBindings, err
	}
	channelBindings, err = NTLMv2ChannelBindings(state)
	if err != nil {
		clear(targetName)
		return nil, [16]byte{}, err
	}
	return targetName, channelBindings, nil
}

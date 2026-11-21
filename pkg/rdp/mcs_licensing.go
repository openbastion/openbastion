package rdp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	rdpSecLicensePacket    = uint16(0x0080)
	rdpSecLicenseEncryptCS = uint16(0x0200)

	rdpLicenseRequest         = byte(0x01)
	rdpLicenseNewRequest      = byte(0x13)
	rdpLicenseErrorAlert      = byte(0xff)
	rdpLicenseProtocolVersion = byte(0x03)
	rdpLicenseExtendedErrors  = byte(0x80)

	rdpLicenseBlobRandom      = uint16(0x0002)
	rdpLicenseBlobCertificate = uint16(0x0003)
	rdpLicenseBlobError       = uint16(0x0004)
	rdpLicenseBlobKeyExchange = uint16(0x000d)
	rdpLicenseBlobScope       = uint16(0x000e)
	rdpLicenseBlobUsername    = uint16(0x000f)
	rdpLicenseBlobMachineName = uint16(0x0010)

	rdpLicenseKeyExchangeRSA = uint32(0x00000001)
	rdpLicensePlatformWinNT  = uint32(0x04010000)
	rdpLicenseStatusValid    = uint32(0x00000007)
	rdpLicenseNoTransition   = uint32(0x00000002)

	maxRDPServerLicenseScopes = 32
	maxRDPLicenseBlobSize     = maxTPKTPacket
	maxRDPLicenseStringSize   = 512
	maxRDPLicenseIdentitySize = 255
)

// CompleteLicensing runs the licensing phase (MS-RDPBCGR 1.3.1.1, phase 7; MS-RDPELE): a server with
// nothing to license, or one in its grace period, answers STATUS_VALID_CLIENT at once or after the
// client's request; a Remote Desktop Session Host may challenge the client (platform challenge),
// then issue or upgrade a license (ADR-0099, option B), which is kept in Licenses and presented
// again at the next connection with the same LicenseScope. Anything else fails closed.
func (s *CredSSPClientSession) CompleteLicensing(ctx context.Context, timeout time.Duration) (err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return ErrMCSConnection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil ||
		!s.credentialsDelegated || !s.mcsConnected || !s.channelsConnected ||
		!s.clientInfoSent || s.licensingAttempted || s.licensingComplete ||
		!validMCSUserID(s.userChannelID) || !s.transport.Conn.ConnectionState().HandshakeComplete {
		return ErrMCSConnection
	}

	conn := s.transport.Conn
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.closeTransportLocked()
		return ErrMCSConnection
	}
	fallbackKey, _ := state.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
	if fallbackKey != nil && (fallbackKey.N == nil || fallbackKey.N.BitLen() < 1024) {
		fallbackKey = nil
	}
	if !validLicenseANSI(s.licensingUsername, maxRDPLicenseIdentitySize) ||
		!validLicenseANSI(s.mcsSettings.ClientName, 15) {
		s.closeTransportLocked()
		return ErrMCSConnection
	}
	s.licensingAttempted = true

	if timeout == 0 {
		timeout = defaultCredSSPTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		s.closeTransportLocked()
		return ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.closeTransportLocked()
			// What failed is said (a stage, a message type, a code: never a secret), for an
			// operator and for the CI against a real host; anything else is ErrMCSConnection.
			if !errors.Is(err, ErrMCSConnection) {
				err = ErrMCSConnection
			}
			return
		}
		if setErr := conn.SetDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.closeTransportLocked()
			err = ErrMCSConnection
			return
		}
		s.licensingComplete = true
	}()

	serverPacket, readErr := readMCSConnectResponse(conn)
	if readErr != nil {
		return ErrMCSConnection
	}
	// A server with nothing to license answers at once (MS-RDPBCGR 1.3.1.1, phase 7).
	if parseRDPServerLicenseSuccess(serverPacket, s.mcsResponse.IOChannelID) {
		clear(serverPacket)
		return nil
	}
	licenseKey, serverRandom, parseErr := parseRDPServerLicenseRequestRandom(serverPacket, s.mcsResponse.IOChannelID, fallbackKey)
	if parseErr != nil {
		if typ, body, ok := licensePreamble(serverPacket, s.mcsResponse.IOChannelID); ok && typ != rdpLicenseRequest {
			parseErr = licensingRefused("the server's first message: %s", describeLicensingMessage(typ, body))
		}
		clear(serverPacket)
		return parseErr
	}
	clear(serverPacket)

	clientRandom := make([]byte, 32)
	preMaster := make([]byte, 48)
	defer clear(clientRandom)
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		return ErrMCSConnection
	}
	if _, err := io.ReadFull(rand.Reader, preMaster); err != nil {
		clear(preMaster)
		return ErrMCSConnection
	}
	keys := deriveLicensingKeys(preMaster, clientRandom, serverRandom)
	defer keys.clear()
	encryptedPreMaster, encErr := rsa.EncryptPKCS1v15(rand.Reader, licenseKey, preMaster)
	clear(preMaster)
	if encErr != nil || len(encryptedPreMaster) > maxRDPLicenseBlobSize {
		return ErrMCSConnection
	}
	defer clear(encryptedPreMaster)

	cache, scope := s.mcsSettings.Licenses, s.mcsSettings.LicenseScope
	hwid := cache.hardwareID()
	kept := cache.get(scope)
	defer clear(kept)
	var request []byte
	var buildErr error
	if len(kept) != 0 {
		request, buildErr = marshalRDPClientLicenseInfo(s.userChannelID, s.mcsResponse.IOChannelID, encryptedPreMaster, clientRandom, kept, keys, hwid)
	} else {
		request, buildErr = marshalRDPClientNewLicenseRequestWith(s.userChannelID, s.mcsResponse.IOChannelID,
			encryptedPreMaster, clientRandom, s.licensingUsername, s.mcsSettings.ClientName)
	}
	if buildErr != nil {
		return ErrMCSConnection
	}
	sendErr := writeFull(conn, request)
	clear(request)
	if ctx.Err() != nil || sendErr != nil {
		return ErrMCSConnection
	}
	if len(kept) != 0 {
		cache.notePresented()
	}

	for challenges := 0; ; {
		serverPacket, readErr = readMCSConnectResponse(conn)
		if readErr != nil {
			return ErrMCSConnection
		}
		if parseRDPServerLicenseSuccess(serverPacket, s.mcsResponse.IOChannelID) {
			clear(serverPacket)
			return nil
		}
		messageType, body, ok := licensePreamble(serverPacket, s.mcsResponse.IOChannelID)
		if !ok {
			clear(serverPacket)
			return ErrMCSConnection
		}
		switch messageType {
		case rdpLicensePlatformChallenge:
			challenges++
			if challenges > maxRDPLicensePlatformChallenges {
				clear(serverPacket)
				return licensingRefused("a platform challenge more than %d", maxRDPLicensePlatformChallenges)
			}
			challenge, ok := parseRDPServerPlatformChallenge(body, keys)
			if !ok {
				shape := describeLicensingBlob(body, 4)
				clear(serverPacket)
				return licensingRefused("platform challenge %d, not decrypted and checked (a MAC that does not match, or its shape): %s", challenges, shape)
			}
			clear(serverPacket)
			cache.noteChallenge()
			response, err := marshalRDPClientPlatformChallengeResponse(s.userChannelID, s.mcsResponse.IOChannelID, keys, challenge, hwid)
			clear(challenge)
			if err != nil {
				return ErrMCSConnection
			}
			sendErr := writeFull(conn, response)
			clear(response)
			if ctx.Err() != nil || sendErr != nil {
				return ErrMCSConnection
			}
		case rdpLicenseNewLicense, rdpLicenseUpgradeLicense:
			license, ok := parseRDPServerNewLicense(body, keys)
			if !ok {
				shape := describeLicensingBlob(body, 0)
				clear(serverPacket)
				return licensingRefused("the license issued (type %#x), not decrypted and checked (a MAC that does not match, or its shape): %s", messageType, shape)
			}
			clear(serverPacket)
			cache.put(scope, license)
			clear(license)
			return nil
		default:
			// An error alert other than STATUS_VALID_CLIENT, or any other message: refused. A
			// license that was presented and refused is not presented again.
			described := describeLicensingMessage(messageType, body)
			clear(serverPacket)
			if len(kept) != 0 {
				cache.drop(scope)
			}
			return licensingRefused("after the client's %s (%d challenge(s)): %s", map[bool]string{true: "license presented again", false: "new license request"}[len(kept) != 0], challenges, described)
		}
	}
}

func validLicenseANSI(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// marshalRDPClientNewLicenseRequest builds CLIENT_NEW_LICENSE_REQUEST with randoms of its own (the
// tests' entry; CompleteLicensing keeps its randoms for the keys of the exchange).
func marshalRDPClientNewLicenseRequest(userID, ioChannelID uint16, serverKey *rsa.PublicKey, username, machineName string) ([]byte, error) {
	if !validMCSUserID(userID) || ioChannelID != mcsGlobalChannelID ||
		serverKey == nil || serverKey.N == nil || serverKey.N.BitLen() < 1024 ||
		!validLicenseANSI(username, maxRDPLicenseIdentitySize) || !validLicenseANSI(machineName, 15) {
		return nil, ErrMCSConnection
	}

	clientRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		return nil, ErrMCSConnection
	}
	defer clear(clientRandom)
	preMaster := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, preMaster); err != nil {
		clear(preMaster)
		return nil, ErrMCSConnection
	}
	encryptedPreMaster, err := rsa.EncryptPKCS1v15(rand.Reader, serverKey, preMaster)
	clear(preMaster)
	if err != nil || len(encryptedPreMaster) > maxRDPLicenseBlobSize {
		clear(encryptedPreMaster)
		return nil, ErrMCSConnection
	}
	defer clear(encryptedPreMaster)
	return marshalRDPClientNewLicenseRequestWith(userID, ioChannelID, encryptedPreMaster, clientRandom, username, machineName)
}

// marshalRDPClientNewLicenseRequestWith is CLIENT_NEW_LICENSE_REQUEST (MS-RDPELE 2.2.2.2) for the
// given ClientRandom and encrypted premaster secret.
func marshalRDPClientNewLicenseRequestWith(userID, ioChannelID uint16, encryptedPreMaster, clientRandom []byte, username, machineName string) ([]byte, error) {
	if !validMCSUserID(userID) || ioChannelID != mcsGlobalChannelID || len(clientRandom) != 32 || len(encryptedPreMaster) == 0 ||
		!validLicenseANSI(username, maxRDPLicenseIdentitySize) || !validLicenseANSI(machineName, 15) {
		return nil, ErrMCSConnection
	}
	message := make([]byte, 8, 8+len(clientRandom)+len(encryptedPreMaster)+len(username)+len(machineName)+32)
	binary.LittleEndian.PutUint32(message[0:4], rdpLicenseKeyExchangeRSA)
	binary.LittleEndian.PutUint32(message[4:8], rdpLicensePlatformWinNT)
	message = append(message, clientRandom...)
	message = appendLicenseBlob(message, rdpLicenseBlobRandom, encryptedPreMaster)
	message = appendLicenseBlob(message, rdpLicenseBlobUsername, append([]byte(username), 0))
	message = appendLicenseBlob(message, rdpLicenseBlobMachineName, append([]byte(machineName), 0))

	preamble := make([]byte, 4, 4+len(message))
	preamble[0] = rdpLicenseNewRequest
	preamble[1] = rdpLicenseProtocolVersion | rdpLicenseExtendedErrors
	if len(preamble)+len(message) > 0xffff {
		clear(message)
		return nil, ErrMCSConnection
	}
	binary.LittleEndian.PutUint16(preamble[2:4], uint16(len(preamble)+len(message)))
	preamble = append(preamble, message...)
	clear(message)

	security := make([]byte, 4, 4+len(preamble))
	binary.LittleEndian.PutUint16(security[:2], rdpSecLicensePacket)
	security = append(security, preamble...)
	clear(preamble)
	packet, err := marshalMCSSendDataRequest(userID, ioChannelID, security)
	clear(security)
	if err != nil {
		return nil, ErrMCSConnection
	}
	return packet, nil
}

func appendLicenseBlob(dst []byte, typ uint16, value []byte) []byte {
	dst = append(dst, 0, 0, 0, 0)
	offset := len(dst) - 4
	binary.LittleEndian.PutUint16(dst[offset:offset+2], typ)
	binary.LittleEndian.PutUint16(dst[offset+2:offset+4], uint16(len(value)))
	return append(dst, value...)
}

func parseRDPServerLicenseRequest(packet []byte, expectedChannelID uint16, fallbackKey *rsa.PublicKey) (*rsa.PublicKey, error) {
	key, serverRandom, err := parseRDPServerLicenseRequestRandom(packet, expectedChannelID, fallbackKey)
	clear(serverRandom)
	return key, err
}

// parseRDPServerLicenseRequestRandom reads SERVER_LICENSE_REQUEST and returns the key the premaster
// secret is encrypted to and the ServerRandom, which the licensing keys are derived from.
func parseRDPServerLicenseRequestRandom(packet []byte, expectedChannelID uint16, fallbackKey *rsa.PublicKey) (*rsa.PublicKey, []byte, error) {
	userData, err := parseMCSLicensingIndication(packet, expectedChannelID)
	if err != nil {
		return nil, nil, err
	}
	if len(userData) < 4+4+32+12+8+4 {
		return nil, nil, licensingRefused("the request: %d bytes", len(packet))
	}
	preamble := userData[4:]
	if preamble[0] != rdpLicenseRequest || preamble[1]&0x0f != rdpLicenseProtocolVersion ||
		preamble[1]&0x70 != 0 || int(binary.LittleEndian.Uint16(preamble[2:4])) != len(preamble) {
		return nil, nil, licensingRefused("the request preamble: type %#x, flags %#x", preamble[0], preamble[1])
	}
	body := preamble[4:]
	if len(body) < 32+12 {
		return nil, nil, licensingRefused("the request body")
	}
	serverRandom := append([]byte(nil), body[:32]...) // TLS already authenticates the server identity.
	body = body[32:]
	if len(body) < 12 {
		return nil, nil, licensingRefused("the request ServerRandom")
	}
	body = body[4:] // ProductInfo.dwVersion
	companyLength := int(binary.LittleEndian.Uint32(body[:4]))
	body = body[4:]
	if companyLength > maxRDPLicenseStringSize || !validLicenseUTF16Blob(body, companyLength) {
		return nil, nil, licensingRefused("the request company name")
	}
	body = body[companyLength:]
	if len(body) < 4 {
		return nil, nil, licensingRefused("the request product")
	}
	productLength := int(binary.LittleEndian.Uint32(body[:4]))
	body = body[4:]
	if productLength > maxRDPLicenseStringSize || !validLicenseUTF16Blob(body, productLength) {
		return nil, nil, licensingRefused("the request product name")
	}
	body = body[productLength:]

	blobType, blobValue, rest, ok := readLicenseBlob(body)
	if !ok || blobType != rdpLicenseBlobKeyExchange || len(blobValue) == 0 || len(blobValue)%4 != 0 {
		return nil, nil, licensingRefused("the request key exchange list")
	}
	hasRSA := false
	for len(blobValue) > 0 {
		if binary.LittleEndian.Uint32(blobValue[:4]) == rdpLicenseKeyExchangeRSA {
			hasRSA = true
		}
		blobValue = blobValue[4:]
	}
	if !hasRSA {
		return nil, nil, licensingRefused("the request: no RSA key exchange")
	}
	body = rest
	var certificateBlob []byte
	blobType, certificateBlob, body, ok = readLicenseBlob(body)
	if !ok || blobType != rdpLicenseBlobCertificate {
		return nil, nil, licensingRefused("the request certificate blob")
	}
	licenseKey, certErr := parseRDPServerLicenseCertificate(certificateBlob, fallbackKey)
	if certErr != nil {
		return nil, nil, certErr
	}
	if len(body) < 4 {
		return nil, nil, licensingRefused("the request scope count")
	}
	scopeCount := binary.LittleEndian.Uint32(body[:4])
	body = body[4:]
	if scopeCount > maxRDPServerLicenseScopes {
		return nil, nil, licensingRefused("the request: %d scopes", scopeCount)
	}
	for i := uint32(0); i < scopeCount; i++ {
		blobType, _, body, ok = readLicenseBlob(body)
		if !ok || blobType != rdpLicenseBlobScope {
			return nil, nil, licensingRefused("the request scope %d", i)
		}
	}
	if len(body) != 0 {
		return nil, nil, licensingRefused("the request: %d bytes after its scopes", len(body))
	}
	return licenseKey, serverRandom, nil
}

// parseRDPServerLicenseCertificate extracts the RSA key from the server's
// licensing certificate. The blob is delivered inside the already-authenticated
// TLS channel; the TLS peer identity therefore authenticates this key material.
// Empty blobs use the TLS certificate key, as permitted by MS-RDPELE.
func parseRDPServerLicenseCertificate(blob []byte, fallback *rsa.PublicKey) (*rsa.PublicKey, error) {
	if len(blob) == 0 {
		if fallback == nil || fallback.N == nil || fallback.N.BitLen() < 1024 {
			return nil, licensingRefused("no certificate, and the TLS key is not RSA of 1024 bits or more")
		}
		return fallback, nil
	}
	if len(blob) >= 4 && binary.LittleEndian.Uint32(blob[:4])&0x7fffffff == 1 {
		return parseRDPProprietaryCertificate(blob[4:])
	}
	if len(blob) < 8 || binary.LittleEndian.Uint32(blob[:4])&0x7fffffff != 2 {
		return nil, licensingRefused("the certificate: version %#x, neither proprietary nor an X.509 chain", licenseCertificateVersion(blob))
	}
	count := binary.LittleEndian.Uint32(blob[4:8])
	if count == 0 || count > 8 {
		return nil, licensingRefused("the certificate chain: %d certificates", count)
	}
	body := blob[8:]
	var leaf []byte
	for i := uint32(0); i < count; i++ {
		if len(body) < 4 {
			return nil, licensingRefused("the certificate chain: certificate %d truncated", i)
		}
		length := int(binary.LittleEndian.Uint32(body[:4]))
		body = body[4:]
		if length <= 0 || length > maxRDPLicenseBlobSize || len(body) < length {
			return nil, licensingRefused("the certificate chain: certificate %d of %d bytes", i, length)
		}
		// The chain goes from the license server's issuer to the terminal server: the key the
		// premaster secret is encrypted to is the last certificate's (MS-RDPELE 2.2.1.4.2, as
		// FreeRDP reads it).
		leaf = body[:length]
		body = body[length:]
	}
	// MS-RDPELE 2.2.1.4.2: 8 + 4 x NumCertBlobs bytes of padding end the chain.
	if len(body) != 0 && len(body) != 8+4*int(count) {
		return nil, licensingRefused("the certificate chain: %d bytes after %d certificates", len(body), count)
	}
	key, err := licenseCertificateRSAKey(leaf)
	if err != nil {
		return nil, err
	}
	if key.N == nil || key.N.BitLen() < 1024 {
		return nil, licensingRefused("the terminal server key: %d bits", key.N.BitLen())
	}
	return key, nil
}

// licenseCertificateRSAKey is the RSA key of a terminal server certificate. A license server issues
// it, and Go's X.509 parser may refuse what it signs; the key is then read from the certificate's
// SubjectPublicKeyInfo alone (an RSAPublicKey in its BIT STRING, RFC 5280 4.1), whatever the
// algorithm says. The TLS channel, pinned, authenticates the server: this key only encrypts the
// premaster secret of the licensing exchange.
func licenseCertificateRSAKey(der []byte) (*rsa.PublicKey, error) {
	if cert, err := x509.ParseCertificate(der); err == nil {
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, licensingRefused("the terminal server key is not RSA")
		}
		return key, nil
	}
	var certificate struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &certificate); err != nil || len(rest) != 0 {
		return nil, licensingRefused("the terminal server certificate is not DER: %v", err)
	}
	// TBSCertificate: [0] version (optional), serial, signature, issuer, validity, subject, SPKI.
	fields := certificate.TBS.Bytes
	var field asn1.RawValue
	index := 0
	for len(fields) > 0 {
		next, err := asn1.Unmarshal(fields, &field)
		if err != nil {
			return nil, licensingRefused("the terminal server certificate's fields: %v", err)
		}
		fields = next
		if index == 0 && field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			continue // version
		}
		if index == 5 {
			var spki struct {
				Algorithm asn1.RawValue
				PublicKey asn1.BitString
			}
			if _, err := asn1.Unmarshal(field.FullBytes, &spki); err != nil {
				return nil, licensingRefused("the terminal server key info: %v", err)
			}
			key, err := x509.ParsePKCS1PublicKey(spki.PublicKey.Bytes)
			if err != nil {
				return nil, licensingRefused("the terminal server key: %v", err)
			}
			return key, nil
		}
		index++
	}
	return nil, licensingRefused("the terminal server certificate has no key")
}

func validLicenseUTF16Blob(data []byte, length int) bool {
	if length < 2 || length > maxRDPLicenseBlobSize || length%2 != 0 || len(data) < length ||
		data[length-2] != 0 || data[length-1] != 0 {
		return false
	}
	units := make([]uint16, 0, length/2-1)
	defer clear(units)
	for i := 0; i < length-2; i += 2 {
		unit := binary.LittleEndian.Uint16(data[i : i+2])
		if unit == 0 {
			return false
		}
		units = append(units, unit)
	}
	runes := utf16.Decode(units)
	defer clear(runes)
	return equalUint16(units, utf16.Encode(runes))
}

func readLicenseBlob(data []byte) (uint16, []byte, []byte, bool) {
	if len(data) < 4 {
		return 0, nil, nil, false
	}
	typ := binary.LittleEndian.Uint16(data[:2])
	length := int(binary.LittleEndian.Uint16(data[2:4]))
	if length > maxRDPLicenseBlobSize || len(data) < 4+length {
		return 0, nil, nil, false
	}
	return typ, data[4 : 4+length], data[4+length:], true
}

func parseMCSLicensingIndication(packet []byte, expectedChannelID uint16) ([]byte, error) {
	if len(packet) < 7+7+4 || len(packet) > maxTPKTPacket || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) {
		return nil, licensingRefused("not one TPKT and X.224 data packet (%d bytes)", len(packet))
	}
	mcs := packet[7:]
	if len(mcs) < 7 || mcs[0] != mcsSendDataIndication {
		return nil, licensingRefused("not an MCS Send Data Indication (%#x)", mcs[0])
	}
	if binary.BigEndian.Uint16(mcs[3:5]) != expectedChannelID || mcs[5] != 0x70 {
		return nil, licensingRefused("MCS channel %d, priority and segmentation %#x", binary.BigEndian.Uint16(mcs[3:5]), mcs[5])
	}
	length, rest, err := readPERLength(mcs[6:])
	if err != nil || length == 0 || length > maxTPKTPacket || len(rest) != length || len(rest) < 4 {
		return nil, licensingRefused("MCS user data of %d bytes for %d", len(rest), length)
	}
	// The basic security header (MS-RDPBCGR 2.2.8.1.1.2.1): SEC_LICENSE_PKT, and possibly
	// SEC_LICENSE_ENCRYPT_CS, which a Remote Desktop Session Host sets to say the client may encrypt
	// its licensing messages; under TLS nothing else (no SEC_ENCRYPT, no SEC_FLAGSHI_VALID). flagsHi
	// is ignored without SEC_FLAGSHI_VALID, as the specification says and FreeRDP does: a session
	// host fills it with what looks like garbage (0x46, 0x1648, 0xafe2… in CI of PR #259).
	flags := binary.LittleEndian.Uint16(rest[:2])
	if flags&rdpSecLicensePacket == 0 || flags&^(rdpSecLicensePacket|rdpSecLicenseEncryptCS) != 0 {
		return nil, licensingRefused("security header flags %#x", flags)
	}
	return rest, nil
}

func parseRDPServerLicenseSuccess(packet []byte, expectedChannelID uint16) bool {
	userData, err := parseMCSLicensingIndication(packet, expectedChannelID)
	if err != nil || len(userData) < 4+4+12 {
		return false
	}
	preamble := userData[4:]
	if preamble[0] != rdpLicenseErrorAlert || preamble[1]&0x0f != rdpLicenseProtocolVersion ||
		preamble[1]&0x70 != 0 || int(binary.LittleEndian.Uint16(preamble[2:4])) != len(preamble) ||
		len(preamble) != 4+12 {
		return false
	}
	body := preamble[4:]
	return binary.LittleEndian.Uint32(body[0:4]) == rdpLicenseStatusValid &&
		binary.LittleEndian.Uint32(body[4:8]) == rdpLicenseNoTransition &&
		binary.LittleEndian.Uint16(body[8:10]) == rdpLicenseBlobError &&
		binary.LittleEndian.Uint16(body[10:12]) == 0
}

func equalUint16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// licensingRefused is ErrMCSConnection said with what failed in the licensing phase.
func licensingRefused(format string, args ...any) error {
	return fmt.Errorf("%w: licensing: "+format, append([]any{ErrMCSConnection}, args...)...)
}

// describeLicensingMessage names a server's licensing message, with an error alert's code and state
// transition (MS-RDPBCGR 2.2.1.12.1.3).
func describeLicensingMessage(messageType byte, body []byte) string {
	if messageType == rdpLicenseErrorAlert && len(body) >= 8 {
		return fmt.Sprintf("error alert, code %#x, state transition %#x", binary.LittleEndian.Uint32(body[0:4]), binary.LittleEndian.Uint32(body[4:8]))
	}
	return fmt.Sprintf("message type %#x, %d bytes", messageType, len(body))
}

// licenseCertificateVersion is the dwVersion of a license server certificate blob: 1 proprietary,
// 0x80000002 X.509 chain (MS-RDPBCGR 2.2.1.4.3.1).
func licenseCertificateVersion(blob []byte) uint32 {
	if len(blob) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(blob[:4])
}

// describeLicensingBlob says the shape of an encrypted blob at offset skip of a message body: its
// type, its length, and what follows it (the MAC is 16 bytes).
func describeLicensingBlob(body []byte, skip int) string {
	if len(body) < skip {
		return fmt.Sprintf("%d bytes", len(body))
	}
	typ, value, rest, ok := readLicenseBlob(body[skip:])
	if !ok {
		return fmt.Sprintf("%d bytes, no blob", len(body))
	}
	return fmt.Sprintf("blob type %#x of %d bytes, then %d bytes", typ, len(value), len(rest))
}

// parseRDPProprietaryCertificate reads a proprietary server certificate (MS-RDPBCGR 2.2.1.4.3.1.1),
// after its dwVersion: RSA for the signature and the key exchange, an RSA1 public key blob, then the
// signature blob. A session host presents it until it holds an X.509 certificate from an activated
// license server (CI of PR #259). The signature is made with the Terminal Services signing key, whose
// private part MS-RDPBCGR 5.3.3.1.1 publishes: verifying it would authenticate nothing, so its shape
// alone is checked. The pinned TLS channel authenticates the server; this key only encrypts the
// premaster secret of the licensing exchange.
func parseRDPProprietaryCertificate(body []byte) (*rsa.PublicKey, error) {
	if len(body) < 12 {
		return nil, licensingRefused("the proprietary certificate: %d bytes", len(body))
	}
	if binary.LittleEndian.Uint32(body[0:4]) != 1 || binary.LittleEndian.Uint32(body[4:8]) != 1 {
		return nil, licensingRefused("the proprietary certificate: algorithms %#x, %#x, RSA alone is accepted",
			binary.LittleEndian.Uint32(body[0:4]), binary.LittleEndian.Uint32(body[4:8]))
	}
	keyType, keyLength := binary.LittleEndian.Uint16(body[8:10]), int(binary.LittleEndian.Uint16(body[10:12]))
	body = body[12:]
	if keyType != 0x0006 || keyLength < 20 || len(body) < keyLength {
		return nil, licensingRefused("the proprietary certificate: key blob type %#x of %d bytes", keyType, keyLength)
	}
	keyBlob, rest := body[:keyLength], body[keyLength:]
	// RSA_PUBLIC_KEY: "RSA1", keylen, bitlen, datalen, pubExp, then keylen bytes of modulus, little
	// endian, of which bitlen/8 are the modulus and 8 are zero padding.
	if string(keyBlob[0:4]) != "RSA1" {
		return nil, licensingRefused("the proprietary certificate: key magic %q", keyBlob[0:4])
	}
	modulusLength, bits := int(binary.LittleEndian.Uint32(keyBlob[4:8])), int(binary.LittleEndian.Uint32(keyBlob[8:12]))
	exponent := binary.LittleEndian.Uint32(keyBlob[16:20])
	if bits < 1024 || bits > 16384 || bits%8 != 0 || modulusLength != bits/8+8 || len(keyBlob) != 20+modulusLength {
		return nil, licensingRefused("the proprietary certificate: a key of %d bits in %d bytes", bits, modulusLength)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, licensingRefused("the proprietary certificate: exponent %d", exponent)
	}
	little := keyBlob[20 : 20+bits/8]
	modulus := make([]byte, len(little))
	for i := range little {
		modulus[len(little)-1-i] = little[i]
	}
	if len(rest) < 4 || binary.LittleEndian.Uint16(rest[0:2]) != 0x0008 || binary.LittleEndian.Uint16(rest[2:4]) != 72 || len(rest) != 4+72 {
		return nil, licensingRefused("the proprietary certificate: a signature blob of %d bytes", len(rest))
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent)}
	if key.N.BitLen() < 1024 {
		return nil, licensingRefused("the proprietary certificate: a modulus of %d bits", key.N.BitLen())
	}
	return key, nil
}

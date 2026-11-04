package rdp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"io"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	rdpSecLicensePacket = uint16(0x0080)

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

// CompleteLicensing executes the deliberately narrow personal-terminal-server
// flow: validate SERVER_LICENSE_REQUEST, send CLIENT_NEW_LICENSE_REQUEST, then
// accept only STATUS_VALID_CLIENT/ST_NO_TRANSITION. CAL issuance, upgrades and
// platform challenges are intentionally unsupported and fail closed.
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
			err = ErrMCSConnection
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
	licenseKey, parseErr := parseRDPServerLicenseRequest(serverPacket, s.mcsResponse.IOChannelID, fallbackKey)
	clear(serverPacket)
	if parseErr != nil {
		return ErrMCSConnection
	}

	request, buildErr := marshalRDPClientNewLicenseRequest(
		s.userChannelID, s.mcsResponse.IOChannelID, licenseKey,
		s.licensingUsername, s.mcsSettings.ClientName,
	)
	if buildErr != nil {
		return ErrMCSConnection
	}
	defer clear(request)
	if ctx.Err() != nil || writeFull(conn, request) != nil {
		return ErrMCSConnection
	}

	serverPacket, readErr = readMCSConnectResponse(conn)
	if readErr != nil {
		return ErrMCSConnection
	}
	defer clear(serverPacket)
	if !parseRDPServerLicenseSuccess(serverPacket, s.mcsResponse.IOChannelID) {
		return ErrMCSConnection
	}
	if ctx.Err() != nil {
		return ErrMCSConnection
	}
	return nil
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
	userData, err := parseMCSLicensingIndication(packet, expectedChannelID)
	if err != nil || len(userData) < 4+4+32+12+8+4 {
		return nil, ErrMCSConnection
	}
	preamble := userData[4:]
	if preamble[0] != rdpLicenseRequest || preamble[1]&0x0f != rdpLicenseProtocolVersion ||
		preamble[1]&0x70 != 0 || int(binary.LittleEndian.Uint16(preamble[2:4])) != len(preamble) {
		return nil, ErrMCSConnection
	}
	body := preamble[4:]
	if len(body) < 32+12 {
		return nil, ErrMCSConnection
	}
	body = body[32:] // ServerRandom; TLS already authenticates the server identity.
	if len(body) < 12 {
		return nil, ErrMCSConnection
	}
	body = body[4:] // ProductInfo.dwVersion
	companyLength := int(binary.LittleEndian.Uint32(body[:4]))
	body = body[4:]
	if companyLength > maxRDPLicenseStringSize || !validLicenseUTF16Blob(body, companyLength) {
		return nil, ErrMCSConnection
	}
	body = body[companyLength:]
	if len(body) < 4 {
		return nil, ErrMCSConnection
	}
	productLength := int(binary.LittleEndian.Uint32(body[:4]))
	body = body[4:]
	if productLength > maxRDPLicenseStringSize || !validLicenseUTF16Blob(body, productLength) {
		return nil, ErrMCSConnection
	}
	body = body[productLength:]

	blobType, blobValue, rest, ok := readLicenseBlob(body)
	if !ok || blobType != rdpLicenseBlobKeyExchange || len(blobValue) == 0 || len(blobValue)%4 != 0 {
		return nil, ErrMCSConnection
	}
	hasRSA := false
	for len(blobValue) > 0 {
		if binary.LittleEndian.Uint32(blobValue[:4]) == rdpLicenseKeyExchangeRSA {
			hasRSA = true
		}
		blobValue = blobValue[4:]
	}
	if !hasRSA {
		return nil, ErrMCSConnection
	}
	body = rest
	var certificateBlob []byte
	blobType, certificateBlob, body, ok = readLicenseBlob(body)
	if !ok || blobType != rdpLicenseBlobCertificate {
		return nil, ErrMCSConnection
	}
	licenseKey, certErr := parseRDPServerLicenseCertificate(certificateBlob, fallbackKey)
	if certErr != nil {
		return nil, ErrMCSConnection
	}
	if len(body) < 4 {
		return nil, ErrMCSConnection
	}
	scopeCount := binary.LittleEndian.Uint32(body[:4])
	body = body[4:]
	if scopeCount > maxRDPServerLicenseScopes {
		return nil, ErrMCSConnection
	}
	for i := uint32(0); i < scopeCount; i++ {
		blobType, _, body, ok = readLicenseBlob(body)
		if !ok || blobType != rdpLicenseBlobScope {
			return nil, ErrMCSConnection
		}
	}
	if len(body) != 0 {
		return nil, ErrMCSConnection
	}
	return licenseKey, nil
}

// parseRDPServerLicenseCertificate extracts the RSA key from the server's
// licensing certificate. The blob is delivered inside the already-authenticated
// TLS channel; the TLS peer identity therefore authenticates this key material.
// Empty blobs use the TLS certificate key, as permitted by MS-RDPELE.
func parseRDPServerLicenseCertificate(blob []byte, fallback *rsa.PublicKey) (*rsa.PublicKey, error) {
	if len(blob) == 0 {
		if fallback == nil || fallback.N == nil || fallback.N.BitLen() < 1024 {
			return nil, ErrMCSConnection
		}
		return fallback, nil
	}
	if len(blob) < 8 || binary.LittleEndian.Uint32(blob[:4]) != 0x80000002 {
		return nil, ErrMCSConnection
	}
	count := binary.LittleEndian.Uint32(blob[4:8])
	if count == 0 || count > 8 {
		return nil, ErrMCSConnection
	}
	body := blob[8:]
	var leaf *x509.Certificate
	for i := uint32(0); i < count; i++ {
		if len(body) < 4 {
			return nil, ErrMCSConnection
		}
		length := int(binary.LittleEndian.Uint32(body[:4]))
		body = body[4:]
		if length <= 0 || length > maxRDPLicenseBlobSize || len(body) < length {
			return nil, ErrMCSConnection
		}
		cert, err := x509.ParseCertificate(body[:length])
		if err != nil {
			return nil, ErrMCSConnection
		}
		if i == 0 {
			leaf = cert
		}
		body = body[length:]
	}
	if len(body) != 0 || leaf == nil {
		return nil, ErrMCSConnection
	}
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 1024 {
		return nil, ErrMCSConnection
	}
	return key, nil
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
		return nil, ErrMCSConnection
	}
	mcs := packet[7:]
	if len(mcs) < 7 || mcs[0] != mcsSendDataIndication ||
		binary.BigEndian.Uint16(mcs[1:3]) != rdpServerChannelID-mcsUserIDBase ||
		binary.BigEndian.Uint16(mcs[3:5]) != expectedChannelID || mcs[5] != 0x70 {
		return nil, ErrMCSConnection
	}
	length, rest, err := readPERLength(mcs[6:])
	if err != nil || length == 0 || length > maxTPKTPacket || len(rest) != length ||
		len(rest) < 4 || binary.LittleEndian.Uint16(rest[:2]) != rdpSecLicensePacket ||
		binary.LittleEndian.Uint16(rest[2:4]) != 0 {
		return nil, ErrMCSConnection
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

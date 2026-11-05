package rdp

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxMCSConnectData = 1024
	maxRDPDesktopArea = uint64(16_777_216)

	mcsConnectInitialTag  = byte(0x65) // [APPLICATION 101]
	mcsConnectResponseTag = byte(0x66) // [APPLICATION 102]

	gccClientCoreType     = uint16(0xc001)
	gccClientSecurityType = uint16(0xc002)
	gccServerCoreType     = uint16(0x0c01)
	gccServerSecurityType = uint16(0x0c02)
	gccServerNetworkType  = uint16(0x0c03)

	rdpClientVersion        = uint32(0x00080004)
	rdpClientBuild          = uint32(1)
	rdpColor8BPP            = uint16(0xca01)
	rdpColor24BPP           = uint16(0xca04)
	rdpHighColor24BPP       = uint16(0x0018)
	rdpSupported32BPP       = uint16(0x0008)
	rdpClientErrInfo        = uint16(0x0001)
	rdpClientWant32BPP      = uint16(0x0002)
	rdpSASDel               = uint16(0xaa03)
	rdpEncryption128Bit     = uint32(0x00000002)
	rdpKeyboardEnhanced     = uint32(4)
	rdpKeyboardFunctionKeys = uint32(12)
	mcsGlobalChannelID      = uint16(1003)
)

// ErrMCSConnection reports a malformed or unsupported MCS/GCC connection exchange.
var ErrMCSConnection = errors.New("rdp: malformed or unsupported MCS/GCC connection exchange")

// MCSClientSettings describes the deliberately small client settings profile
// advertised after CredSSP. FrenchLocale selects the French extEncryptionMethods form.
// No static or dynamic virtual channels are requested.
type MCSClientSettings struct {
	DesktopWidth  uint16
	DesktopHeight uint16
	ClientName    string
	FrenchLocale  bool
	Timeout       time.Duration
}

// MCSConnectResponse contains the only server settings accepted by this stage.
// Channel connection (Erect Domain, Attach User and Channel Join) follows via ConnectMCSChannels.
type MCSConnectResponse struct {
	ServerVersion uint32
	IOChannelID   uint16
}

// MarshalMCSConnectInitial builds the TPKT/X.224/MCS Connect-Initial PDU with
// a GCC Conference-Create-Request. It advertises 32 bpp, HYBRID, and no channels.
func MarshalMCSConnectInitial(settings MCSClientSettings) ([]byte, error) {
	if settings.Timeout < 0 || settings.DesktopWidth == 0 || settings.DesktopHeight == 0 ||
		uint64(settings.DesktopWidth)*uint64(settings.DesktopHeight) > maxRDPDesktopArea ||
		!validRDPClientName(settings.ClientName) {
		return nil, ErrMCSConnection
	}

	clientData, err := marshalClientDataBlocks(settings)
	if err != nil {
		return nil, err
	}
	gccData, err := marshalGCCConferenceCreateRequest(clientData)
	clear(clientData)
	if err != nil {
		return nil, err
	}
	if len(gccData) > maxMCSConnectData {
		clear(gccData)
		return nil, ErrMCSConnection
	}
	mcsData, err := marshalMCSConnectInitial(gccData)
	clear(gccData)
	if err != nil {
		return nil, err
	}
	packetLength := 4 + 3 + len(mcsData)
	if packetLength > maxTPKTPacket || packetLength > 0xffff {
		clear(mcsData)
		return nil, ErrMCSConnection
	}
	packet := make([]byte, packetLength)
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(packetLength))
	copy(packet[4:7], []byte{2, 0xf0, 0x80}) // X.224 Class 0 Data TPDU
	copy(packet[7:], mcsData)
	clear(mcsData)
	return packet, nil
}

// ParseMCSConnectResponse validates a complete server Connect-Response and the
// strict HYBRID/no-virtual-channel settings profile requested by this client.
func ParseMCSConnectResponse(packet []byte) (MCSConnectResponse, error) {
	var response MCSConnectResponse
	if len(packet) < 7+2 || len(packet) > maxTPKTPacket || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) {
		return response, ErrMCSConnection
	}
	mcs := packet[7:]
	outer, rest, err := readMCSBER(mcs, []byte{0x7f, mcsConnectResponseTag})
	if err != nil || len(rest) != 0 {
		return response, ErrMCSConnection
	}
	body := outer
	result, body, err := readMCSBER(body, []byte{0x0a}) // ENUMERATED
	if err != nil || len(result) != 1 || result[0] != 0 {
		return response, ErrMCSConnection
	}
	calledConnectID, body, err := readMCSBER(body, []byte{0x02})
	if err != nil || !validBERInteger(calledConnectID) {
		return response, ErrMCSConnection
	}
	domainParameters, body, err := readMCSBER(body, []byte{0x30})
	if err != nil || !validMCSBERDomainParameters(domainParameters) {
		return response, ErrMCSConnection
	}
	userData, body, err := readMCSBER(body, []byte{0x04})
	if err != nil || len(body) != 0 || len(userData) == 0 || len(userData) > maxMCSConnectData {
		return response, ErrMCSConnection
	}
	response, err = parseGCCConferenceCreateResponse(userData)
	if err != nil {
		return MCSConnectResponse{}, err
	}
	return response, nil
}

func validRDPClientName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	runes := []rune(name)
	units := utf16.Encode(runes)
	if len(units) == 0 || len(units) > 15 {
		return false
	}
	for _, r := range runes {
		if r == 0 || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func marshalClientDataBlocks(settings MCSClientSettings) ([]byte, error) {
	core := make([]byte, 212) // CS_CORE through serverSelectedProtocol; omit optional DPI fields.
	offset := 0
	put32 := func(v uint32) { binary.LittleEndian.PutUint32(core[offset:offset+4], v); offset += 4 }
	put16 := func(v uint16) { binary.LittleEndian.PutUint16(core[offset:offset+2], v); offset += 2 }
	put32(rdpClientVersion)
	put16(settings.DesktopWidth)
	put16(settings.DesktopHeight)
	put16(rdpColor8BPP) // Ignored when postBeta2ColorDepth is present.
	put16(rdpSASDel)
	put32(0) // Let the server select the account's default keyboard layout.
	put32(rdpClientBuild)
	name := utf16.Encode([]rune(settings.ClientName))
	for _, unit := range name {
		put16(unit)
	}
	put16(0) // clientName terminator
	offset += (16 - len(name) - 1) * 2
	put32(rdpKeyboardEnhanced)
	put32(0) // keyboardSubType
	put32(rdpKeyboardFunctionKeys)
	offset += 64 // imeFileName, unused
	put16(rdpColor24BPP)
	put16(1) // clientProductId
	put32(0) // serialNumber
	put16(rdpHighColor24BPP)
	put16(rdpSupported32BPP)
	put16(rdpClientErrInfo | rdpClientWant32BPP)
	productID := utf16.Encode([]rune("OpenBastion"))
	for _, unit := range productID {
		put16(unit)
	}
	offset += (32 - len(productID)) * 2 // clientDigProductId, fixed 64 bytes.
	core[offset] = 0                    // connectionType (not marked valid)
	offset++
	core[offset] = 0 // pad1octet
	offset++
	put32(protocolHybrid) // serverSelectedProtocol
	if offset != len(core) {
		clear(core)
		return nil, ErrMCSConnection
	}

	blocks := make([]byte, 0, 228)
	blocks = appendGCCBlock(blocks, gccClientCoreType, core)
	clear(core)
	// Advertise a valid Standard RDP Security capability for protocol compliance.
	// HYBRID remains mandatory, so this capability is never used as the security layer.
	security := make([]byte, 8)
	if settings.FrenchLocale {
		binary.LittleEndian.PutUint32(security[4:8], rdpEncryption128Bit) // extEncryptionMethods
	} else {
		binary.LittleEndian.PutUint32(security[0:4], rdpEncryption128Bit) // encryptionMethods
	}
	blocks = appendGCCBlock(blocks, gccClientSecurityType, security)
	clear(security)
	if len(blocks) > maxMCSConnectData {
		clear(blocks)
		return nil, ErrMCSConnection
	}
	return blocks, nil
}

func appendGCCBlock(dst []byte, blockType uint16, payload []byte) []byte {
	length := len(payload) + 4
	dst = append(dst, byte(blockType), byte(blockType>>8), byte(length), byte(length>>8))
	return append(dst, payload...)
}

func marshalGCCConferenceCreateRequest(clientData []byte) ([]byte, error) {
	if len(clientData) == 0 || len(clientData) > maxMCSConnectData {
		return nil, ErrMCSConnection
	}
	connectPDU := make([]byte, 0, 14+len(clientData))
	connectPDU = append(connectPDU, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 'D', 'u', 'c', 'a')
	connectPDU = appendPERLength(connectPDU, len(clientData))
	connectPDU = append(connectPDU, clientData...)
	if len(connectPDU) != 14+len(clientData) {
		clear(connectPDU)
		return nil, ErrMCSConnection
	}
	gcc := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}
	gcc = appendPERLength(gcc, len(connectPDU))
	gcc = append(gcc, connectPDU...)
	clear(connectPDU)
	return gcc, nil
}

func marshalMCSConnectInitial(gccData []byte) ([]byte, error) {
	if len(gccData) == 0 || len(gccData) > maxMCSConnectData {
		return nil, ErrMCSConnection
	}
	var body []byte
	body = appendBER(body, 0x04, []byte{1})    // callingDomainSelector
	body = appendBER(body, 0x04, []byte{1})    // calledDomainSelector
	body = appendBER(body, 0x01, []byte{0xff}) // upwardFlag TRUE
	body = appendBER(body, 0x30, marshalMCSDomainParameters([]uint32{34, 2, 0, 1, 0, 1, 65535, 2}))
	body = appendBER(body, 0x30, marshalMCSDomainParameters([]uint32{1, 1, 1, 1, 0, 1, 1056, 2}))
	body = appendBER(body, 0x30, marshalMCSDomainParameters([]uint32{65535, 65535, 65535, 1, 0, 1, 65535, 2}))
	body = appendBER(body, 0x04, gccData)
	return appendBERHighTag(nil, []byte{0x7f, mcsConnectInitialTag}, body), nil
}

func marshalMCSDomainParameters(values []uint32) []byte {
	var encoded []byte
	for _, value := range values {
		encoded = appendBERInteger(encoded, value)
	}
	return encoded
}

func appendBER(dst []byte, tag byte, value []byte) []byte {
	dst = append(dst, tag)
	dst = appendBERLength(dst, len(value))
	return append(dst, value...)
}

func appendBERHighTag(dst, tag, value []byte) []byte {
	dst = append(dst, tag...)
	dst = appendBERLength(dst, len(value))
	return append(dst, value...)
}

func appendBERLength(dst []byte, length int) []byte {
	switch {
	case length < 0x80:
		return append(dst, byte(length))
	case length <= 0xff:
		return append(dst, 0x81, byte(length))
	case length <= 0xffff:
		return append(dst, 0x82, byte(length>>8), byte(length))
	default:
		return append(dst, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
}

func appendBERInteger(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	start := 0
	for start < 3 && encoded[start] == 0 && encoded[start+1]&0x80 == 0 {
		start++
	}
	if encoded[start]&0x80 != 0 {
		return appendBER(dst, 0x02, append([]byte{0}, encoded[start:]...))
	}
	return appendBER(dst, 0x02, encoded[start:])
}

func readMCSBER(data, expectedTag []byte) ([]byte, []byte, error) {
	if len(expectedTag) == 0 || len(data) < len(expectedTag)+1 || !equalBytes(data[:len(expectedTag)], expectedTag) {
		return nil, nil, ErrMCSConnection
	}
	header := len(expectedTag)
	first := data[header]
	header++
	length := int(first)
	if first == 0x80 {
		return nil, nil, ErrMCSConnection
	}
	if first&0x80 != 0 {
		count := int(first & 0x7f)
		if count == 0 || count > 3 || len(data) < header+count || data[header] == 0 {
			return nil, nil, ErrMCSConnection
		}
		length = 0
		for _, b := range data[header : header+count] {
			length = length<<8 | int(b)
		}
		if length < 128 || count > 1 && length < 256 || count > 2 && length < 65536 {
			return nil, nil, ErrMCSConnection
		}
		header += count
	}
	if length > maxTPKTPacket || header+length > len(data) {
		return nil, nil, ErrMCSConnection
	}
	return data[header : header+length], data[header+length:], nil
}

func validBERInteger(value []byte) bool {
	if len(value) == 0 || len(value) > 5 {
		return false
	}
	if len(value) > 1 && value[0] == 0 && value[1]&0x80 == 0 {
		return false
	}
	if len(value) > 1 && value[0] == 0xff && value[1]&0x80 != 0 {
		return false
	}
	return true
}

func validMCSBERDomainParameters(value []byte) bool {
	// MS-RDPBCGR specifies that the client ignores the DomainParameters values.
	// Validate the eight BER INTEGER encodings and sequence boundary only.
	for i := 0; i < 8; i++ {
		integer, rest, err := readMCSBER(value, []byte{0x02})
		if err != nil || !validBERInteger(integer) {
			return false
		}
		value = rest
	}
	return len(value) == 0
}

func appendPERLength(dst []byte, length int) []byte {
	if length < 0x80 {
		return append(dst, byte(length))
	}
	if length <= 0x3fff {
		return append(dst, byte(0x80|(length>>8)), byte(length))
	}
	return dst
}

func readPERLength(data []byte) (int, []byte, error) {
	if len(data) == 0 {
		return 0, nil, ErrMCSConnection
	}
	first := data[0]
	if first&0x80 == 0 {
		return int(first), data[1:], nil
	}
	if first&0xc0 != 0x80 || len(data) < 2 {
		return 0, nil, ErrMCSConnection
	}
	length := int(first&0x3f)<<8 | int(data[1])
	if length < 0x80 {
		return 0, nil, ErrMCSConnection
	}
	return length, data[2:], nil
}

func parseGCCConferenceCreateResponse(data []byte) (MCSConnectResponse, error) {
	var response MCSConnectResponse
	if len(data) < 16 || len(data) > maxMCSConnectData || !equalBytes(data[:7], []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}) {
		return response, ErrMCSConnection
	}
	_, rest, err := readPERLength(data[7:])
	if err != nil || len(rest) < 1 || rest[0] != 0x14 {
		return response, ErrMCSConnection
	}
	rest = rest[1:]
	if len(rest) < 11 {
		return response, ErrMCSConnection
	}
	// The nodeID, tag, result and number-of-sets fields are ignored by the
	// RDP client. Only the conference choice and mandatory H.221 key matter.
	rest = rest[2:]
	if rest[3] != 0xc0 || rest[4] != 0 || !equalBytes(rest[5:9], []byte("McDn")) {
		return response, ErrMCSConnection
	}
	rest = rest[9:]
	userDataLength, rest, err := readPERLength(rest)
	if err != nil || userDataLength == 0 || userDataLength > maxMCSConnectData || len(rest) != userDataLength {
		return response, ErrMCSConnection
	}
	response, err = parseServerDataBlocks(rest)
	if err != nil {
		return MCSConnectResponse{}, err
	}
	return response, nil
}

func parseServerDataBlocks(data []byte) (MCSConnectResponse, error) {
	var response MCSConnectResponse
	seen := map[uint16]bool{}
	for len(data) > 0 {
		if len(data) < 4 {
			return response, ErrMCSConnection
		}
		blockType := binary.LittleEndian.Uint16(data[:2])
		blockLength := int(binary.LittleEndian.Uint16(data[2:4]))
		if blockLength < 4 || blockLength > len(data) || seen[blockType] {
			return response, ErrMCSConnection
		}
		seen[blockType] = true
		payload := data[4:blockLength]
		switch blockType {
		case gccServerCoreType:
			if len(payload) != 8 && len(payload) != 12 {
				return response, ErrMCSConnection
			}
			response.ServerVersion = binary.LittleEndian.Uint32(payload[:4])
			if !validRDPServerVersion(response.ServerVersion) || binary.LittleEndian.Uint32(payload[4:8]) != protocolHybrid {
				return MCSConnectResponse{}, ErrMCSConnection
			}
		case gccServerSecurityType:
			if len(payload) != 8 || binary.LittleEndian.Uint32(payload[:4]) != 0 || binary.LittleEndian.Uint32(payload[4:8]) != 0 {
				return MCSConnectResponse{}, ErrMCSConnection
			}
		case gccServerNetworkType:
			if len(payload) != 4 || binary.LittleEndian.Uint16(payload[:2]) != mcsGlobalChannelID || binary.LittleEndian.Uint16(payload[2:4]) != 0 {
				return MCSConnectResponse{}, ErrMCSConnection
			}
			response.IOChannelID = mcsGlobalChannelID
		default:
			return MCSConnectResponse{}, ErrMCSConnection
		}
		data = data[blockLength:]
	}
	if !seen[gccServerCoreType] || !seen[gccServerSecurityType] || !seen[gccServerNetworkType] || response.IOChannelID == 0 {
		return MCSConnectResponse{}, ErrMCSConnection
	}
	return response, nil
}

func validRDPServerVersion(version uint32) bool {
	return version >= 0x00080004 && version <= 0x00080011
}

func equalBytes(a, b []byte) bool {
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

func readMCSConnectResponse(r io.Reader) ([]byte, error) {
	return readTPKTPacket(r, maxTPKTPacket)
}

// readRDPServerUpdatePacket reads one bounded TPKT slow-path packet or one
// Fast-Path Output PDU. The bool result identifies the fast-path form.
func readRDPServerUpdatePacket(r io.Reader, maxPacket int) ([]byte, bool, error) {
	if maxPacket < 9 || maxPacket > maxRDPFastPathPacket {
		return nil, false, ErrMCSConnection
	}
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, false, ErrMCSConnection
	}
	if first[0] == 3 {
		var rest [3]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return nil, false, ErrMCSConnection
		}
		length := int(binary.BigEndian.Uint16(rest[1:3]))
		if rest[0] != 0 || length < 9 || length > maxPacket {
			return nil, false, ErrMCSConnection
		}
		packet := make([]byte, length)
		packet[0] = first[0]
		copy(packet[1:4], rest[:])
		if _, err := io.ReadFull(r, packet[4:]); err != nil {
			clear(packet)
			return nil, false, ErrMCSConnection
		}
		return packet, false, nil
	}
	// TLS is the security layer. Reject legacy RDP encryption and non-fast-path
	// action values rather than attempting to interpret their payload.
	if first[0] != 0 {
		return nil, false, ErrMCSConnection
	}
	var lengthFirst [1]byte
	if _, err := io.ReadFull(r, lengthFirst[:]); err != nil {
		return nil, false, ErrMCSConnection
	}
	length := int(lengthFirst[0])
	headerLength := 2
	var lengthSecond [1]byte
	if lengthFirst[0]&0x80 != 0 {
		if _, err := io.ReadFull(r, lengthSecond[:]); err != nil {
			return nil, false, ErrMCSConnection
		}
		length = int(lengthFirst[0]&0x7f)<<8 | int(lengthSecond[0])
		headerLength++
		if length < 128 {
			return nil, false, ErrMCSConnection
		}
	}
	if length < headerLength+4 || length > maxPacket {
		return nil, false, ErrMCSConnection
	}
	packet := make([]byte, length)
	packet[0], packet[1] = first[0], lengthFirst[0]
	if headerLength == 3 {
		packet[2] = lengthSecond[0]
	}
	if _, err := io.ReadFull(r, packet[headerLength:]); err != nil {
		clear(packet)
		return nil, false, ErrMCSConnection
	}
	return packet, true, nil
}

// readTPKTPacket reads one complete TPKT with a caller-selected, protocol-
// specific bound. Handshake and control exchanges keep their small legacy cap;
// the graphics receive path uses the larger RDP MCS bound.
func readTPKTPacket(r io.Reader, maxPacket int) ([]byte, error) {
	var header [4]byte
	if maxPacket < 9 || maxPacket > 0xffff {
		return nil, ErrMCSConnection
	}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, ErrMCSConnection
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || length < 9 || length > maxPacket {
		return nil, ErrMCSConnection
	}
	packet := make([]byte, length)
	copy(packet, header[:])
	if _, err := io.ReadFull(r, packet[4:]); err != nil {
		clear(packet)
		return nil, ErrMCSConnection
	}
	return packet, nil
}

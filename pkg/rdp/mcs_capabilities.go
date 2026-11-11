package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	rdpServerChannelID = uint16(1002)
	// TS_GENERAL_CAPABILITYSET extraFlags.
	rdpFastPathOutputSupported = uint16(0x0001)
	mcsSendDataRequest         = byte(0x64)
	mcsSendDataIndication      = byte(0x68)

	rdpDemandActivePDU  = uint16(0x11)
	rdpConfirmActivePDU = uint16(0x13)

	rdpCapGeneral = uint16(1)
	rdpCapBitmap  = uint16(2)
	rdpCapOrder   = uint16(3)
	rdpCapPointer = uint16(8)
	rdpCapInput   = uint16(13)

	maxRDPCapabilitySets = 32
	maxRDPCapabilitySize = 2048
)

// RDPServerCapabilities is the validated, bounded subset of the server's
// Demand Active PDU needed by the following client phases.
type RDPServerCapabilities struct {
	ShareID               uint32
	DesktopWidth          uint16
	DesktopHeight         uint16
	PreferredBitsPerPixel uint16
	CapabilityTypes       []uint16
}

// ExchangeCapabilities consumes one Demand Active PDU and sends one
// Confirm Active PDU. It is available only after Client Info and a completed
// Licensing exchange. Until that handler exists, licensingComplete remains
// false and this transition refuses to consume any server PDU.
func (s *CredSSPClientSession) ExchangeCapabilities(ctx context.Context, timeout time.Duration) (capabilities RDPServerCapabilities, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return capabilities, ErrMCSConnection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.credentialsDelegated ||
		!s.mcsConnected || !s.channelsConnected || !s.clientInfoSent || !s.licensingComplete || s.capabilitiesExchanged ||
		!validMCSUserID(s.userChannelID) || !s.transport.Conn.ConnectionState().HandshakeComplete {
		return capabilities, ErrMCSConnection
	}
	if timeout == 0 {
		timeout = defaultCredSSPTimeout
	}
	conn := s.transport.Conn
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		s.closeTransportLocked()
		return capabilities, ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.closeTransportLocked()
			if !errors.Is(err, ErrMCSConnection) {
				err = ErrMCSConnection // a described refusal keeps its description
			}
			capabilities = RDPServerCapabilities{}
			return
		}
		if setErr := conn.SetDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.closeTransportLocked()
			err = ErrMCSConnection
			capabilities = RDPServerCapabilities{}
			return
		}
		s.capabilitiesExchanged = true
		s.serverCapabilities = cloneRDPServerCapabilities(capabilities)
	}()

	packet, readErr := readMCSConnectResponse(conn)
	if readErr != nil {
		return capabilities, ErrMCSConnection
	}
	capabilities, err = parseRDPDemandActive(packet, s.mcsResponse.IOChannelID)
	if err != nil {
		described := fmt.Errorf("%w: Demand Active refused: %s", ErrMCSConnection, describeRDPServerPacket(packet))
		clear(packet)
		return RDPServerCapabilities{}, described
	}
	clear(packet)
	if ctx.Err() != nil {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	confirm, buildErr := marshalRDPConfirmActive(capabilities, s.mcsSettings, s.userChannelID)
	if buildErr != nil {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	defer clear(confirm)
	if len(confirm) == 0 || writeFull(conn, confirm) != nil {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	if ctx.Err() != nil {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	return capabilities, nil
}

func cloneRDPServerCapabilities(in RDPServerCapabilities) RDPServerCapabilities {
	in.CapabilityTypes = append([]uint16(nil), in.CapabilityTypes...)
	return in
}

func parseRDPDemandActive(packet []byte, expectedChannelID uint16) (RDPServerCapabilities, error) {
	var result RDPServerCapabilities
	if len(packet) < 7+8 || len(packet) > maxTPKTPacket || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || !equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) ||
		expectedChannelID != mcsGlobalChannelID {
		return result, ErrMCSConnection
	}
	mcs := packet[7:]
	if len(mcs) < 7 || mcs[0] != mcsSendDataIndication ||
		binary.BigEndian.Uint16(mcs[3:5]) != expectedChannelID || mcs[5] != 0x70 {
		return result, ErrMCSConnection
	}
	userDataLength, userData, err := readPERLength(mcs[6:])
	if err != nil || userDataLength == 0 || userDataLength > maxTPKTPacket || len(userData) != userDataLength {
		return result, ErrMCSConnection
	}
	return parseRDPDemandActiveData(userData)
}

func parseRDPDemandActiveData(data []byte) (RDPServerCapabilities, error) {
	var result RDPServerCapabilities
	if len(data) < 6+4+2+2+4 || len(data) > maxTPKTPacket ||
		int(binary.LittleEndian.Uint16(data[0:2])) != len(data) ||
		binary.LittleEndian.Uint16(data[2:4]) != rdpDemandActivePDU {
		return result, ErrMCSConnection
	}
	// pduSource is whichever channel the server speaks from (FreeRDP: its own, 1004): not checked.
	result.ShareID = binary.LittleEndian.Uint32(data[6:10])
	sourceLength := int(binary.LittleEndian.Uint16(data[10:12]))
	combinedLength := int(binary.LittleEndian.Uint16(data[12:14]))
	if result.ShareID == 0 || sourceLength == 0 || sourceLength > 64 || combinedLength < 4 ||
		14+sourceLength+combinedLength+4 != len(data) {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	// The descriptor is informative, and usually NUL-terminated ("RDP\0").
	source := bytes.TrimSuffix(data[14:14+sourceLength], []byte{0})
	for _, b := range source {
		if b < 0x20 || b > 0x7e {
			return RDPServerCapabilities{}, ErrMCSConnection
		}
	}
	combined := data[14+sourceLength : 14+sourceLength+combinedLength]
	count := int(binary.LittleEndian.Uint16(combined[:2]))
	if count == 0 || count > maxRDPCapabilitySets {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	// pad2Octets is explicitly ignored by MS-RDPBCGR.
	capData := combined[4:]
	seen := make(map[uint16]struct{}, count)
	result.CapabilityTypes = make([]uint16, 0, count)
	for i := 0; i < count; i++ {
		if len(capData) < 4 {
			return RDPServerCapabilities{}, ErrMCSConnection
		}
		typ := binary.LittleEndian.Uint16(capData[:2])
		length := int(binary.LittleEndian.Uint16(capData[2:4]))
		if length < 4 || length > maxRDPCapabilitySize || length > len(capData) {
			return RDPServerCapabilities{}, ErrMCSConnection
		}
		if _, duplicate := seen[typ]; duplicate {
			return RDPServerCapabilities{}, ErrMCSConnection
		}
		seen[typ] = struct{}{}
		capability := capData[:length]
		if err := validateRDPServerCapability(typ, capability, &result); err != nil {
			return RDPServerCapabilities{}, err
		}
		result.CapabilityTypes = append(result.CapabilityTypes, typ)
		capData = capData[length:]
	}
	if len(capData) != 0 {
		return RDPServerCapabilities{}, ErrMCSConnection
	}
	for _, required := range []uint16{rdpCapGeneral, rdpCapBitmap, rdpCapOrder, rdpCapPointer, rdpCapInput} {
		if _, ok := seen[required]; !ok {
			return RDPServerCapabilities{}, ErrMCSConnection
		}
	}
	return result, nil
}

func validateRDPServerCapability(typ uint16, capability []byte, result *RDPServerCapabilities) error {
	data := capability[4:]
	switch typ {
	case rdpCapGeneral:
		if len(capability) != 24 || binary.LittleEndian.Uint16(data[4:6]) != 0x0200 ||
			binary.LittleEndian.Uint16(data[8:10]) != 0 || binary.LittleEndian.Uint16(data[12:14]) != 0 ||
			binary.LittleEndian.Uint16(data[14:16]) != 0 || binary.LittleEndian.Uint16(data[16:18]) != 0 ||
			!validRDPBoolean(data[18]) || !validRDPBoolean(data[19]) {
			return ErrMCSConnection
		}
	case rdpCapBitmap:
		if len(capability) != 28 {
			return ErrMCSConnection
		}
		bpp := binary.LittleEndian.Uint16(data[:2])
		width := binary.LittleEndian.Uint16(data[8:10])
		height := binary.LittleEndian.Uint16(data[10:12])
		// 32 bpp, or 15/16 bpp, which Windows offers a client without the graphics pipeline when
		// its maximum color depth is left as installed (ADR-0086). 8 and 24 bpp are not decoded.
		if (bpp != 32 && bpp != 16 && bpp != 15) || width == 0 || height == 0 || uint64(width)*uint64(height) > maxRDPDesktopArea ||
			binary.LittleEndian.Uint16(data[14:16]) > 1 || binary.LittleEndian.Uint16(data[16:18]) != 1 ||
			data[19]&^byte(0x1e) != 0 || binary.LittleEndian.Uint16(data[20:22]) != 1 {
			return ErrMCSConnection
		}
		result.PreferredBitsPerPixel, result.DesktopWidth, result.DesktopHeight = bpp, width, height
	case rdpCapOrder:
		if len(capability) != 88 {
			return ErrMCSConnection
		}
		for _, supported := range data[32:64] {
			if !validRDPBoolean(supported) {
				return ErrMCSConnection
			}
		}
	case rdpCapPointer:
		if len(capability) != 10 {
			return ErrMCSConnection
		}
	case rdpCapInput:
		inputFlags := binary.LittleEndian.Uint16(data[:2])
		if len(capability) != 88 || inputFlags&0x0001 == 0 || inputFlags&^uint16(0x03fd) != 0 {
			return ErrMCSConnection
		}
	}
	return nil
}

func validRDPBoolean(value byte) bool { return value == 0 || value == 1 }

func marshalRDPConfirmActive(capabilities RDPServerCapabilities, settings MCSClientSettings, userID uint16) ([]byte, error) {
	if capabilities.ShareID == 0 || !validMCSUserID(userID) || settings.DesktopWidth == 0 || settings.DesktopHeight == 0 ||
		uint64(settings.DesktopWidth)*uint64(settings.DesktopHeight) > maxRDPDesktopArea {
		return nil, ErrMCSConnection
	}
	sessionBPP := capabilities.PreferredBitsPerPixel
	if sessionBPP == 0 {
		sessionBPP = 32
	}
	if sessionBPP != 32 && sessionBPP != 16 && sessionBPP != 15 {
		return nil, ErrMCSConnection
	}
	caps := marshalRDPClientCapabilitySets(settings, sessionBPP)
	combinedLength := 4 + len(caps)
	if combinedLength > 0xffff || len(caps) == 0 {
		clear(caps)
		return nil, ErrMCSConnection
	}
	source := []byte("OpenBastion")
	// TS_CONFIRM_ACTIVE_PDU (MS-RDPBCGR 2.2.1.13.2.1): the source of the PDU is this client, its
	// originator the server's channel, whichever channel the server spoke from.
	share := make([]byte, 6+4+2+2+2+len(source)+combinedLength)
	binary.LittleEndian.PutUint16(share[0:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpConfirmActivePDU)
	binary.LittleEndian.PutUint16(share[4:6], userID)
	binary.LittleEndian.PutUint32(share[6:10], capabilities.ShareID)
	binary.LittleEndian.PutUint16(share[10:12], rdpServerChannelID)
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(source)))
	binary.LittleEndian.PutUint16(share[14:16], uint16(combinedLength))
	copy(share[16:], source)
	offset := 16 + len(source)
	binary.LittleEndian.PutUint16(share[offset:offset+2], rdpClientCapabilitySetCount)
	copy(share[offset+4:], caps)
	clear(caps)
	packet, err := marshalMCSSendDataRequest(userID, mcsGlobalChannelID, share)
	clear(share)
	return packet, err
}

func marshalRDPClientCapabilitySets(settings MCSClientSettings, sessionBPP uint16) []byte {
	caps := make([]byte, 0, 242)
	general := make([]byte, 24)
	binary.LittleEndian.PutUint16(general[0:2], rdpCapGeneral)
	binary.LittleEndian.PutUint16(general[2:4], uint16(len(general)))
	binary.LittleEndian.PutUint16(general[8:10], 0x0200)
	// Servers may send graphics by Fast-Path only (FreeRDP's shadow does): this client reads it.
	binary.LittleEndian.PutUint16(general[14:16], rdpFastPathOutputSupported|rdpBitmapNoCompHdr)
	caps = append(caps, general...)
	clear(general)

	bitmap := make([]byte, 28)
	binary.LittleEndian.PutUint16(bitmap[0:2], rdpCapBitmap)
	binary.LittleEndian.PutUint16(bitmap[2:4], uint16(len(bitmap)))
	binary.LittleEndian.PutUint16(bitmap[4:6], sessionBPP) // the depth the server chose
	binary.LittleEndian.PutUint16(bitmap[6:8], 1)          // receive 1 bpp (required legacy field)
	binary.LittleEndian.PutUint16(bitmap[8:10], 1)         // receive 4 bpp (required legacy field)
	binary.LittleEndian.PutUint16(bitmap[10:12], 1)        // receive 8 bpp (required legacy field)
	binary.LittleEndian.PutUint16(bitmap[12:14], settings.DesktopWidth)
	binary.LittleEndian.PutUint16(bitmap[14:16], settings.DesktopHeight)
	// bitmapCompressionFlag "MUST be set to TRUE" (MS-RDPBCGR 2.2.7.1.2); Windows Server 2022 answers
	// FALSE with ERRINFO_BADCAPABILITIES (ADR-0071, CI run #31). Compressed bitmaps are decoded:
	// RDP 6.0 planar at 32 bpp, Interleaved RLE at 15 and 16 bpp (ADR-0086).
	binary.LittleEndian.PutUint16(bitmap[20:22], 1)
	binary.LittleEndian.PutUint16(bitmap[24:26], 1) // multiple rectangles are mandatory
	caps = append(caps, bitmap...)
	clear(bitmap)

	// Advertise only the mandatory baseline: no primary orders, a pointer cache only when the
	// pointer is drawn (PointerShapes), and scancodes only (no fast-path, Unicode or extended mouse input).
	order := make([]byte, 88)
	binary.LittleEndian.PutUint16(order[:2], rdpCapOrder)
	binary.LittleEndian.PutUint16(order[2:4], uint16(len(order)))
	binary.LittleEndian.PutUint16(order[30:32], 1)      // ORD_LEVEL_1_ORDERS
	binary.LittleEndian.PutUint16(order[34:36], 0x000a) // NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT
	caps = append(caps, order...)
	clear(order)

	pointer := make([]byte, 10)
	binary.LittleEndian.PutUint16(pointer[:2], rdpCapPointer)
	binary.LittleEndian.PutUint16(pointer[2:4], uint16(len(pointer)))
	binary.LittleEndian.PutUint16(pointer[4:6], 1) // Color Pointer Update is mandatory.
	if settings.PointerShapes {
		// colorPointerCacheSize and pointerCacheSize: the shapes RDPPointer keeps (ADR-0091).
		binary.LittleEndian.PutUint16(pointer[6:8], rdpPointerCacheSize)
		binary.LittleEndian.PutUint16(pointer[8:10], rdpPointerCacheSize)
	}
	caps = append(caps, pointer...)
	clear(pointer)

	input := make([]byte, 88)
	binary.LittleEndian.PutUint16(input[:2], rdpCapInput)
	binary.LittleEndian.PutUint16(input[2:4], uint16(len(input)))
	binary.LittleEndian.PutUint16(input[4:6], 1) // INPUT_FLAG_SCANCODES is mandatory.
	binary.LittleEndian.PutUint32(input[12:16], rdpKeyboardEnhanced)
	binary.LittleEndian.PutUint32(input[20:24], rdpKeyboardFunctionKeys)
	caps = append(caps, input...)
	clear(input)

	// TS_MULTIFRAGMENTUPDATE_CAPABILITYSET: the size this client reassembles a fragmented
	// Fast-Path update to, and the bound it holds the server to (fastpath_fragments.go).
	multifragment := make([]byte, 8)
	binary.LittleEndian.PutUint16(multifragment[:2], rdpCapMultifragmentUpdate)
	binary.LittleEndian.PutUint16(multifragment[2:4], uint16(len(multifragment)))
	binary.LittleEndian.PutUint32(multifragment[4:8], maxRDPFastPathReassembly)
	caps = append(caps, multifragment...)
	return caps
}

// rdpClientCapabilitySetCount is the number of sets marshalRDPClientCapabilitySets writes.
const rdpClientCapabilitySetCount = 6

func marshalMCSSendDataRequest(userID, channelID uint16, userData []byte) ([]byte, error) {
	if !validMCSUserID(userID) || channelID != mcsGlobalChannelID ||
		len(userData) == 0 || len(userData) > maxTPKTPacket-16 {
		return nil, ErrMCSConnection
	}
	mcs := []byte{mcsSendDataRequest, 0, 0, 0, 0, 0x70}
	binary.BigEndian.PutUint16(mcs[1:3], userID-mcsUserIDBase)
	binary.BigEndian.PutUint16(mcs[3:5], channelID)
	mcs = appendPERLength(mcs, len(userData))
	mcs = append(mcs, userData...)
	length := 7 + len(mcs)
	if length > maxTPKTPacket || length > 0xffff {
		clear(mcs)
		return nil, ErrMCSConnection
	}
	packet := make([]byte, length)
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	clear(mcs)
	return packet, nil
}

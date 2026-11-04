package rdp

import (
	"context"
	"encoding/binary"
	"time"
)

const (
	rdpShareDataPDU      = uint16(0x0017)
	rdpPDU2Synchronize   = byte(31)
	rdpPDU2Control       = byte(20)
	rdpPDU2FontList      = byte(39)
	rdpPDU2FontMap       = byte(40)
	rdpSyncMessage       = uint16(1)
	rdpControlRequest    = uint16(1)
	rdpControlGranted    = uint16(2)
	rdpControlCooperate  = uint16(4)
	rdpFontListFirstLast = uint16(0x0003)
	rdpFontMapFirstLast  = uint16(0x0003)
	rdpFontListEntrySize = uint16(50)
	rdpFontMapEntrySize  = uint16(4)
)

// RDPFinalizationResult records the strictly validated server responses that
// complete the RDP connection-finalization phase.
type RDPFinalizationResult struct {
	ServerSynchronized bool
	ServerCooperated   bool
	ControlGranted     bool
	FontMapEntries     uint16
}

// FinalizeConnection sends the client Synchronize, Cooperate, Request Control
// and empty Font List PDUs in protocol order, then validates the corresponding
// server Synchronize, Cooperate, Granted Control and Font Map responses.
// It is deliberately unavailable until a real Licensing and Capabilities
// exchange have completed. Any uncertain stream state is terminal.
func (s *CredSSPClientSession) FinalizeConnection(ctx context.Context, timeout time.Duration) (result RDPFinalizationResult, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return result, ErrMCSConnection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.credentialsDelegated ||
		!s.mcsConnected || !s.channelsConnected || !s.clientInfoSent || !s.licensingComplete ||
		!s.capabilitiesExchanged || s.connectionFinalized || !validMCSUserID(s.userChannelID) ||
		!s.transport.Conn.ConnectionState().HandshakeComplete || s.serverCapabilities.ShareID == 0 {
		return result, ErrMCSConnection
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
		return result, ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.closeTransportLocked()
			err = ErrMCSConnection
			result = RDPFinalizationResult{}
			return
		}
		if setErr := conn.SetDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.closeTransportLocked()
			err = ErrMCSConnection
			result = RDPFinalizationResult{}
			return
		}
		s.connectionFinalized = true
	}()

	for _, payload := range [][]byte{
		marshalRDPClientSynchronize(s.serverCapabilities.ShareID, s.userChannelID),
		marshalRDPClientControl(s.serverCapabilities.ShareID, s.userChannelID, rdpControlCooperate),
		marshalRDPClientControl(s.serverCapabilities.ShareID, s.userChannelID, rdpControlRequest),
		marshalRDPClientFontList(s.serverCapabilities.ShareID, s.userChannelID),
	} {
		if len(payload) == 0 || ctx.Err() != nil {
			clear(payload)
			return RDPFinalizationResult{}, ErrMCSConnection
		}
		writeErr := writeFull(conn, payload)
		clear(payload)
		if writeErr != nil {
			return RDPFinalizationResult{}, ErrMCSConnection
		}
	}

	for _, expected := range []struct {
		typ    byte
		stream byte
		action uint16
	}{
		{typ: rdpPDU2Synchronize, stream: 0}, // STREAM_UNDEFINED is seen in some server implementations.
		{typ: rdpPDU2Control, stream: 2, action: rdpControlCooperate},
		{typ: rdpPDU2Control, stream: 2, action: rdpControlGranted},
		{typ: rdpPDU2FontMap, stream: 2},
	} {
		packet, readErr := readMCSConnectResponse(conn)
		if readErr != nil {
			return RDPFinalizationResult{}, ErrMCSConnection
		}
		entries, parseErr := parseRDPFinalizationResponse(packet, s.mcsResponse.IOChannelID,
			s.serverCapabilities.ShareID, s.userChannelID, expected.typ, expected.stream, expected.action)
		clear(packet)
		if parseErr != nil || ctx.Err() != nil {
			return RDPFinalizationResult{}, ErrMCSConnection
		}
		switch expected.typ {
		case rdpPDU2Synchronize:
			result.ServerSynchronized = true
		case rdpPDU2Control:
			if !result.ServerCooperated {
				result.ServerCooperated = true
			} else {
				result.ControlGranted = true
			}
		case rdpPDU2FontMap:
			result.FontMapEntries = entries
		}
	}
	if !result.ServerSynchronized || !result.ServerCooperated || !result.ControlGranted {
		return RDPFinalizationResult{}, ErrMCSConnection
	}
	return result, nil
}

func marshalRDPShareData(userID uint16, shareID uint32, streamID, pduType2 byte, payload []byte) ([]byte, error) {
	if !validMCSUserID(userID) || shareID == 0 || (streamID != 1 && streamID != 2) || len(payload) == 0 || len(payload) > 0xffff-18 {
		return nil, ErrMCSConnection
	}
	share := make([]byte, 18+len(payload))
	binary.LittleEndian.PutUint16(share[0:2], uint16(len(share)))
	binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint16(share[4:6], userID)
	binary.LittleEndian.PutUint32(share[6:10], shareID)
	share[10] = 0
	share[11] = streamID
	binary.LittleEndian.PutUint16(share[12:14], uint16(len(share)))
	share[14] = pduType2
	copy(share[18:], payload)
	packet, err := marshalMCSSendDataRequest(userID, mcsGlobalChannelID, share)
	clear(share)
	return packet, err
}

func marshalRDPClientSynchronize(shareID uint32, userID uint16) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[0:2], rdpSyncMessage)
	binary.LittleEndian.PutUint16(payload[2:4], rdpServerChannelID)
	packet, _ := marshalRDPShareData(userID, shareID, 1, rdpPDU2Synchronize, payload)
	clear(payload)
	return packet
}

func marshalRDPClientControl(shareID uint32, userID, action uint16) []byte {
	if action != rdpControlCooperate && action != rdpControlRequest {
		return nil
	}
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], action)
	packet, _ := marshalRDPShareData(userID, shareID, 1, rdpPDU2Control, payload)
	clear(payload)
	return packet
}

func marshalRDPClientFontList(shareID uint32, userID uint16) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[4:6], rdpFontListFirstLast)
	binary.LittleEndian.PutUint16(payload[6:8], rdpFontListEntrySize)
	packet, _ := marshalRDPShareData(userID, shareID, 1, rdpPDU2FontList, payload)
	clear(payload)
	return packet
}

func parseRDPFinalizationResponse(packet []byte, expectedChannelID uint16, shareID uint32, userID uint16, pduType2, streamID byte, expectedAction uint16) (uint16, error) {
	if len(packet) < 7+7+18 || len(packet) > maxTPKTPacket || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || !equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) ||
		expectedChannelID != mcsGlobalChannelID {
		return 0, ErrMCSConnection
	}
	mcs := packet[7:]
	if mcs[0] != mcsSendDataIndication || binary.BigEndian.Uint16(mcs[1:3]) != rdpServerChannelID-mcsUserIDBase ||
		binary.BigEndian.Uint16(mcs[3:5]) != expectedChannelID || mcs[5] != 0x70 {
		return 0, ErrMCSConnection
	}
	length, userData, err := readPERLength(mcs[6:])
	if err != nil || length == 0 || length != len(userData) || len(userData) < 18 {
		return 0, ErrMCSConnection
	}
	streamMatches := userData[11] == streamID
	if pduType2 == rdpPDU2Synchronize {
		streamMatches = userData[11] == 0 || userData[11] == 1
	}
	if int(binary.LittleEndian.Uint16(userData[0:2])) != len(userData) ||
		binary.LittleEndian.Uint16(userData[2:4]) != rdpShareDataPDU ||
		binary.LittleEndian.Uint16(userData[4:6]) != rdpServerChannelID ||
		binary.LittleEndian.Uint32(userData[6:10]) != shareID || !streamMatches ||
		int(binary.LittleEndian.Uint16(userData[12:14])) != len(userData) || userData[14] != pduType2 ||
		userData[15] != 0 || binary.LittleEndian.Uint16(userData[16:18]) != 0 {
		return 0, ErrMCSConnection
	}
	payload := userData[18:]
	switch pduType2 {
	case rdpPDU2Synchronize:
		if len(payload) != 4 || binary.LittleEndian.Uint16(payload[:2]) != rdpSyncMessage ||
			binary.LittleEndian.Uint16(payload[2:4]) != 0 {
			return 0, ErrMCSConnection
		}
	case rdpPDU2Control:
		if len(payload) != 8 {
			return 0, ErrMCSConnection
		}
		action := binary.LittleEndian.Uint16(payload[:2])
		if action != expectedAction || (action != rdpControlCooperate && action != rdpControlGranted) {
			return 0, ErrMCSConnection
		}
		grantID := binary.LittleEndian.Uint16(payload[2:4])
		controlID := binary.LittleEndian.Uint32(payload[4:8])
		if action == rdpControlCooperate && (grantID != 0 || controlID != 0) {
			return 0, ErrMCSConnection
		}
		if action == rdpControlGranted && (grantID != userID || controlID != uint32(rdpServerChannelID)) {
			return 0, ErrMCSConnection
		}
	case rdpPDU2FontMap:
		if len(payload) != 8 || binary.LittleEndian.Uint16(payload[0:2]) != 0 ||
			binary.LittleEndian.Uint16(payload[2:4]) != 0 ||
			binary.LittleEndian.Uint16(payload[4:6]) != rdpFontMapFirstLast ||
			binary.LittleEndian.Uint16(payload[6:8]) != rdpFontMapEntrySize {
			return 0, ErrMCSConnection
		}
	default:
		return 0, ErrMCSConnection
	}
	return binary.LittleEndian.Uint16(payload[:2]), nil
}

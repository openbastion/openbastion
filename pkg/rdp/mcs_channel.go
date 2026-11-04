package rdp

import (
	"context"
	"encoding/binary"
	"io"
	"time"
)

const mcsUserIDBase = uint16(1001)

// MCSChannelConnection is the bounded channel set negotiated for this RDP
// profile. Static virtual channels are intentionally not requested.
type MCSChannelConnection struct {
	UserChannelID uint16
	IOChannelID   uint16
}

func marshalMCSErectDomainRequest() []byte {
	return mcsDataTPDU([]byte{0x04, 1, 0, 1, 0}) // subHeight=0, subInterval=0
}

func marshalMCSAttachUserRequest() []byte {
	return mcsDataTPDU([]byte{0x28})
}

func marshalMCSChannelJoinRequest(userID, channelID uint16) []byte {
	if !validMCSUserID(userID) || channelID == 0 {
		return nil
	}
	pdu := []byte{0x38, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(pdu[1:3], userID-mcsUserIDBase)
	binary.BigEndian.PutUint16(pdu[3:5], channelID)
	return mcsDataTPDU(pdu)
}

func mcsDataTPDU(pdu []byte) []byte {
	length := 7 + len(pdu)
	if len(pdu) == 0 || length > maxTPKTPacket || length > 0xffff {
		return nil
	}
	packet := make([]byte, length)
	packet[0], packet[1] = 3, 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], pdu)
	return packet
}

func parseMCSAttachUserConfirm(packet []byte) (uint16, error) {
	pdu, err := parseMCSDataTPDU(packet)
	if err != nil || len(pdu) != 4 || pdu[0] != 0x2e || pdu[1] != 0 {
		return 0, ErrMCSConnection
	}
	userID := binary.BigEndian.Uint16(pdu[2:4])
	if userID > ^uint16(0)-mcsUserIDBase {
		return 0, ErrMCSConnection
	}
	userID += mcsUserIDBase
	if !validMCSUserID(userID) {
		return 0, ErrMCSConnection
	}
	return userID, nil
}

func parseMCSChannelJoinConfirm(packet []byte, expectedUserID, expectedChannelID uint16) (uint16, error) {
	pdu, err := parseMCSDataTPDU(packet)
	if err != nil || len(pdu) != 8 || pdu[0] != 0x3e || pdu[1] != 0 {
		return 0, ErrMCSConnection
	}
	encodedUserID := binary.BigEndian.Uint16(pdu[2:4])
	if encodedUserID > ^uint16(0)-mcsUserIDBase {
		return 0, ErrMCSConnection
	}
	initiator := encodedUserID + mcsUserIDBase
	requested := binary.BigEndian.Uint16(pdu[4:6])
	joined := binary.BigEndian.Uint16(pdu[6:8])
	if !validMCSUserID(initiator) || initiator != expectedUserID || requested != expectedChannelID || joined != expectedChannelID {
		return 0, ErrMCSConnection
	}
	return joined, nil
}

func parseMCSDataTPDU(packet []byte) ([]byte, error) {
	if len(packet) < 8 || len(packet) > maxTPKTPacket || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || !equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) {
		return nil, ErrMCSConnection
	}
	return packet[7:], nil
}

func validMCSUserID(userID uint16) bool {
	return userID >= mcsUserIDBase && userID != mcsGlobalChannelID
}

// ConnectMCSChannels performs Erect Domain, Attach User and the two sequential
// Channel Join exchanges required by the no-static-channel profile.
func (s *CredSSPClientSession) ConnectMCSChannels(ctx context.Context, timeout time.Duration) (channels MCSChannelConnection, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return channels, ErrMCSConnection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.credentialsDelegated ||
		!s.mcsConnected || s.channelsConnected || s.mcsResponse.IOChannelID == 0 ||
		!s.transport.Conn.ConnectionState().HandshakeComplete {
		return channels, ErrMCSConnection
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
		return channels, ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.closeTransportLocked()
			err = ErrMCSConnection
			channels = MCSChannelConnection{}
			return
		}
		if setErr := conn.SetDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.closeTransportLocked()
			err = ErrMCSConnection
			channels = MCSChannelConnection{}
			return
		}
		s.channelsConnected = true
		s.userChannelID = channels.UserChannelID
	}()

	if err = sendMCSChannelRequest(conn, marshalMCSErectDomainRequest()); err != nil {
		return channels, ErrMCSConnection
	}
	if err = sendMCSChannelRequest(conn, marshalMCSAttachUserRequest()); err != nil {
		return channels, ErrMCSConnection
	}
	attachConfirm, readErr := readMCSConnectResponse(conn)
	if readErr != nil {
		return channels, ErrMCSConnection
	}
	userID, parseErr := parseMCSAttachUserConfirm(attachConfirm)
	clear(attachConfirm)
	if parseErr != nil {
		return channels, ErrMCSConnection
	}

	ioChannelID := s.mcsResponse.IOChannelID
	for _, channelID := range []uint16{userID, ioChannelID} {
		request := marshalMCSChannelJoinRequest(userID, channelID)
		if request == nil {
			return channels, ErrMCSConnection
		}
		if err = sendMCSChannelRequest(conn, request); err != nil {
			return channels, ErrMCSConnection
		}
		confirm, readErr := readMCSConnectResponse(conn)
		if readErr != nil {
			return channels, ErrMCSConnection
		}
		joined, parseErr := parseMCSChannelJoinConfirm(confirm, userID, channelID)
		clear(confirm)
		if parseErr != nil || joined != channelID {
			return channels, ErrMCSConnection
		}
	}
	if ctx.Err() != nil {
		return channels, ErrMCSConnection
	}
	return MCSChannelConnection{UserChannelID: userID, IOChannelID: ioChannelID}, nil
}

func sendMCSChannelRequest(conn io.Writer, packet []byte) error {
	if len(packet) == 0 {
		return ErrMCSConnection
	}
	defer clear(packet)
	if err := writeFull(conn, packet); err != nil {
		return ErrMCSConnection
	}
	return nil
}

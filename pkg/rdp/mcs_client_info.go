package rdp

import (
	"context"
	"encoding/binary"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	rdpSecInfoPacket = uint16(0x0040)

	rdpInfoAutoLogon           = uint32(0x00000008)
	rdpInfoUnicode             = uint32(0x00000010)
	rdpInfoForceEncryptedCSPDU = uint32(0x00004000)

	maxRDPInfoStringBytes = 510 // 512 bytes including the mandatory UTF-16 NUL.
)

// RDPClientInfo contains the identity and logon secret sent after CredSSP.
// Password must be the same secret delegated to CredSSP. It is borrowed
// read-only, encoded only into the TLS-protected Client Info PDU, and never
// retained in CredSSPClientSession. The caller must clear its buffer afterward.
type RDPClientInfo struct {
	Domain   string
	Username string
	Password []byte
}

// SendClientInfo emits one minimal Unicode Client Info PDU on the MCS I/O
// channel. The MCS initiator remains the assigned User Channel ID. It is
// available only after CredSSP and Channel Connection, and before licensing
// or Demand Active. Password is included for the target's interactive logon.
func (s *CredSSPClientSession) SendClientInfo(ctx context.Context, info RDPClientInfo, timeout time.Duration) (err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return ErrMCSConnection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.credentialsDelegated ||
		!s.mcsConnected || !s.channelsConnected || s.clientInfoSent || s.capabilitiesExchanged ||
		!validMCSUserID(s.userChannelID) || !s.transport.Conn.ConnectionState().HandshakeComplete {
		return ErrMCSConnection
	}
	packet, buildErr := marshalRDPClientInfo(s.userChannelID, s.mcsResponse.IOChannelID, info)
	if buildErr != nil {
		return buildErr
	}
	defer clear(packet)

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
		s.clientInfoSent = true
		s.licensingUsername = info.Username
	}()
	if ctx.Err() != nil || writeFull(conn, packet) != nil {
		return ErrMCSConnection
	}
	if ctx.Err() != nil {
		return ErrMCSConnection
	}
	return nil
}

func marshalRDPClientInfo(userID, ioChannelID uint16, info RDPClientInfo) ([]byte, error) {
	if !validMCSUserID(userID) || ioChannelID != mcsGlobalChannelID {
		return nil, ErrMCSConnection
	}
	domain, ok := encodeRDPInfoString(info.Domain, true)
	if !ok {
		return nil, ErrMCSConnection
	}
	defer clear(domain)
	username, ok := encodeRDPInfoString(info.Username, false)
	if !ok {
		return nil, ErrMCSConnection
	}
	defer clear(username)
	password, ok := encodeRDPInfoBytes(info.Password, false, false)
	if !ok {
		return nil, ErrMCSConnection
	}
	defer clear(password)

	// TS_INFO_PACKET has five length fields. Every string is UTF-16LE and
	// includes a mandatory NUL terminator not counted by its cb* field.
	infoPacket := make([]byte, 18, 18+len(domain)+len(username)+len(password)+10)
	binary.LittleEndian.PutUint32(infoPacket[0:4], 0) // keyboardLayout=0: language ID ignored.
	binary.LittleEndian.PutUint32(infoPacket[4:8], rdpInfoUnicode|rdpInfoAutoLogon|rdpInfoForceEncryptedCSPDU)
	binary.LittleEndian.PutUint16(infoPacket[8:10], uint16(len(domain)))
	binary.LittleEndian.PutUint16(infoPacket[10:12], uint16(len(username)))
	binary.LittleEndian.PutUint16(infoPacket[12:14], uint16(len(password)))
	// cbAlternateShell and cbWorkingDir remain zero.
	infoPacket = append(infoPacket, domain...)
	infoPacket = append(infoPacket, 0, 0)
	infoPacket = append(infoPacket, username...)
	infoPacket = append(infoPacket, 0, 0)
	infoPacket = append(infoPacket, password...)
	infoPacket = append(infoPacket, 0, 0) // Password is protected by HYBRID/TLS.
	infoPacket = append(infoPacket, 0, 0) // AlternateShell: default shell.
	infoPacket = append(infoPacket, 0, 0) // WorkingDir: default directory.

	// The Basic Security Header remains present under HYBRID/TLS. TLS protects
	// the complete transport; SEC_INFO_PKT identifies the Client Info payload.
	payload := make([]byte, 4, 4+len(infoPacket))
	binary.LittleEndian.PutUint16(payload[:2], rdpSecInfoPacket)
	payload = append(payload, infoPacket...)
	clear(infoPacket)
	packet, err := marshalMCSSendDataRequest(userID, ioChannelID, payload)
	clear(payload)
	if err != nil {
		return nil, ErrMCSConnection
	}
	return packet, nil
}

func encodeRDPInfoString(value string, emptyAllowed bool) ([]byte, bool) {
	return encodeRDPInfoBytes([]byte(value), emptyAllowed, true)
}

// encodeRDPInfoBytes converts UTF-8 to bounded UTF-16LE without retaining a
// string copy of secret data. Passwords may contain control characters but
// never NUL, which is reserved for the field terminator.
func encodeRDPInfoBytes(value []byte, emptyAllowed, rejectControls bool) ([]byte, bool) {
	if !utf8.Valid(value) || (!emptyAllowed && len(value) == 0) {
		return nil, false
	}
	runes := make([]rune, 0, len(value))
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == 0 || (rejectControls && unicode.IsControl(r)) {
			clear(runes)
			return nil, false
		}
		runes = append(runes, r)
		value = value[size:]
	}
	units := utf16.Encode(runes)
	clear(runes)
	if len(units)*2 > maxRDPInfoStringBytes {
		clear(units)
		return nil, false
	}
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:i*2+2], unit)
	}
	clear(units)
	return encoded, true
}

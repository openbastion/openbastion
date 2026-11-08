package rdp

import (
	"context"
	"encoding/binary"
	"time"
)

const (
	rdpPDU2Input          = byte(28)
	rdpInputEventScancode = uint16(0x0004)
	rdpInputEventMouse    = uint16(0x8001)
	rdpKBDFlagsRelease    = uint16(0x8000)
	rdpKBDFlagsExtended   = uint16(0x0100)
	rdpPtrFlagsMove       = uint16(0x0800)
	rdpPtrFlagsButton1    = uint16(0x1000)
	rdpPtrFlagsButton2    = uint16(0x2000)
	rdpPtrFlagsButton3    = uint16(0x4000)
	rdpPtrFlagsDown       = uint16(0x8000)
	rdpPtrFlagsWheel      = uint16(0x0200)
	rdpPtrFlagsWheelNeg   = uint16(0x0100)
	rdpPtrFlagsWheelMask  = uint16(0x01ff)
	maxRDPInputEvents     = 128
)

type RDPInputEventType byte

const (
	RDPInputScancode RDPInputEventType = 1
	RDPInputMouse    RDPInputEventType = 2
)

// RDPInputEvent is one bounded slow-path keyboard or mouse event. Scancodes
// are the 8-bit Set-1 make code; Extended marks an E0-prefixed code. Mouse
// PointerFlags uses the documented PTRFLAGS values and coordinates are pixels.
type RDPInputEvent struct {
	Type         RDPInputEventType
	Scancode     byte
	Extended     bool
	Released     bool
	PointerFlags uint16
	X            uint16
	Y            uint16
}

// SendInput serializes one bounded TS_INPUT_PDU. TLS permits one concurrent
// reader and writer; readMu/writeMu keep each direction ordered independently.
func (s *CredSSPClientSession) SendInput(ctx context.Context, events []RDPInputEvent, timeout time.Duration) (err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 || len(events) == 0 || len(events) > maxRDPInputEvents {
		return ErrMCSConnection
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if ctx.Err() != nil || s.transport == nil || s.transport.Conn == nil || !s.connectionFinalized ||
		!s.capabilitiesExchanged || !validMCSUserID(s.userChannelID) || s.serverCapabilities.ShareID == 0 ||
		!s.transport.Conn.ConnectionState().HandshakeComplete {
		s.mu.Unlock()
		return ErrMCSConnection
	}
	conn := s.transport.Conn
	userID, shareID := s.userChannelID, s.serverCapabilities.ShareID
	s.mu.Unlock()

	packet, buildErr := marshalRDPInput(userID, shareID, events)
	if buildErr != nil {
		return buildErr
	}
	defer clear(packet)
	if timeout == 0 {
		timeout = defaultCredSSPTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		s.mu.Lock()
		s.closeTransportLocked()
		s.mu.Unlock()
		return ErrMCSConnection
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Now()) })
	defer func() {
		cancelStopped := stopCancel()
		if err != nil || ctx.Err() != nil || !cancelStopped {
			s.mu.Lock()
			s.closeTransportLocked()
			s.mu.Unlock()
			err = ErrMCSConnection
			return
		}
		if setErr := conn.SetWriteDeadline(time.Time{}); setErr != nil || ctx.Err() != nil {
			s.mu.Lock()
			s.closeTransportLocked()
			s.mu.Unlock()
			err = ErrMCSConnection
		}
	}()
	if ctx.Err() != nil || writeFull(conn, packet) != nil {
		return ErrMCSConnection
	}
	return nil
}

func marshalRDPInput(userID uint16, shareID uint32, events []RDPInputEvent) ([]byte, error) {
	if len(events) == 0 || len(events) > maxRDPInputEvents {
		return nil, ErrMCSConnection
	}
	payload := make([]byte, 4+len(events)*12)
	binary.LittleEndian.PutUint16(payload[:2], uint16(len(events)))
	for i, event := range events {
		entry := payload[4+i*12 : 4+(i+1)*12]
		binary.LittleEndian.PutUint32(entry[0:4], 0) // eventTime is ignored by the server.
		switch event.Type {
		case RDPInputScancode:
			if event.PointerFlags != 0 || event.X != 0 || event.Y != 0 || event.Scancode == 0 || event.Scancode > 0x7f {
				clear(payload)
				return nil, ErrMCSConnection
			}
			binary.LittleEndian.PutUint16(entry[4:6], rdpInputEventScancode)
			// A press has no flag: KBDFLAGS_DOWN says the key was already down, a repeat
			// (MS-RDPBCGR 2.2.8.1.1.3.1.1.1), as FreeRDP sends it. Set on every press, Windows took
			// presses for repeats of keys it held up, and lost some (ADR-0071, CI run #48).
			flags := uint16(0)
			if event.Released {
				flags = rdpKBDFlagsRelease
			}
			if event.Extended {
				flags |= rdpKBDFlagsExtended
			}
			binary.LittleEndian.PutUint16(entry[6:8], flags)
			binary.LittleEndian.PutUint16(entry[8:10], uint16(event.Scancode))
		case RDPInputMouse:
			flags := event.PointerFlags
			buttonFlags := flags & (rdpPtrFlagsButton1 | rdpPtrFlagsButton2 | rdpPtrFlagsButton3)
			wheelBits := flags & rdpPtrFlagsWheelMask
			wheelValid := flags&rdpPtrFlagsWheel != 0 && wheelBits&0x00ff != 0
			if event.Scancode != 0 || event.Extended || event.Released || flags == 0 ||
				flags&^(rdpPtrFlagsMove|rdpPtrFlagsButton1|rdpPtrFlagsButton2|rdpPtrFlagsButton3|rdpPtrFlagsDown|rdpPtrFlagsWheel|rdpPtrFlagsWheelNeg|rdpPtrFlagsWheelMask) != 0 ||
				flags&rdpPtrFlagsDown != 0 && buttonFlags == 0 ||
				flags&rdpPtrFlagsWheel != 0 && !wheelValid ||
				flags&rdpPtrFlagsWheel == 0 && wheelBits != 0 {
				clear(payload)
				return nil, ErrMCSConnection
			}
			binary.LittleEndian.PutUint16(entry[4:6], rdpInputEventMouse)
			binary.LittleEndian.PutUint16(entry[6:8], event.PointerFlags)
			binary.LittleEndian.PutUint16(entry[8:10], event.X)
			binary.LittleEndian.PutUint16(entry[10:12], event.Y)
		default:
			clear(payload)
			return nil, ErrMCSConnection
		}
	}
	packet, err := marshalRDPShareData(userID, shareID, 1, rdpPDU2Input, payload)
	clear(payload)
	return packet, err
}

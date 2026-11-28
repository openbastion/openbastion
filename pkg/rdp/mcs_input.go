package rdp

import (
	"context"
	"encoding/binary"
	"time"
)

const (
	rdpPDU2Input                  = byte(28)
	rdpInputEventScancode         = uint16(0x0004)
	rdpInputEventUnicode          = uint16(0x0005)
	rdpInputEventMouse            = uint16(0x8001)
	rdpKBDFlagsRelease            = uint16(0x8000)
	rdpKBDFlagsExtended           = uint16(0x0100)
	rdpPtrFlagsMove               = uint16(0x0800)
	rdpPtrFlagsButton1            = uint16(0x1000)
	rdpPtrFlagsButton2            = uint16(0x2000)
	rdpPtrFlagsButton3            = uint16(0x4000)
	rdpPtrFlagsDown               = uint16(0x8000)
	rdpPtrFlagsWheel              = uint16(0x0200)
	rdpPtrFlagsWheelNeg           = uint16(0x0100)
	rdpPtrFlagsWheelMask          = uint16(0x01ff)
	maxRDPInputEvents             = 128
	rdpInputFlagScancodes         = uint16(0x0001)
	rdpInputFlagUnicode           = uint16(0x0010)
	rdpInputFlagFastPathInput2    = uint16(0x0020)
	rdpFastPathInputMaxPDU        = 16383
	rdpFastPathInputEventScancode = byte(0)
	rdpFastPathInputEventMouse    = byte(1)
	rdpFastPathInputEventSync     = byte(3)
	rdpFastPathInputEventUnicode  = byte(4)
	rdpFastPathInputKBDRelease    = byte(0x01)
	rdpFastPathInputKBDExtended   = byte(0x02)
)

type RDPInputEventType byte

const (
	RDPInputScancode RDPInputEventType = 1
	RDPInputMouse    RDPInputEventType = 2
	RDPInputUnicode  RDPInputEventType = 4
	// RDPInputSync is TS_SYNC_EVENT: the state of the toggle keys (ToggleFlags), which a client
	// sends when it gains the focus (MS-RDPBCGR 2.2.8.1.1.3.1.1.5).
	RDPInputSync RDPInputEventType = 3
)

const (
	rdpInputEventSync     = uint16(0x0000)
	rdpSyncToggleFlagsAll = uint32(0x0000000f) // scroll, num, caps and kana lock
)

// RDPInputEvent is one bounded keyboard or mouse event. Scancodes
// are the 8-bit Set-1 make code; Extended marks an E0-prefixed code. Mouse
// PointerFlags uses the documented PTRFLAGS values and coordinates are pixels.
type RDPInputEvent struct {
	Type         RDPInputEventType
	Scancode     byte
	Unicode      uint16 // UTF-16 code unit for RDPInputUnicode only.
	Extended     bool
	Released     bool
	PointerFlags uint16
	X            uint16
	Y            uint16
	ToggleFlags  uint32 // RDPInputSync only
}

// SendInput serializes one bounded slow- or Fast-Path input PDU. TLS permits one concurrent
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
	inputFlags := s.serverCapabilities.InputFlags
	s.mu.Unlock()

	var packet []byte
	var buildErr error
	if inputFlags&rdpInputFlagFastPathInput2 != 0 && fastPathInputEventsSupported(events, inputFlags) {
		packet, buildErr = marshalRDPFastPathInput(events)
	} else {
		packet, buildErr = marshalRDPInput(userID, shareID, events)
	}
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

// fastPathInputEventsSupported reports whether every event in a batch is covered by the
// server's negotiated Input Capability Set. A mixed batch falls back as a whole to slow-path.
func fastPathInputEventsSupported(events []RDPInputEvent, inputFlags uint16) bool {
	if inputFlags&rdpInputFlagFastPathInput2 == 0 {
		return false
	}
	for _, event := range events {
		if event.Type == RDPInputUnicode && inputFlags&rdpInputFlagUnicode == 0 {
			return false
		}
		if event.Type != RDPInputScancode && event.Type != RDPInputUnicode && event.Type != RDPInputMouse && event.Type != RDPInputSync {
			return false
		}
	}
	return len(events) > 0 && len(events) <= maxRDPInputEvents
}

// marshalRDPFastPathInput emits an unencrypted TS_FP_INPUT_PDU. The enclosing TLS
// transport provides confidentiality and integrity (Enhanced RDP Security).
func marshalRDPFastPathInput(events []RDPInputEvent) ([]byte, error) {
	if len(events) == 0 || len(events) > maxRDPInputEvents {
		return nil, ErrMCSConnection
	}
	encoded := make([]byte, 0, len(events)*7)
	for _, event := range events {
		var header byte
		switch event.Type {
		case RDPInputScancode:
			if event.Scancode == 0 || event.Scancode > 0x7f || event.Unicode != 0 || event.PointerFlags != 0 || event.X != 0 || event.Y != 0 || event.ToggleFlags != 0 {
				clear(encoded)
				return nil, ErrMCSConnection
			}
			if event.Released {
				header |= rdpFastPathInputKBDRelease
			}
			if event.Extended {
				header |= rdpFastPathInputKBDExtended
			}
			header = header<<3 | rdpFastPathInputEventScancode
			encoded = append(encoded, header, event.Scancode)
		case RDPInputUnicode:
			if event.Unicode == 0 || event.Scancode != 0 || event.Extended || event.PointerFlags != 0 || event.X != 0 || event.Y != 0 || event.ToggleFlags != 0 {
				clear(encoded)
				return nil, ErrMCSConnection
			}
			if event.Released {
				header |= rdpFastPathInputKBDRelease
			}
			header = header<<3 | rdpFastPathInputEventUnicode
			encoded = append(encoded, header, byte(event.Unicode), byte(event.Unicode>>8))
		case RDPInputMouse:
			flags := event.PointerFlags
			buttonFlags := flags & (rdpPtrFlagsButton1 | rdpPtrFlagsButton2 | rdpPtrFlagsButton3)
			wheelBits := flags & rdpPtrFlagsWheelMask
			wheelValid := flags&rdpPtrFlagsWheel != 0 && wheelBits&0x00ff != 0
			if event.Scancode != 0 || event.Unicode != 0 || event.Extended || event.Released || event.ToggleFlags != 0 || flags == 0 ||
				flags&^(rdpPtrFlagsMove|rdpPtrFlagsButton1|rdpPtrFlagsButton2|rdpPtrFlagsButton3|rdpPtrFlagsDown|rdpPtrFlagsWheel|rdpPtrFlagsWheelNeg|rdpPtrFlagsWheelMask) != 0 ||
				flags&rdpPtrFlagsDown != 0 && buttonFlags == 0 || flags&rdpPtrFlagsWheel != 0 && !wheelValid || flags&rdpPtrFlagsWheel == 0 && wheelBits != 0 {
				clear(encoded)
				return nil, ErrMCSConnection
			}
			header = rdpFastPathInputEventMouse
			encoded = append(encoded, header, byte(flags), byte(flags>>8), byte(event.X), byte(event.X>>8), byte(event.Y), byte(event.Y>>8))
		case RDPInputSync:
			if event.Scancode != 0 || event.Unicode != 0 || event.Extended || event.Released || event.PointerFlags != 0 || event.X != 0 || event.Y != 0 || event.ToggleFlags&^rdpSyncToggleFlagsAll != 0 {
				clear(encoded)
				return nil, ErrMCSConnection
			}
			header = byte(event.ToggleFlags<<3) | rdpFastPathInputEventSync
			encoded = append(encoded, header)
		default:
			clear(encoded)
			return nil, ErrMCSConnection
		}
	}
	packet, err := marshalRDPFastPathInputPDU(encoded, len(events))
	clear(encoded)
	return packet, err
}

// marshalRDPFastPathInputPDU adds the compact count and one- or two-byte total length.
// This helper also makes the 16,383-byte protocol boundary independently testable.
func marshalRDPFastPathInputPDU(events []byte, count int) ([]byte, error) {
	if count < 1 || count > maxRDPInputEvents || len(events) == 0 {
		return nil, ErrMCSConnection
	}
	countBytes := 0
	if count > 15 {
		countBytes = 1
	}
	shortLength := 1 + 1 + countBytes + len(events)
	lengthBytes := 1
	length := shortLength
	if shortLength > 127 {
		lengthBytes = 2
		length++ // The extended length field adds one byte to the overall PDU.
	}
	if length > rdpFastPathInputMaxPDU {
		return nil, ErrMCSConnection
	}
	packet := make([]byte, length)
	if count <= 15 {
		packet[0] = byte(count << 2)
	}
	if lengthBytes == 1 {
		packet[1] = byte(length)
		if count > 15 {
			packet[2] = byte(count)
		}
		copy(packet[2+countBytes:], events)
	} else {
		packet[1] = 0x80 | byte(length>>8)
		packet[2] = byte(length)
		if count > 15 {
			packet[3] = byte(count)
		}
		copy(packet[3+countBytes:], events)
	}
	return packet, nil
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
		case RDPInputSync:
			if event.Scancode != 0 || event.Unicode != 0 || event.Extended || event.Released || event.PointerFlags != 0 ||
				event.X != 0 || event.Y != 0 || event.ToggleFlags&^rdpSyncToggleFlagsAll != 0 {
				clear(payload)
				return nil, ErrMCSConnection
			}
			binary.LittleEndian.PutUint16(entry[4:6], rdpInputEventSync)
			binary.LittleEndian.PutUint32(entry[8:12], event.ToggleFlags) // after two pad bytes
		case RDPInputScancode:
			if event.Unicode != 0 || event.PointerFlags != 0 || event.X != 0 || event.Y != 0 || event.ToggleFlags != 0 || event.Scancode == 0 || event.Scancode > 0x7f {
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
		case RDPInputUnicode:
			if event.Scancode != 0 || event.Extended || event.PointerFlags != 0 || event.X != 0 || event.Y != 0 || event.ToggleFlags != 0 || event.Unicode == 0 {
				clear(payload)
				return nil, ErrMCSConnection
			}
			binary.LittleEndian.PutUint16(entry[4:6], rdpInputEventUnicode)
			flags := uint16(0)
			if event.Released {
				flags = rdpKBDFlagsRelease
			}
			binary.LittleEndian.PutUint16(entry[6:8], flags)
			binary.LittleEndian.PutUint16(entry[8:10], event.Unicode)
		case RDPInputMouse:
			flags := event.PointerFlags
			buttonFlags := flags & (rdpPtrFlagsButton1 | rdpPtrFlagsButton2 | rdpPtrFlagsButton3)
			wheelBits := flags & rdpPtrFlagsWheelMask
			wheelValid := flags&rdpPtrFlagsWheel != 0 && wheelBits&0x00ff != 0
			if event.Scancode != 0 || event.Unicode != 0 || event.Extended || event.Released || event.ToggleFlags != 0 || flags == 0 ||
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

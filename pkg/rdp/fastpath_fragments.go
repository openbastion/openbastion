package rdp

import (
	"encoding/binary"
	"fmt"
)

// Fast-Path update fragmentation (MS-RDPBCGR 2.2.9.1.2.1, the fragmentation field of the update
// header): an update larger than a PDU comes as FIRST, NEXT..., LAST, all of one update code. The
// client announces, in TS_MULTIFRAGMENTUPDATE_CAPABILITYSET, the size it reassembles; a server
// must not send a larger update. That size is the bound held here: a sequence past it, out of
// order, mixing codes, or of too many pieces is refused, and the session with it.

const (
	rdpFastPathFragmentSingle = byte(0)
	rdpFastPathFragmentLast   = byte(1)
	rdpFastPathFragmentFirst  = byte(2)
	rdpFastPathFragmentNext   = byte(3)

	rdpCapMultifragmentUpdate = uint16(0x001a)
	// maxRDPFastPathReassembly is the MaxRequestSize this client announces and holds the server
	// to: 256 KiB, eight full Fast-Path PDUs. What it decodes to stays bounded by the bitmap
	// bounds (maxRDPBitmapUpdateRects, maxRDPDesktopArea).
	maxRDPFastPathReassembly = 256 * 1024
	maxRDPFastPathFragments  = 64
)

// splitRDPFastPathUpdate returns the update code, fragmentation and data of a Fast-Path PDU that
// carries exactly one update, uncompressed and unencrypted (TLS is the security layer).
func splitRDPFastPathUpdate(packet []byte) (code, fragmentation byte, data []byte, err error) {
	if len(packet) < 2+3 || len(packet) > maxRDPFastPathPacket || packet[0] != 0 {
		return 0, 0, nil, ErrMCSConnection
	}
	offset, length := 2, int(packet[1])
	if packet[1]&0x80 != 0 {
		offset, length = 3, int(packet[1]&0x7f)<<8|int(packet[2])
	}
	if length != len(packet) || len(packet) < offset+3 {
		return 0, 0, nil, ErrMCSConnection
	}
	header := packet[offset]
	size := int(binary.LittleEndian.Uint16(packet[offset+1 : offset+3]))
	data = packet[offset+3:]
	if header>>6 != 0 || size != len(data) { // compression is not negotiated; one update per PDU
		return 0, 0, nil, ErrMCSConnection
	}
	return header & 0x0f, header >> 4 & 0x03, data, nil
}

// rdpFastPathAssembler reassembles one fragmented update at a time.
type rdpFastPathAssembler struct {
	active bool
	code   byte
	pieces int
	data   []byte
}

// add takes one update; it returns the whole update when it is complete. Any error leaves the
// assembler unusable: the caller ends the session.
func (a *rdpFastPathAssembler) add(code, fragmentation byte, data []byte) ([]byte, bool, error) {
	// fail says which rule refused the update (CI of PR #157, Windows Server 2019: a LAST refused
	// after a reactivation, and the bound it crossed was not said).
	fail := func(why string) ([]byte, bool, error) {
		why = fmt.Sprintf("%s (fragment %d, %d bytes so far, this one %d)", why, a.pieces+1, len(a.data), len(data))
		clear(a.data)
		*a = rdpFastPathAssembler{active: true, code: 0xff} // nothing more is accepted
		return nil, false, fmt.Errorf("%w: fragmented update refused: %s", ErrMCSConnection, why)
	}
	switch fragmentation {
	case rdpFastPathFragmentSingle:
		if a.active {
			return fail("a whole update inside a fragmented one")
		}
		return data, true, nil
	case rdpFastPathFragmentFirst:
		if a.active {
			return fail("a first fragment inside a fragmented update")
		}
		if len(data) == 0 || len(data) > maxRDPFastPathReassembly {
			return fail("a first fragment empty or past the reassembly bound")
		}
		a.active, a.code, a.pieces = true, code, 1
		a.data = append(make([]byte, 0, len(data)), data...)
		return nil, false, nil
	default: // NEXT or LAST
		switch {
		case !a.active:
			return fail("a fragment with no first fragment before it")
		case a.code != code:
			return fail(fmt.Sprintf("a fragment of update code %d inside code %d", code, a.code))
		case len(data) == 0:
			return fail("an empty fragment")
		case a.pieces >= maxRDPFastPathFragments:
			return fail(fmt.Sprintf("past %d fragments", maxRDPFastPathFragments))
		case len(data) > maxRDPFastPathReassembly-len(a.data):
			return fail(fmt.Sprintf("past the %d-byte reassembly bound this client announces", maxRDPFastPathReassembly))
		}
		a.data = append(a.data, data...)
		a.pieces++
		if fragmentation == rdpFastPathFragmentNext {
			return nil, false, nil
		}
		whole := a.data
		*a = rdpFastPathAssembler{}
		return whole, true, nil
	}
}

// rdpFastPathCodeIsPointer is the closed list of the pointer's updates, decoded when the pointer is
// drawn (ADR-0091) and ignored otherwise.
func rdpFastPathCodeIsPointer(code byte) bool {
	switch code {
	case rdpFastPathPointerHidden, rdpFastPathPointerDefault, rdpFastPathPointerPosition,
		rdpFastPathPointerColor, rdpFastPathPointerCached, rdpFastPathPointerNew:
		return true
	}
	return false
}

// rdpFastPathCodeIsIgnored is the closed list of updates that show nothing in the screen stream:
// synchronize, and the pointer, which the operator's browser draws itself.
func rdpFastPathCodeIsIgnored(code byte) bool {
	switch code {
	case 0x3, 0x5, 0x6, 0x8, 0x9, 0xa, 0xb:
		return true
	}
	return false
}

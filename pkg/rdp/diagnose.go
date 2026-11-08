package rdp

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// describeRDPServerPacket names what a server packet carries, from its headers only: the TPKT
// Share Control type and Share Data type, or each Fast-Path update's code, fragmentation and
// compression, and for a Demand Active its capability sets and session depth. A refused packet is
// described this way in the error (ADR-0071: a bare refusal left Windows' behaviour unknown). It
// reads no pixel and no field a server would keep secret, and never fails: what it cannot read,
// it says so.
func describeRDPServerPacket(packet []byte) string {
	if len(packet) > 0 && packet[0] == 3 {
		if len(packet) < 8 {
			return fmt.Sprintf("TPKT of %d bytes", len(packet))
		}
		// The MCS PDU type: Send Data Indication, or what is not (a Disconnect Provider Ultimatum,
		// 0x80 to 0x83, says the server ends the connection).
		if len(packet) < 14 || packet[7] != mcsSendDataIndication {
			return fmt.Sprintf("TPKT of %d bytes, MCS PDU 0x%02x", len(packet), packet[7])
		}
		channel := fmt.Sprintf("channel %d, priority/segmentation 0x%02x", binary.BigEndian.Uint16(packet[10:12]), packet[12])
		_, share, err := readPERLength(packet[13:])
		if err != nil || len(share) < 6 {
			return fmt.Sprintf("TPKT of %d bytes, MCS %s", len(packet), channel)
		}
		if binary.BigEndian.Uint16(packet[10:12]) != mcsGlobalChannelID || packet[12]&0xcf != 0x40 || packet[12]>>4&3 != 3 {
			return fmt.Sprintf("TPKT of %d bytes, MCS %s, share PDU type %d", len(packet), channel, binary.LittleEndian.Uint16(share[2:4])&0x0f)
		}
		kind := binary.LittleEndian.Uint16(share[2:4]) & 0x0f
		switch {
		case kind == 1:
			return "TPKT, " + describeRDPDemandActive(share)
		case kind != 7 || len(share) < 20:
			return fmt.Sprintf("TPKT, share PDU type %d", kind)
		}
		text := fmt.Sprintf("TPKT, share data pduType2 0x%02x", share[14])
		if share[14] == rdpPDU2Update {
			text += fmt.Sprintf(", update type %d", binary.LittleEndian.Uint16(share[18:20]))
		}
		return text
	}
	if len(packet) < 2 {
		return fmt.Sprintf("%d bytes", len(packet))
	}
	offset := 2
	if packet[1]&0x80 != 0 {
		offset = 3
	}
	var updates []string
	for rest := packet[min(offset, len(packet)):]; len(rest) >= 3 && len(updates) < 16; {
		header := rest[0]
		size := int(binary.LittleEndian.Uint16(rest[1:3]))
		body := 3
		if header>>6&0x2 != 0 { // compressed: one compressionFlags byte before the size
			if len(rest) < 4 {
				break
			}
			size = int(binary.LittleEndian.Uint16(rest[2:4]))
			body = 4
		}
		updates = append(updates, fmt.Sprintf("code %d frag %d comp %d size %d", header&0x0f, header>>4&0x3, header>>6, size))
		if body+size > len(rest) {
			updates = append(updates, "(truncated)")
			break
		}
		rest = rest[body+size:]
	}
	return fmt.Sprintf("Fast-Path action %d, %d bytes [%s]", packet[0]&0x3, len(packet), strings.Join(updates, "; "))
}

// describeRDPDemandActive lists a Demand Active's capability sets and the bitmap set's depth and
// desktop size, as far as its lengths allow.
func describeRDPDemandActive(share []byte) string {
	if len(share) < 14 {
		return "Demand Active, truncated"
	}
	sourceLength := int(binary.LittleEndian.Uint16(share[10:12]))
	combined := int(binary.LittleEndian.Uint16(share[12:14]))
	if 14+sourceLength+combined > len(share) || combined < 4 {
		return fmt.Sprintf("Demand Active, lengths %d+%d of %d", sourceLength, combined, len(share))
	}
	data := share[14+sourceLength : 14+sourceLength+combined]
	count := int(binary.LittleEndian.Uint16(data[:2]))
	var kinds []string
	bitmap := ""
	for rest := data[4:]; len(rest) >= 4 && len(kinds) < 64; {
		kind, size := binary.LittleEndian.Uint16(rest[:2]), int(binary.LittleEndian.Uint16(rest[2:4]))
		kinds = append(kinds, fmt.Sprintf("0x%04x/%d", kind, size))
		if size < 4 || size > len(rest) {
			kinds = append(kinds, "(bad length)")
			break
		}
		if kind == rdpCapBitmap && size >= 16 {
			bitmap = fmt.Sprintf(", bitmap %d bpp %dx%d", binary.LittleEndian.Uint16(rest[4:6]),
				binary.LittleEndian.Uint16(rest[12:14]), binary.LittleEndian.Uint16(rest[14:16]))
		}
		rest = rest[size:]
	}
	return fmt.Sprintf("Demand Active, %d capability sets [%s]%s", count, strings.Join(kinds, " "), bitmap)
}

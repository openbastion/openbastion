package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The dynamic channels (MS-RDPEDYC), carried by the static channel drdynvc (ADR-0095 §3): the
// target proposes channels by name, and this client opens only the names of a closed list, which
// holds two names, the display control (MS-RDPEDISP) and the graphics pipeline (MS-RDPEGFX, ADR-0101). Every other name is refused by the
// protocol's own answer: the target goes on without it, and so does the session. What the target
// sends is bounded as the static channels are, and anything outside the protocol ends the session.

// RDPDisplayControlChannel is the dynamic channel of the display control (MS-RDPEDISP).
const RDPDisplayControlChannel = "Microsoft::Windows::RDS::DisplayControl"

const (
	dynvcCreate         = byte(0x01)
	dynvcDataFirst      = byte(0x02)
	dynvcData           = byte(0x03)
	dynvcClose          = byte(0x04)
	dynvcCapability     = byte(0x05)
	dynvcDataFirstCompr = byte(0x06)
	dynvcDataCompr      = byte(0x07)

	// dynvcClientVersion is the version this client answers with: 2 at most, which has no
	// compression (version 3 adds it, MS-RDPEDYC 2.2.1.2).
	dynvcClientVersion = uint16(2)

	// maxDynvcNameBytes bounds a proposed channel's name, its NUL excluded.
	maxDynvcNameBytes = 255
	// maxDynvcRefusals bounds the refused names a session keeps for its log.
	maxDynvcRefusals = 32
	// maxDynvcSendBytes bounds a message this client sends on a dynamic channel: one DATA PDU in
	// one channel chunk, header and channel ID included.
	maxDynvcSendBytes = rdpChannelChunkLength - 6

	// dynvcCreationRefused is the CreationStatus of a refused channel: any negative HRESULT says
	// the creation failed (MS-RDPEDYC 2.2.2.2); this one is E_ACCESSDENIED.
	dynvcCreationRefused = uint32(0x80070005)
)

// rdpDynamicChannelsAllowed is the closed list of ADR-0095: what EnableDynamicChannels may open.
var rdpDynamicChannelsAllowed = map[string]bool{RDPDisplayControlChannel: true, RDPGraphicsChannel: true}

// rdpDynamicChannelLimits bounds a message reassembled on a channel, MaxRDPChannelMessage otherwise:
// the graphics pipeline carries whole bitmaps, compressed (ADR-0101).
var rdpDynamicChannelLimits = map[string]int{RDPGraphicsChannel: maxGraphicsMessage}

func dynvcLimit(name string) int {
	if limit, ok := rdpDynamicChannelLimits[name]; ok {
		return limit
	}
	return MaxRDPChannelMessage
}

// ErrRDPDynamicChannel reports a dynamic channel message outside MS-RDPEDYC or its bounds.
var ErrRDPDynamicChannel = errors.New("rdp: dynamic channel message refused")

// ErrRDPDynamicChannelClosed says the channel to send on is not open now: the target closed it, as
// Windows does while it reactivates, and may open it again (CI of PR #155). It is no fault of the
// session's: the caller may drop what it meant to send.
var ErrRDPDynamicChannelClosed = fmt.Errorf("%w: the channel is not open", ErrRDPDynamicChannel)

// rdpDynamicChannels is the state of the dynamic channels of one session: which names may open,
// which are open under which ID, the message being reassembled on each, and the names refused.
type rdpDynamicChannels struct {
	allowed    map[string]bool
	capsSeen   bool
	open       map[uint32]string
	assembling map[uint32]*dynvcAssembly
	refused    []string
	refusals   int
	// What handle found to tell, told by the reader once s.mu is released and the answers sent:
	// the callbacks may send on a channel, which takes s.mu.
	opened    []string
	delivered []dynvcDelivery
}

type dynvcDelivery struct {
	name string
	data []byte
}

type dynvcAssembly struct {
	total int
	data  []byte
}

// dynvcIDBytes is the size of the ChannelId field its cbId bits say.
func dynvcIDBytes(cbID byte) int {
	switch cbID {
	case 0:
		return 1
	case 1:
		return 2
	case 2:
		return 4
	}
	return 0
}

func readDynvcVar(data []byte, size int) (uint32, []byte, bool) {
	if size == 0 || len(data) < size {
		return 0, nil, false
	}
	switch size {
	case 1:
		return uint32(data[0]), data[1:], true
	case 2:
		return uint32(binary.LittleEndian.Uint16(data[:2])), data[2:], true
	}
	return binary.LittleEndian.Uint32(data[:4]), data[4:], true
}

func appendDynvcID(dst []byte, cbID byte, id uint32) []byte {
	switch cbID {
	case 0:
		return append(dst, byte(id))
	case 1:
		return binary.LittleEndian.AppendUint16(dst, uint16(id))
	}
	return binary.LittleEndian.AppendUint32(dst, id)
}

// dynvcCbIDFor is the smallest cbId that holds id.
func dynvcCbIDFor(id uint32) byte {
	switch {
	case id <= 0xff:
		return 0
	case id <= 0xffff:
		return 1
	}
	return 2
}

// handle reads one drdynvc message and returns the answers to send back on drdynvc, in order.
func (d *rdpDynamicChannels) handle(message []byte) ([][]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("%w: an empty message", ErrRDPDynamicChannel)
	}
	header := message[0]
	cmd, sp, cbID := header>>4, (header>>2)&0x03, header&0x03
	body := message[1:]
	switch cmd {
	case dynvcCapability:
		// DYNVC_CAPS_VERSION1 is Pad and Version; versions 2 and 3 add four priority charges.
		if len(body) < 3 {
			return nil, fmt.Errorf("%w: capabilities cut short", ErrRDPDynamicChannel)
		}
		version := binary.LittleEndian.Uint16(body[1:3])
		if version == 0 || (version == 1 && len(body) != 3) || (version > 1 && len(body) != 11) || d.capsSeen {
			return nil, fmt.Errorf("%w: capabilities version %d, %d bytes", ErrRDPDynamicChannel, version, len(message))
		}
		d.capsSeen = true
		answer := []byte{dynvcCapability << 4, 0, 0, 0}
		binary.LittleEndian.PutUint16(answer[2:4], min(version, dynvcClientVersion))
		return [][]byte{answer}, nil
	case dynvcCreate:
		id, rest, ok := readDynvcVar(body, dynvcIDBytes(cbID))
		if !ok || !d.capsSeen || len(rest) < 2 || rest[len(rest)-1] != 0 {
			return nil, fmt.Errorf("%w: a malformed create request", ErrRDPDynamicChannel)
		}
		name := rest[:len(rest)-1]
		if len(name) == 0 || len(name) > maxDynvcNameBytes {
			return nil, fmt.Errorf("%w: a %d-byte channel name", ErrRDPDynamicChannel, len(name))
		}
		for _, c := range name {
			if c < 0x20 || c > 0x7e {
				return nil, fmt.Errorf("%w: a channel name outside printable ASCII", ErrRDPDynamicChannel)
			}
		}
		if _, taken := d.open[id]; taken {
			return nil, fmt.Errorf("%w: channel ID %d created twice", ErrRDPDynamicChannel, id)
		}
		status := dynvcCreationRefused
		accepted := false
		if d.allowed[string(name)] {
			accepted = true
			for _, openName := range d.open {
				if openName == string(name) {
					accepted = false // one channel of a name at a time (ADR-0095 §3)
				}
			}
		}
		if accepted {
			status = 0
			d.open[id] = string(name)
		} else {
			d.refusals++
			if len(d.refused) < maxDynvcRefusals {
				d.refused = append(d.refused, string(name))
			}
		}
		answer := appendDynvcID([]byte{dynvcCreate<<4 | cbID}, cbID, id)
		answer = binary.LittleEndian.AppendUint32(answer, status)
		if accepted {
			d.opened = append(d.opened, string(name))
		}
		return [][]byte{answer}, nil
	case dynvcDataFirst, dynvcData:
		id, rest, ok := readDynvcVar(body, dynvcIDBytes(cbID))
		if !ok {
			return nil, fmt.Errorf("%w: a malformed data PDU", ErrRDPDynamicChannel)
		}
		name, isOpen := d.open[id]
		if !isOpen {
			return nil, fmt.Errorf("%w: data on dynamic channel %d, not open", ErrRDPDynamicChannel, id)
		}
		if cmd == dynvcDataFirst {
			if d.assembling[id] != nil {
				return nil, fmt.Errorf("%w: a message started inside another on %q", ErrRDPDynamicChannel, name)
			}
			total, data, ok := readDynvcVar(rest, dynvcIDBytes(sp))
			if !ok || total == 0 || uint64(total) > uint64(dynvcLimit(name)) || len(data) > int(total) {
				return nil, fmt.Errorf("%w: a %d-byte message on %q", ErrRDPDynamicChannel, total, name)
			}
			if len(data) < int(total) {
				d.assembling[id] = &dynvcAssembly{total: int(total), data: append(make([]byte, 0, total), data...)}
				return nil, nil
			}
			return nil, d.deliver(name, data)
		}
		if sp != 0 {
			return nil, fmt.Errorf("%w: a data PDU with Sp %d", ErrRDPDynamicChannel, sp)
		}
		assembly := d.assembling[id]
		if assembly == nil {
			// DATA alone is a whole message.
			if len(rest) == 0 || len(rest) > dynvcLimit(name) {
				return nil, fmt.Errorf("%w: a %d-byte message on %q", ErrRDPDynamicChannel, len(rest), name)
			}
			return nil, d.deliver(name, rest)
		}
		if len(assembly.data)+len(rest) > assembly.total {
			delete(d.assembling, id)
			return nil, fmt.Errorf("%w: data longer than its message on %q", ErrRDPDynamicChannel, name)
		}
		assembly.data = append(assembly.data, rest...)
		if len(assembly.data) < assembly.total {
			return nil, nil
		}
		delete(d.assembling, id)
		return nil, d.deliver(name, assembly.data)
	case dynvcClose:
		id, rest, ok := readDynvcVar(body, dynvcIDBytes(cbID))
		if !ok || len(rest) != 0 {
			return nil, fmt.Errorf("%w: a malformed close", ErrRDPDynamicChannel)
		}
		if _, isOpen := d.open[id]; !isOpen {
			return nil, fmt.Errorf("%w: close of dynamic channel %d, not open", ErrRDPDynamicChannel, id)
		}
		delete(d.open, id)
		delete(d.assembling, id)
		// The client answers a close with its own (MS-RDPEDYC 3.2.5.2).
		return [][]byte{appendDynvcID([]byte{dynvcClose<<4 | cbID}, cbID, id)}, nil
	}
	// Compressed data (6, 7) is not announced; soft-sync (8, 9) belongs to version 3; nothing else is.
	return nil, fmt.Errorf("%w: command %d", ErrRDPDynamicChannel, cmd)
}

func (d *rdpDynamicChannels) deliver(name string, data []byte) error {
	d.delivered = append(d.delivered, dynvcDelivery{name: name, data: data})
	return nil
}

// take returns what handle found to tell, and forgets it.
func (d *rdpDynamicChannels) take() ([]string, []dynvcDelivery) {
	opened, delivered := d.opened, d.delivered
	d.opened, d.delivered = nil, nil
	return opened, delivered
}

// dataPDU is a DATA PDU of data for the open channel named name.
func (d *rdpDynamicChannels) dataPDU(name string, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > maxDynvcSendBytes {
		return nil, fmt.Errorf("%w: a %d-byte message to send", ErrRDPDynamicChannel, len(data))
	}
	for id, openName := range d.open {
		if openName == name {
			cbID := dynvcCbIDFor(id)
			pdu := appendDynvcID([]byte{dynvcData<<4 | cbID}, cbID, id)
			return append(pdu, data...), nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrRDPDynamicChannelClosed, name)
}

// EnableDynamicChannels opens, among the dynamic channels the target proposes on drdynvc, those of
// names, which must be in the closed list (ADR-0095): RDPDisplayControlChannel and RDPGraphicsChannel. onOpen is told
// when a channel opens, onMessage gets each message on it, reassembled; both run on the goroutine
// that reads the screen (ReadBitmapUpdate), and an error from onMessage ends the session. Call it
// after ConnectMCS with DynamicChannels on, and before the screen is read.
func (s *CredSSPClientSession) EnableDynamicChannels(names []string, onOpen func(name string), onMessage func(name string, data []byte) error) error {
	if s == nil || len(names) == 0 {
		return ErrRDPDynamicChannel
	}
	allowed := map[string]bool{}
	for _, name := range names {
		if !rdpDynamicChannelsAllowed[name] {
			return fmt.Errorf("%w: %q is not in the closed list", ErrRDPDynamicChannel, name)
		}
		allowed[name] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.mcsSettings.DynamicChannels || s.dynamicChannels != nil {
		return fmt.Errorf("%w: drdynvc not announced, or dynamic channels already enabled", ErrRDPDynamicChannel)
	}
	dynamic := &rdpDynamicChannels{allowed: allowed, open: map[uint32]string{},
		assembling: map[uint32]*dynvcAssembly{}}
	s.dynamicChannels = dynamic
	if s.channelReaders == nil {
		s.channelReaders = map[string]func([]byte) error{}
	}
	s.channelReaders[RDPChannelDynamic] = func(message []byte) error {
		s.mu.Lock()
		answers, err := dynamic.handle(message)
		opened, delivered := dynamic.take()
		s.mu.Unlock()
		if err != nil {
			return err
		}
		for _, answer := range answers {
			ctx, cancel := context.WithTimeout(context.Background(), defaultCredSSPTimeout)
			sendErr := s.SendChannelMessage(ctx, RDPChannelDynamic, answer, 0)
			cancel()
			if sendErr != nil {
				return sendErr
			}
		}
		for _, name := range opened {
			if onOpen != nil {
				onOpen(name)
			}
		}
		for _, delivery := range delivered {
			if onMessage != nil {
				if err := onMessage(delivery.name, delivery.data); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return nil
}

// SendDynamicChannelMessage sends data, one DATA PDU, on the open dynamic channel named name.
func (s *CredSSPClientSession) SendDynamicChannelMessage(ctx context.Context, name string, data []byte, timeout time.Duration) error {
	if s == nil {
		return ErrRDPDynamicChannel
	}
	s.mu.Lock()
	if s.dynamicChannels == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: dynamic channels not enabled", ErrRDPDynamicChannel)
	}
	pdu, err := s.dynamicChannels.dataPDU(name, data)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.SendChannelMessage(ctx, RDPChannelDynamic, pdu, timeout)
}

// DynamicChannelRefusals are the names of the dynamic channels refused, the first 32, and how many
// were refused in all: what a log says of what the target proposed (ADR-0095 §3, §7).
func (s *CredSSPClientSession) DynamicChannelRefusals() ([]string, int) {
	if s == nil {
		return nil, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dynamicChannels == nil {
		return nil, 0
	}
	return append([]string(nil), s.dynamicChannels.refused...), s.dynamicChannels.refusals
}

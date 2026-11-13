package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The static virtual channels (ADR-0095): a closed list, announced only when a dynamic channel is
// permitted, and one name in it today, drdynvc, which carries the dynamic channels (MS-RDPEDYC).
// Everything a channel brings is untrusted input from the target: bounded, and refused when it does
// not follow the framing of MS-RDPBCGR 2.2.6.1.
const (
	gccClientNetworkType = uint16(0xc003)

	// RDPChannelDynamic is the static channel of the dynamic channels.
	RDPChannelDynamic = "drdynvc"

	rdpChannelOptionInitialized  = uint32(0x80000000)
	rdpChannelOptionEncryptRDP   = uint32(0x40000000)
	rdpChannelOptionShowProtocol = uint32(0x00200000)

	rdpChannelFlagFirst        = uint32(0x00000001)
	rdpChannelFlagLast         = uint32(0x00000002)
	rdpChannelFlagShowProtocol = uint32(0x00000010)

	// rdpChannelChunkLength is CHANNEL_CHUNK_LENGTH, the chunk size every peer accepts: this client
	// sends no larger chunk, whatever the server announces.
	rdpChannelChunkLength = 1600

	// MaxRDPChannelMessage bounds a channel message reassembled from its chunks (ADR-0095 §2).
	MaxRDPChannelMessage = 64 << 10

	// rdpCapVirtualChannel is TS_VIRTUALCHANNEL_CAPABILITYSET, sent when a channel is announced.
	rdpCapVirtualChannel = uint16(0x0014)

	// maxRDPChannelPending bounds the channel packets that arrive before the screen is read (during
	// the connection's finalization) and are kept for it.
	maxRDPChannelPending = 16
)

// ErrRDPChannel reports virtual channel data that does not follow the framing, the bounds or the
// closed list of ADR-0095: the session ends.
var ErrRDPChannel = errors.New("rdp: virtual channel data refused")

// rdpStaticChannelNames is the closed list of the channels this client announces, in order.
func rdpStaticChannelNames(settings MCSClientSettings) []string {
	var names []string
	if settings.DynamicChannels {
		names = append(names, RDPChannelDynamic)
	}
	if settings.ClipboardChannel {
		names = append(names, RDPChannelClipboard) // ADR-0096
	}
	return names
}

// marshalClientNetworkData is TS_UD_CS_NET's payload: channelCount, then each CHANNEL_DEF (an
// 8-byte name, NUL-terminated, and its options).
func marshalClientNetworkData(names []string) ([]byte, error) {
	if len(names) == 0 || len(names) > 2 {
		return nil, ErrMCSConnection
	}
	out := make([]byte, 4+12*len(names))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(names)))
	for i, name := range names {
		if len(name) == 0 || len(name) > 7 {
			return nil, ErrMCSConnection
		}
		def := out[4+12*i : 4+12*(i+1)]
		copy(def[:8], name)
		options := rdpChannelOptionInitialized | rdpChannelOptionEncryptRDP
		if rdpChannelShowsProtocol(name) {
			options |= rdpChannelOptionShowProtocol
		}
		binary.LittleEndian.PutUint32(def[8:12], options)
	}
	return out, nil
}

// rdpChannelShowsProtocol says whether the application at the server's end of a channel reads its
// CHANNEL_PDU_HEADER. The clipboard's does: Windows's rdpclip answers nothing (not even the format
// list response) to chunks without CHANNEL_FLAG_SHOW_PROTOCOL, and mstsc and FreeRDP announce
// cliprdr with CHANNEL_OPTION_SHOW_PROTOCOL and set the flag on its every chunk. The server ignores
// the option (MS-RDPBCGR 2.2.1.3.4.1): the flag on each chunk is what counts.
func rdpChannelShowsProtocol(name string) bool {
	return name == RDPChannelClipboard
}

// parseServerNetworkData reads TS_UD_SC_NET's payload: the I/O channel, then exactly one channel ID
// per announced channel, each distinct and none the I/O channel, then the padding an odd count
// calls for.
func parseServerNetworkData(payload []byte, announced int) (uint16, []uint16, error) {
	want := 4 + 2*announced
	if announced%2 == 1 {
		want += 2
	}
	if len(payload) != want || binary.LittleEndian.Uint16(payload[:2]) != mcsGlobalChannelID ||
		int(binary.LittleEndian.Uint16(payload[2:4])) != announced {
		return 0, nil, fmt.Errorf("%w: unsupported GCC SC_NET channels", ErrMCSConnection)
	}
	var ids []uint16
	for i := 0; i < announced; i++ {
		id := binary.LittleEndian.Uint16(payload[4+2*i : 6+2*i])
		if id == mcsGlobalChannelID || id == 0 {
			return 0, nil, fmt.Errorf("%w: GCC SC_NET channel ID %d", ErrMCSConnection, id)
		}
		for _, seen := range ids {
			if seen == id {
				return 0, nil, fmt.Errorf("%w: GCC SC_NET channel ID %d twice", ErrMCSConnection, id)
			}
		}
		ids = append(ids, id)
	}
	return mcsGlobalChannelID, ids, nil
}

// rdpChannelAssembler reassembles one channel's message from its chunks: CHANNEL_PDU_HEADER (the
// whole message's length, and its flags), then the chunk's data. FIRST opens a message, LAST
// closes it; the length is the same in every chunk, and the data adds up to it exactly.
type rdpChannelAssembler struct {
	total int
	data  []byte
	open  bool
}

func (a *rdpChannelAssembler) add(chunk []byte) ([]byte, bool, error) {
	if len(chunk) < 8 {
		return nil, false, fmt.Errorf("%w: a chunk shorter than its header", ErrRDPChannel)
	}
	total := binary.LittleEndian.Uint32(chunk[:4])
	flags := binary.LittleEndian.Uint32(chunk[4:8])
	data := chunk[8:]
	// Compression is not announced; suspend, resume and the rest mean nothing this client does.
	if flags&^(rdpChannelFlagFirst|rdpChannelFlagLast|rdpChannelFlagShowProtocol) != 0 {
		return nil, false, fmt.Errorf("%w: chunk flags 0x%08x", ErrRDPChannel, flags)
	}
	if total == 0 || total > MaxRDPChannelMessage {
		return nil, false, fmt.Errorf("%w: a %d-byte message", ErrRDPChannel, total)
	}
	if flags&rdpChannelFlagFirst != 0 {
		if a.open {
			return nil, false, fmt.Errorf("%w: a message started inside another", ErrRDPChannel)
		}
		a.total, a.data, a.open = int(total), make([]byte, 0, total), true
	} else if !a.open || int(total) != a.total {
		return nil, false, fmt.Errorf("%w: a chunk outside its message", ErrRDPChannel)
	}
	if len(a.data)+len(data) > a.total {
		a.reset()
		return nil, false, fmt.Errorf("%w: chunks longer than their message", ErrRDPChannel)
	}
	a.data = append(a.data, data...)
	if flags&rdpChannelFlagLast == 0 {
		return nil, false, nil
	}
	if len(a.data) != a.total {
		a.reset()
		return nil, false, fmt.Errorf("%w: a message shorter than announced", ErrRDPChannel)
	}
	message := a.data
	a.total, a.data, a.open = 0, nil, false
	return message, true, nil
}

func (a *rdpChannelAssembler) reset() {
	clear(a.data)
	a.total, a.data, a.open = 0, nil, false
}

// marshalRDPChannelChunks cuts a message into chunks of rdpChannelChunkLength at most, each with
// its CHANNEL_PDU_HEADER; showProtocol sets CHANNEL_FLAG_SHOW_PROTOCOL on every one.
func marshalRDPChannelChunks(message []byte, showProtocol bool) ([][]byte, error) {
	if len(message) == 0 || len(message) > MaxRDPChannelMessage {
		return nil, fmt.Errorf("%w: a %d-byte message to send", ErrRDPChannel, len(message))
	}
	var chunks [][]byte
	for offset := 0; offset < len(message); offset += rdpChannelChunkLength {
		end := min(offset+rdpChannelChunkLength, len(message))
		flags := uint32(0)
		if showProtocol {
			flags |= rdpChannelFlagShowProtocol
		}
		if offset == 0 {
			flags |= rdpChannelFlagFirst
		}
		if end == len(message) {
			flags |= rdpChannelFlagLast
		}
		chunk := make([]byte, 8+end-offset)
		binary.LittleEndian.PutUint32(chunk[:4], uint32(len(message)))
		binary.LittleEndian.PutUint32(chunk[4:8], flags)
		copy(chunk[8:], message[offset:end])
		chunks = append(chunks, chunk)
	}
	return chunks, nil
}

// rdpChannelPacket reads a TPKT packet as an MCS Send Data Indication on one of channels, the
// static channels joined: the channel's index and the chunk it carries. ok is false for any other
// packet, which the caller reads as it did before. A Send Data Indication on a channel neither the
// I/O channel nor a joined one is refused: data on a channel this client did not join (ADR-0095 §2).
func rdpChannelPacket(packet []byte, channels []uint16) (index int, chunk []byte, ok bool, err error) {
	if len(packet) < 7+7 || packet[0] != 3 || packet[1] != 0 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || !equalBytes(packet[4:7], []byte{2, 0xf0, 0x80}) {
		return 0, nil, false, nil
	}
	mcs := packet[7:]
	if mcs[0] != mcsSendDataIndication {
		return 0, nil, false, nil
	}
	channelID := binary.BigEndian.Uint16(mcs[3:5])
	if channelID == mcsGlobalChannelID {
		return 0, nil, false, nil
	}
	index = -1
	for i, id := range channels {
		if id == channelID {
			index = i
		}
	}
	if index < 0 {
		return 0, nil, false, fmt.Errorf("%w: data on channel %d, not joined", ErrRDPChannel, channelID)
	}
	// A channel chunk is one MCS segment: begin and end both set, the reserved bits clear.
	if mcs[5]&0x0f != 0 || (mcs[5]>>4)&0x03 != 0x03 {
		return 0, nil, false, fmt.Errorf("%w: an MCS-segmented chunk on channel %d", ErrRDPChannel, channelID)
	}
	length, userData, perErr := readPERLength(mcs[6:])
	if perErr != nil || length == 0 || length != len(userData) {
		return 0, nil, false, fmt.Errorf("%w: a malformed chunk on channel %d", ErrRDPChannel, channelID)
	}
	return index, userData, true, nil
}

// SetChannelHandler names who reads the static channels' messages: handler gets each message,
// reassembled, on the goroutine that reads the screen (ReadBitmapUpdate), and an error from it ends
// the session. Without a handler, a message is dropped. The message is the caller's only until
// handler returns.
func (s *CredSSPClientSession) SetChannelHandler(handler func(channel string, message []byte) error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.channelHandler = handler
	s.mu.Unlock()
}

// StaticChannels are the static channels joined, by name, in the order announced: none unless
// MCSClientSettings.DynamicChannels was on and the server gave each an ID.
func (s *CredSSPClientSession) StaticChannels() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.channelsConnected || len(s.mcsResponse.StaticChannelIDs) == 0 {
		return nil
	}
	return rdpStaticChannelNames(s.mcsSettings)
}

// takePendingChannelPacket returns the next channel packet kept during the finalization, or nil.
func (s *CredSSPClientSession) takePendingChannelPacket() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pendingChannelPackets) == 0 {
		return nil
	}
	packet := s.pendingChannelPackets[0]
	s.pendingChannelPackets = s.pendingChannelPackets[1:]
	return packet
}

// deliverChannelChunk adds one chunk to its channel's message, and hands a complete message to the
// handler. readMu is held, s.mu is not.
func (s *CredSSPClientSession) deliverChannelChunk(index int, chunk []byte) error {
	s.mu.Lock()
	names := rdpStaticChannelNames(s.mcsSettings)
	if index < 0 || index >= len(s.channelAssemblers) || index >= len(names) {
		s.mu.Unlock()
		return fmt.Errorf("%w: a chunk for no channel", ErrRDPChannel)
	}
	message, complete, err := s.channelAssemblers[index].add(chunk)
	reader, handler := s.channelReaders[names[index]], s.channelHandler
	s.mu.Unlock()
	if err != nil || !complete {
		return err
	}
	defer clear(message)
	if reader != nil {
		return reader(message)
	}
	if handler == nil {
		return nil
	}
	return handler(names[index], message)
}

// readChannelPacket hands packet to its channel when it is a static channel's: ok says it was one.
func (s *CredSSPClientSession) readChannelPacket(packet []byte, channels []uint16) (ok bool, err error) {
	if len(channels) == 0 {
		return false, nil
	}
	index, chunk, ok, err := rdpChannelPacket(packet, channels)
	if err != nil || !ok {
		return false, err
	}
	return true, s.deliverChannelChunk(index, chunk)
}

// SendChannelMessage sends message on the static channel named channel, in chunks of 1600 bytes
// at most, once the channels are joined. Only a joined channel of the closed list is one.
func (s *CredSSPClientSession) SendChannelMessage(ctx context.Context, channel string, message []byte, timeout time.Duration) (err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || timeout < 0 {
		return ErrMCSConnection
	}
	chunks, err := marshalRDPChannelChunks(message, rdpChannelShowsProtocol(channel))
	if err != nil {
		return err
	}
	defer func() {
		for _, chunk := range chunks {
			clear(chunk)
		}
	}()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	channelID := uint16(0)
	for i, name := range rdpStaticChannelNames(s.mcsSettings) {
		if name == channel && i < len(s.mcsResponse.StaticChannelIDs) {
			channelID = s.mcsResponse.StaticChannelIDs[i]
		}
	}
	// The channels belong to the MCS connection, not to the share: joined, they carry messages
	// while a reactivation replaces the share (Windows Server 2019 reactivates at a resize).
	if channelID == 0 || s.transport == nil || s.transport.Conn == nil || !s.channelsConnected ||
		!validMCSUserID(s.userChannelID) || !s.transport.Conn.ConnectionState().HandshakeComplete {
		s.mu.Unlock()
		return fmt.Errorf("%w: no channel %q to send on", ErrRDPChannel, channel)
	}
	conn, userID := s.transport.Conn, s.userChannelID
	s.mu.Unlock()

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
		if err != nil || ctx.Err() != nil || !cancelStopped || conn.SetWriteDeadline(time.Time{}) != nil {
			s.mu.Lock()
			s.closeTransportLocked()
			s.mu.Unlock()
			err = ErrMCSConnection
		}
	}()
	for _, chunk := range chunks {
		packet, buildErr := marshalMCSSendDataRequestOn(userID, channelID, chunk)
		if buildErr != nil {
			return buildErr
		}
		writeErr := writeFull(conn, packet)
		clear(packet)
		if writeErr != nil || ctx.Err() != nil {
			return ErrMCSConnection
		}
	}
	return nil
}

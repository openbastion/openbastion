package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// The static channels of ADR-0095: announced only when asked, the closed list, the framing bounded.

func TestConnectInitial_AnnouncesDrdynvcOnlyWhenDynamicChannelsAreOn(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion"}
	off, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := connectInitialBlocks(off)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range blocks {
		if block.kind == gccClientNetworkType {
			t.Fatal("CS_NET announced with DynamicChannels off: the connection must stay as it was")
		}
	}
	settings.DynamicChannels = true
	on, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err = connectInitialBlocks(on)
	if err != nil {
		t.Fatal(err)
	}
	var network []byte
	for _, block := range blocks {
		if block.kind == gccClientNetworkType {
			network = block.payload
		}
	}
	want := make([]byte, 16)
	binary.LittleEndian.PutUint32(want[:4], 1)
	copy(want[4:12], "drdynvc")
	binary.LittleEndian.PutUint32(want[12:16], 0xc0000000)
	if !bytes.Equal(network, want) {
		t.Fatalf("CS_NET = %x, want %x: one channel, drdynvc, initialized", network, want)
	}
}

func TestMarshalClientNetworkData_KeepsToTheClosedList(t *testing.T) {
	for _, names := range [][]string{nil, {""}, {"toolongname"}, {"drdynvc", "cliprdr"}} {
		if _, err := marshalClientNetworkData(names); err == nil {
			t.Errorf("%q announced", names)
		}
	}
}

func serverNetwork(io uint16, ids ...uint16) []byte {
	out := binary.LittleEndian.AppendUint16(nil, io)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(ids)))
	for _, id := range ids {
		out = binary.LittleEndian.AppendUint16(out, id)
	}
	if len(ids)%2 == 1 {
		out = append(out, 0, 0)
	}
	return out
}

func TestParseServerNetworkData_OneIDForEachChannelAnnounced(t *testing.T) {
	io, ids, err := parseServerNetworkData(serverNetwork(1003, 1004), 1)
	if err != nil || io != 1003 || len(ids) != 1 || ids[0] != 1004 {
		t.Fatalf("got %d %v %v, want 1003 [1004]", io, ids, err)
	}
	if _, ids, err := parseServerNetworkData(serverNetwork(1003), 0); err != nil || ids != nil {
		t.Fatalf("no channel announced, none given: %v %v", ids, err)
	}
	for name, c := range map[string]struct {
		payload   []byte
		announced int
	}{
		"a channel given that was not announced": {serverNetwork(1003, 1004), 0},
		"no channel given for the one announced": {serverNetwork(1003), 1},
		"the padding missing":                    {serverNetwork(1003, 1004)[:6], 1},
		"the I/O channel given as a static one":  {serverNetwork(1003, 1003), 1},
		"channel 0":                              {serverNetwork(1003, 0), 1},
		"another I/O channel":                    {serverNetwork(1005, 1004), 1},
		"two channels for one":                   {serverNetwork(1003, 1004, 1005), 1},
	} {
		if _, _, err := parseServerNetworkData(c.payload, c.announced); !errors.Is(err, ErrMCSConnection) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestParseServerNetworkData_RefusesTheSameIDTwice(t *testing.T) {
	// Two channels are not announced today; the check stands for when the list grows.
	if _, _, err := parseServerNetworkData(serverNetwork(1003, 1004, 1004), 2); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("the same ID twice: %v", err)
	}
}

func chunk(total, flags uint32, data []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, total)
	out = binary.LittleEndian.AppendUint32(out, flags)
	return append(out, data...)
}

func TestChannelAssembler_ReassemblesWithinTheBounds(t *testing.T) {
	var a rdpChannelAssembler
	message, complete, err := a.add(chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast|rdpChannelFlagShowProtocol, []byte("abc")))
	if err != nil || !complete || string(message) != "abc" {
		t.Fatalf("one chunk: %q %v %v", message, complete, err)
	}
	if _, complete, err := a.add(chunk(5, rdpChannelFlagFirst, []byte("ab"))); err != nil || complete {
		t.Fatalf("first of two: %v %v", complete, err)
	}
	message, complete, err = a.add(chunk(5, rdpChannelFlagLast, []byte("cde")))
	if err != nil || !complete || string(message) != "abcde" {
		t.Fatalf("last of two: %q %v %v", message, complete, err)
	}
	if _, _, err := a.add(chunk(MaxRDPChannelMessage, rdpChannelFlagFirst, nil)); err != nil {
		t.Fatalf("a message of exactly the bound: %v", err)
	}
}

func TestChannelAssembler_RefusesWhatTheFramingForbids(t *testing.T) {
	cases := map[string][][]byte{
		"a header cut short":           {{1, 0, 0, 0, 3}},
		"a chunk with no message open": {chunk(3, rdpChannelFlagLast, []byte("abc"))},
		"a message inside another":     {chunk(5, rdpChannelFlagFirst, []byte("ab")), chunk(5, rdpChannelFlagFirst, []byte("ab"))},
		"the length changed":           {chunk(5, rdpChannelFlagFirst, []byte("ab")), chunk(6, rdpChannelFlagLast, []byte("cde"))},
		"longer than announced":        {chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("abcd"))},
		"shorter than announced":       {chunk(5, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("abc"))},
		"compressed":                   {chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast|0x00200000, []byte("abc"))},
		"suspend":                      {chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast|0x20, []byte("abc"))},
		"an empty message":             {chunk(0, rdpChannelFlagFirst|rdpChannelFlagLast, nil)},
		"past 64 KiB":                  {chunk(MaxRDPChannelMessage+1, rdpChannelFlagFirst, nil)},
	}
	for name, chunks := range cases {
		var a rdpChannelAssembler
		var err error
		for _, c := range chunks {
			if _, _, err = a.add(c); err != nil {
				break
			}
		}
		if !errors.Is(err, ErrRDPChannel) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestMarshalRDPChannelChunks_CutsAt1600AndRoundTrips(t *testing.T) {
	message := bytes.Repeat([]byte{0x5a}, 2*rdpChannelChunkLength+7)
	chunks, err := marshalRDPChannelChunks(message)
	if err != nil || len(chunks) != 3 {
		t.Fatalf("%d chunks, %v; want 3", len(chunks), err)
	}
	wantFlags := []uint32{rdpChannelFlagFirst, 0, rdpChannelFlagLast}
	var a rdpChannelAssembler
	for i, c := range chunks {
		if len(c)-8 > rdpChannelChunkLength || binary.LittleEndian.Uint32(c[4:8]) != wantFlags[i] ||
			int(binary.LittleEndian.Uint32(c[:4])) != len(message) {
			t.Fatalf("chunk %d: %d bytes, flags %x", i, len(c)-8, binary.LittleEndian.Uint32(c[4:8]))
		}
		got, complete, err := a.add(c)
		if err != nil || complete != (i == 2) || (complete && !bytes.Equal(got, message)) {
			t.Fatalf("chunk %d back: %v %v", i, complete, err)
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, MaxRDPChannelMessage+1)} {
		if _, err := marshalRDPChannelChunks(bad); !errors.Is(err, ErrRDPChannel) {
			t.Errorf("a %d-byte message cut: %v", len(bad), err)
		}
	}
}

// channelIndication is an MCS Send Data Indication of chunk on channelID; segmentation is its
// begin/end bits.
func channelIndication(channelID uint16, segmentation byte, data []byte) []byte {
	mcs := []byte{mcsSendDataIndication, 0, 1, byte(channelID >> 8), byte(channelID), segmentation << 4}
	mcs = appendPERLength(mcs, len(data))
	mcs = append(mcs, data...)
	packet := make([]byte, 7+len(mcs))
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
}

func TestRDPChannelPacket_RoutesTheJoinedChannelAndRefusesAnyOther(t *testing.T) {
	data := chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("abc"))
	index, got, ok, err := rdpChannelPacket(channelIndication(1004, 3, data), []uint16{1004})
	if err != nil || !ok || index != 0 || !bytes.Equal(got, data) {
		t.Fatalf("on the joined channel: %d %v %v", index, ok, err)
	}
	if _, _, ok, err := rdpChannelPacket(channelIndication(1003, 3, data), []uint16{1004}); ok || err != nil {
		t.Fatalf("the I/O channel is the screen's: %v %v", ok, err)
	}
	if _, _, ok, err := rdpChannelPacket([]byte{3, 0, 0, 4}, []uint16{1004}); ok || err != nil {
		t.Fatalf("not a Send Data Indication: %v %v", ok, err)
	}
	if _, _, _, err := rdpChannelPacket(channelIndication(1005, 3, data), []uint16{1004}); !errors.Is(err, ErrRDPChannel) {
		t.Fatalf("a channel not joined: %v", err)
	}
	if _, _, _, err := rdpChannelPacket(channelIndication(1005, 3, data), nil); !errors.Is(err, ErrRDPChannel) {
		t.Fatalf("a channel, none joined: %v", err)
	}
	if _, _, _, err := rdpChannelPacket(channelIndication(1004, 2, data), []uint16{1004}); !errors.Is(err, ErrRDPChannel) {
		t.Fatalf("an MCS-segmented chunk: %v", err)
	}
}

func TestSessionDeliversAChannelMessageToItsHandler(t *testing.T) {
	s := &CredSSPClientSession{mcsSettings: MCSClientSettings{DynamicChannels: true},
		mcsResponse: MCSConnectResponse{IOChannelID: 1003, StaticChannelIDs: []uint16{1004}}, channelsConnected: true,
		channelAssemblers: make([]rdpChannelAssembler, 1)}
	var got []string
	s.SetChannelHandler(func(channel string, message []byte) error {
		got = append(got, channel+":"+string(message))
		return nil
	})
	for _, c := range [][]byte{chunk(5, rdpChannelFlagFirst, []byte("he")), chunk(5, rdpChannelFlagLast, []byte("llo"))} {
		if ok, err := s.readChannelPacket(channelIndication(1004, 3, c), s.mcsResponse.StaticChannelIDs); !ok || err != nil {
			t.Fatalf("%v %v", ok, err)
		}
	}
	if len(got) != 1 || got[0] != "drdynvc:hello" {
		t.Fatalf("handler got %q, want one drdynvc message", got)
	}
	if names := s.StaticChannels(); len(names) != 1 || names[0] != RDPChannelDynamic {
		t.Fatalf("StaticChannels() = %q", names)
	}
	refused := errors.New("refused")
	s.SetChannelHandler(func(string, []byte) error { return refused })
	if _, err := s.readChannelPacket(channelIndication(1004, 3, chunk(1, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("x"))), []uint16{1004}); !errors.Is(err, refused) {
		t.Fatalf("the handler's refusal ends the read: %v", err)
	}
}

// finalizationPeer reads what the client writes and answers with packets, in order.
type finalizationPeer struct {
	in io.Reader
}

func (p *finalizationPeer) Read(b []byte) (int, error)  { return p.in.Read(b) }
func (p *finalizationPeer) Write(b []byte) (int, error) { return len(b), nil }

func finalizationAnswers(extra map[int][][]byte) io.Reader {
	answers := [][]byte{
		mcsTestFinalizationResponse(0x000103ea, rdpPDU2Synchronize, 0, []byte{1, 0, 0, 0}),
		mcsTestFinalizationResponse(0x000103ea, rdpPDU2Control, 2, []byte{4, 0, 0, 0, 0, 0, 0, 0}),
		mcsTestFinalizationResponse(0x000103ea, rdpPDU2Control, 2, []byte{2, 0, 0xef, 0x03, 0xea, 0x03, 0, 0}),
		mcsTestFinalizationResponse(0x000103ea, rdpPDU2FontMap, 2, []byte{0, 0, 0, 0, 3, 0, 4, 0}),
	}
	var out bytes.Buffer
	for i, answer := range answers {
		for _, packet := range extra[i] {
			out.Write(packet)
		}
		out.Write(answer)
	}
	return &out
}

func TestFinalization_KeepsTheChannelPacketsThatComeBetweenTheAnswers(t *testing.T) {
	caps := channelIndication(1004, 3, chunk(4, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("caps")))
	peer := &finalizationPeer{in: finalizationAnswers(map[int][][]byte{1: {caps}, 3: {caps, caps}})}
	result, pending, err := finalizeRDPConnection(context.Background(), peer, 1003, 0x000103ea, 1007, []uint16{1004})
	if err != nil || !result.ControlGranted || len(pending) != 3 {
		t.Fatalf("finalization: %v, %d packet(s) kept, want 3", err, len(pending))
	}
	peer = &finalizationPeer{in: finalizationAnswers(map[int][][]byte{1: {caps}})}
	if _, _, err := finalizeRDPConnection(context.Background(), peer, 1003, 0x000103ea, 1007, nil); err == nil {
		t.Fatal("a channel packet with no channel joined was taken")
	}
	other := channelIndication(1005, 3, chunk(1, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("x")))
	peer = &finalizationPeer{in: finalizationAnswers(map[int][][]byte{2: {other}})}
	if _, _, err := finalizeRDPConnection(context.Background(), peer, 1003, 0x000103ea, 1007, []uint16{1004}); err == nil {
		t.Fatal("a packet on a channel not joined was taken")
	}
	flood := make([][]byte, maxRDPChannelPending+1)
	for i := range flood {
		flood[i] = caps
	}
	peer = &finalizationPeer{in: finalizationAnswers(map[int][][]byte{0: flood})}
	if _, _, err := finalizeRDPConnection(context.Background(), peer, 1003, 0x000103ea, 1007, []uint16{1004}); err == nil {
		t.Fatalf("%d channel packets kept, past the bound of %d", len(flood), maxRDPChannelPending)
	}
}

func TestConfirmActive_AnnouncesTheVirtualChannelSetOnlyWithAChannel(t *testing.T) {
	for _, on := range []bool{false, true} {
		settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, DynamicChannels: on}
		caps := marshalRDPClientCapabilitySets(settings, 32)
		found := false
		for rest := caps; len(rest) >= 4; {
			length := int(binary.LittleEndian.Uint16(rest[2:4]))
			if binary.LittleEndian.Uint16(rest[:2]) == rdpCapVirtualChannel {
				found = length == 8 && binary.LittleEndian.Uint32(rest[4:8]) == 0
			}
			rest = rest[length:]
		}
		want := uint16(rdpClientCapabilitySetCount)
		if on {
			want++
		}
		if found != on || rdpClientCapabilitySetCountFor(settings) != want {
			t.Fatalf("DynamicChannels %v: virtual channel set %v, %d sets", on, found, rdpClientCapabilitySetCountFor(settings))
		}
	}
}

func FuzzRDPChannelAssembler(f *testing.F) {
	f.Add(chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("abc")), chunk(3, rdpChannelFlagLast, []byte("abc")))
	f.Add(chunk(5, rdpChannelFlagFirst, []byte("ab")), chunk(5, rdpChannelFlagLast, []byte("cde")))
	f.Fuzz(func(t *testing.T, first, second []byte) {
		var a rdpChannelAssembler
		for _, c := range [][]byte{first, second} {
			message, complete, err := a.add(c)
			if err == nil && complete && (len(message) == 0 || len(message) > MaxRDPChannelMessage) {
				t.Fatalf("a %d-byte message taken", len(message))
			}
		}
	})
}

func FuzzRDPChannelPacket(f *testing.F) {
	f.Add(channelIndication(1004, 3, chunk(3, rdpChannelFlagFirst|rdpChannelFlagLast, []byte("abc"))))
	f.Fuzz(func(t *testing.T, packet []byte) {
		index, data, ok, err := rdpChannelPacket(packet, []uint16{1004})
		if ok && (err != nil || index != 0 || len(data) == 0) {
			t.Fatalf("%d %d %v", index, len(data), err)
		}
	})
}

package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// The graphics pipeline of ADR-0101, increment 1: the capabilities advertised, the confirmation
// checked, the PDUs read and bounded; the early capability and the channel's place in the closed
// list.

func graphicsPDU(command uint16, body []byte) []byte { return marshalGraphicsPDU(command, body) }

func capsConfirm(version, flags uint32) []byte {
	body := binary.LittleEndian.AppendUint32(nil, version)
	body = binary.LittleEndian.AppendUint32(body, 4)
	body = binary.LittleEndian.AppendUint32(body, flags)
	return graphicsPDU(rdpGraphicsCapsConfirm, body)
}

// unencoded is one message of the channel, a single segment, not compressed.
func unencoded(pdus ...[]byte) []byte {
	return single(append([]byte{zgfxTypeRDP8}, bytes.Join(pdus, nil)...))
}

func TestGraphics_TheAdvertisedCapabilities(t *testing.T) {
	got := NewRDPGraphicsPipeline().CapsAdvertise()
	// The spec's values (MS-RDPEGFX 2.2.3), copied apart from the client's table.
	want := []struct{ version, flags uint32 }{
		{0x000a0701, 0x20 | 0x02 | 0x80}, {0x000a0600, 0x22}, {0x000a0502, 0x22}, {0x000a0400, 0x22},
		{0x000a0200, 0x22}, {0x000a0002, 0x22}, {0x00080105, 0x02}, {0x00080004, 0x02},
	}
	if len(got) != 10+12*len(want) || binary.LittleEndian.Uint16(got[0:2]) != 0x0012 ||
		binary.LittleEndian.Uint16(got[2:4]) != 0 || int(binary.LittleEndian.Uint32(got[4:8])) != len(got) ||
		int(binary.LittleEndian.Uint16(got[8:10])) != len(want) {
		t.Fatalf("CAPS_ADVERTISE header: % x", got[:min(len(got), 10)])
	}
	for i, set := range want {
		at := got[10+12*i:]
		if binary.LittleEndian.Uint32(at[0:4]) != set.version || binary.LittleEndian.Uint32(at[4:8]) != 4 ||
			binary.LittleEndian.Uint32(at[8:12]) != set.flags {
			t.Fatalf("set %d: % x, want version 0x%08x flags 0x%08x", i, at[:12], set.version, set.flags)
		}
	}
	// Every set from version 10 keeps H.264 out; none leaves the 16 MB cache.
	for _, set := range rdpGraphicsAdvertised {
		if set.Flags&rdpGraphicsCapsSmallCache == 0 || (set.Version >= rdpGraphicsCapVersion10 && set.Flags&rdpGraphicsCapsAVCDisabled == 0) {
			t.Fatalf("set 0x%08x advertised with flags 0x%08x", set.Version, set.Flags)
		}
	}
}

func TestGraphics_TheConfirmationThenThePDUs(t *testing.T) {
	p := NewRDPGraphicsPipeline()
	if _, ok := p.Confirmed(); ok {
		t.Fatal("confirmed before anything was read")
	}
	reset := graphicsPDU(RDPGraphicsResetGraphics, make([]byte, 332))
	start := graphicsPDU(RDPGraphicsStartFrame, make([]byte, 8))
	// One message may hold the confirmation and what follows it.
	pdus, err := p.Read(unencoded(capsConfirm(0x000a0701, 0xa2), reset, start))
	if err != nil {
		t.Fatal(err)
	}
	if set, ok := p.Confirmed(); !ok || set.Version != 0x000a0701 || set.Flags != 0xa2 {
		t.Fatalf("confirmed %+v, %v", set, ok)
	}
	if len(pdus) != 2 || pdus[0].Command != RDPGraphicsResetGraphics || len(pdus[0].Body) != 332 ||
		pdus[1].Command != RDPGraphicsStartFrame || len(pdus[1].Body) != 8 {
		t.Fatalf("PDUs: %+v", pdus)
	}
	// Compressed: the same bytes, through the history.
	var w zgfxWriter
	for _, c := range graphicsPDU(RDPGraphicsEndFrame, []byte{1, 0, 0, 0}) {
		w.literal(c)
	}
	pdus, err = p.Read(single(w.segment()))
	if err != nil || len(pdus) != 1 || pdus[0].Command != RDPGraphicsEndFrame || !bytes.Equal(pdus[0].Body, []byte{1, 0, 0, 0}) {
		t.Fatalf("compressed END_FRAME: %+v, %v", pdus, err)
	}
	for version, flags := range map[uint32]uint32{0x000a0600: 0x22, 0x00080004: 0x02, 0x00080105: 0x02, 0x000a0002: 0x22} {
		if _, err := NewRDPGraphicsPipeline().Read(unencoded(capsConfirm(version, flags))); err != nil {
			t.Fatalf("version 0x%08x: %v", version, err)
		}
	}
}

func TestGraphics_RefusesWhatATargetMayNotSend(t *testing.T) {
	confirmed := capsConfirm(0x000a0600, 0x22)
	frame := graphicsPDU(RDPGraphicsStartFrame, make([]byte, 8))
	longConfirm := append(capsConfirm(0x000a0600, 0x22), 0)
	binary.LittleEndian.PutUint32(longConfirm[4:8], uint32(len(longConfirm)))
	flagged := graphicsPDU(RDPGraphicsStartFrame, make([]byte, 8))
	flagged[2] = 1
	long := graphicsPDU(RDPGraphicsStartFrame, make([]byte, 8))
	binary.LittleEndian.PutUint32(long[4:8], 17)
	short := graphicsPDU(RDPGraphicsStartFrame, nil)
	binary.LittleEndian.PutUint32(short[4:8], 7)
	for name, message := range map[string][]byte{
		"a PDU before the confirmation":         unencoded(frame),
		"a second confirmation":                 unencoded(confirmed, confirmed),
		"version 10.1, not advertised":          unencoded(capsConfirm(0x000a0100, 0)),
		"version 10.3, not advertised":          unencoded(capsConfirm(0x000a0301, 0x20)),
		"H.264 left on":                         unencoded(capsConfirm(0x000a0600, 0x02)),
		"the 100 MB cache":                      unencoded(capsConfirm(0x000a0600, 0x20)),
		"AVC420 asked in 8.1":                   unencoded(capsConfirm(0x00080105, 0x12)),
		"scaled mappings left on":               unencoded(capsConfirm(0x000a0701, 0x22)),
		"a confirmation of 13 bytes":            unencoded(longConfirm),
		"a frame acknowledgement, the client's": unencoded(confirmed, graphicsPDU(rdpGraphicsFrameAcknowledge, make([]byte, 12))),
		"a capabilities advertisement":          unencoded(confirmed, NewRDPGraphicsPipeline().CapsAdvertise()),
		"a cache import offer":                  unencoded(confirmed, graphicsPDU(rdpGraphicsCacheImportOffer, make([]byte, 2))),
		"a QoE acknowledgement":                 unencoded(confirmed, graphicsPDU(rdpGraphicsQoEFrameAcknowledge, make([]byte, 12))),
		"command 0x0014":                        unencoded(confirmed, graphicsPDU(0x0014, nil)),
		"command 0x0019":                        unencoded(confirmed, graphicsPDU(0x0019, nil)),
		"header flags":                          unencoded(confirmed, flagged),
		"a length past the message":             unencoded(confirmed, long),
		"a length under the header":             unencoded(confirmed, short),
		"a header cut short":                    unencoded(confirmed, []byte{0x0b, 0, 0, 0}),
		"not segmented":                         confirmed,
	} {
		if _, err := NewRDPGraphicsPipeline().Read(message); !errors.Is(err, ErrRDPGraphics) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGraphics_TheEarlyCapability(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", DynamicChannels: true}
	early := func(s MCSClientSettings) uint16 {
		blocks, err := marshalClientDataBlocks(s)
		if err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint16(blocks[4+140 : 4+142])
	}
	if got := early(settings); got != rdpClientErrInfo|rdpClientWant32BPP {
		t.Fatalf("off: 0x%04x", got)
	}
	settings.GraphicsPipeline = true
	if got := early(settings); got != rdpClientErrInfo|rdpClientWant32BPP|0x0100 {
		t.Fatalf("on: 0x%04x, want RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL (0x0100) added", got)
	}
	if _, err := MarshalMCSConnectInitial(settings); err != nil {
		t.Fatal(err)
	}
	settings.DynamicChannels = false
	if _, err := MarshalMCSConnectInitial(settings); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("the pipeline without drdynvc: %v", err)
	}
}

// The channel opens from the closed list, and its messages may be larger than another channel's.
func TestGraphics_TheChannelAndItsBound(t *testing.T) {
	d := &rdpDynamicChannels{allowed: map[string]bool{RDPGraphicsChannel: true, RDPDisplayControlChannel: true},
		open: map[uint32]string{}, assembling: map[uint32]*dynvcAssembly{}}
	mustHandle(t, d, capsRequest(2))
	mustHandle(t, d, createRequest(0, 7, RDPGraphicsChannel))
	mustHandle(t, d, createRequest(0, 8, RDPDisplayControlChannel))
	if opened, _ := d.take(); len(opened) != 2 || opened[0] != RDPGraphicsChannel {
		t.Fatalf("opened %q", opened)
	}
	first := func(id byte, total uint32) []byte {
		return append(binary.LittleEndian.AppendUint32([]byte{dynvcDataFirst<<4 | 2<<2, id}, total), 1)
	}
	mustHandle(t, d, first(7, MaxRDPChannelMessage+1))
	if _, err := d.handle(first(8, MaxRDPChannelMessage+1)); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("the display control past 64 KiB: %v", err)
	}
	if _, err := d.handle(first(9, 2)); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("a channel not open: %v", err)
	}
	d2 := &rdpDynamicChannels{allowed: map[string]bool{RDPGraphicsChannel: true}, open: map[uint32]string{7: RDPGraphicsChannel},
		assembling: map[uint32]*dynvcAssembly{}, capsSeen: true}
	if _, err := d2.handle(first(7, maxGraphicsMessage+1)); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("the graphics channel past 16 MiB: %v", err)
	}
	if !rdpDynamicChannelsAllowed[RDPGraphicsChannel] {
		t.Fatal("the graphics channel is not in the closed list")
	}
}

func FuzzRDPGraphicsPipelineRead(f *testing.F) {
	f.Add(unencoded(capsConfirm(0x000a0600, 0x22), graphicsPDU(RDPGraphicsStartFrame, make([]byte, 8))))
	f.Add(unencoded(graphicsPDU(RDPGraphicsEndFrame, make([]byte, 4))))
	f.Fuzz(func(t *testing.T, message []byte) {
		p := NewRDPGraphicsPipeline()
		pdus, err := p.Read(message)
		if err != nil {
			if !errors.Is(err, ErrRDPGraphics) {
				t.Fatalf("an error outside ErrRDPGraphics: %v", err)
			}
			return
		}
		if _, ok := p.Confirmed(); len(pdus) > 0 && !ok {
			t.Fatal("PDUs handed before the confirmation")
		}
		for _, pdu := range pdus {
			if !rdpGraphicsFromTarget[pdu.Command] {
				t.Fatalf("command 0x%04x handed", pdu.Command)
			}
		}
	})
}

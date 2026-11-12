package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// The dynamic channels of ADR-0095 §3: the closed list, the protocol's answers, and the bounds.

func newDynamic() *rdpDynamicChannels {
	return &rdpDynamicChannels{allowed: map[string]bool{RDPDisplayControlChannel: true},
		open: map[uint32]string{}, assembling: map[uint32]*dynvcAssembly{}}
}

func capsRequest(version uint16) []byte {
	out := []byte{dynvcCapability << 4, 0}
	out = binary.LittleEndian.AppendUint16(out, version)
	if version > 1 {
		out = append(out, make([]byte, 8)...)
	}
	return out
}

func createRequest(cbID byte, id uint32, name string) []byte {
	out := appendDynvcID([]byte{dynvcCreate<<4 | 2<<2 | cbID}, cbID, id)
	return append(append(out, name...), 0)
}

func mustHandle(t *testing.T, d *rdpDynamicChannels, message []byte) [][]byte {
	t.Helper()
	answers, err := d.handle(message)
	if err != nil {
		t.Fatalf("% x: %v", message, err)
	}
	return answers
}

func TestDynamicChannels_AnswerTheCapabilitiesWithoutCompression(t *testing.T) {
	for version, want := range map[uint16]uint16{1: 1, 2: 2, 3: 2} {
		answers := mustHandle(t, newDynamic(), capsRequest(version))
		if len(answers) != 1 || !bytes.Equal(answers[0], []byte{0x50, 0, byte(want), 0}) {
			t.Fatalf("version %d answered % x, want version %d", version, answers, want)
		}
	}
	d := newDynamic()
	mustHandle(t, d, capsRequest(3))
	if _, err := d.handle(capsRequest(3)); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("capabilities twice: %v", err)
	}
	for name, message := range map[string][]byte{
		"version 0":                  capsRequest(0),
		"version 2 without charges":  {0x50, 0, 2, 0},
		"version 1 with charges":     append([]byte{0x50, 0, 1, 0}, make([]byte, 8)...),
		"cut short":                  {0x50, 0},
		"a create before the caps":   createRequest(0, 3, RDPDisplayControlChannel),
		"compressed data":            {dynvcDataFirstCompr << 4, 3, 0},
		"compressed data, continued": {dynvcDataCompr << 4, 3, 0},
		"soft-sync":                  {0x80, 0},
		"empty":                      {},
	} {
		if _, err := newDynamic().handle(message); !errors.Is(err, ErrRDPDynamicChannel) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestDynamicChannels_OpenOnlyTheClosedList(t *testing.T) {
	d := newDynamic()
	mustHandle(t, d, capsRequest(3))
	answers := mustHandle(t, d, createRequest(0, 7, "Microsoft::Windows::RDS::Telemetry"))
	want := []byte{0x10, 7, 0x05, 0x00, 0x07, 0x80}
	if len(answers) != 1 || !bytes.Equal(answers[0], want) {
		t.Fatalf("a name outside the list answered % x, want % x (E_ACCESSDENIED)", answers, want)
	}
	answers = mustHandle(t, d, createRequest(1, 0x0102, RDPDisplayControlChannel))
	if len(answers) != 1 || !bytes.Equal(answers[0], []byte{0x11, 0x02, 0x01, 0, 0, 0, 0}) {
		t.Fatalf("the display control answered % x, want success on ID 0x0102", answers)
	}
	opened, _ := d.take()
	if len(opened) != 1 || opened[0] != RDPDisplayControlChannel {
		t.Fatalf("opened %q", opened)
	}
	// One channel of a name at a time.
	answers = mustHandle(t, d, createRequest(0, 9, RDPDisplayControlChannel))
	if binary.LittleEndian.Uint32(answers[0][2:6]) != dynvcCreationRefused {
		t.Fatalf("the display control opened twice: % x", answers)
	}
	if d.refusals != 2 || len(d.refused) != 2 || d.refused[0] != "Microsoft::Windows::RDS::Telemetry" {
		t.Fatalf("refusals %d %q", d.refusals, d.refused)
	}
	for i := 0; i < maxDynvcRefusals+5; i++ {
		mustHandle(t, d, createRequest(0, uint32(20+i), "other"))
	}
	if len(d.refused) != maxDynvcRefusals || d.refusals != maxDynvcRefusals+7 {
		t.Fatalf("refused names kept %d (bound %d), counted %d", len(d.refused), maxDynvcRefusals, d.refusals)
	}
}

func TestDynamicChannels_RefuseAMalformedCreate(t *testing.T) {
	long := string(bytes.Repeat([]byte{'a'}, maxDynvcNameBytes+1))
	for name, message := range map[string][]byte{
		"no NUL":            createRequest(0, 3, RDPDisplayControlChannel)[:3+len(RDPDisplayControlChannel)-1],
		"an empty name":     createRequest(0, 3, ""),
		"a name too long":   createRequest(0, 3, long),
		"a control char":    createRequest(0, 3, "Disp\x01"),
		"cbId 3":            {dynvcCreate<<4 | 3, 3, 'a', 0},
		"an ID cut short":   {dynvcCreate<<4 | 2, 3},
		"the ID already in": nil,
	} {
		d := newDynamic()
		mustHandle(t, d, capsRequest(3))
		if message == nil {
			mustHandle(t, d, createRequest(0, 3, RDPDisplayControlChannel))
			message = createRequest(0, 3, "other")
		}
		if _, err := d.handle(message); !errors.Is(err, ErrRDPDynamicChannel) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func openDisplay(t *testing.T) *rdpDynamicChannels {
	t.Helper()
	d := newDynamic()
	mustHandle(t, d, capsRequest(3))
	mustHandle(t, d, createRequest(0, 3, RDPDisplayControlChannel))
	d.take()
	return d
}

func dataFirst(id byte, total uint16, data []byte) []byte {
	out := []byte{dynvcDataFirst<<4 | 1<<2, id}
	out = binary.LittleEndian.AppendUint16(out, total)
	return append(out, data...)
}

func TestDynamicChannels_ReassembleTheDataWithinTheBounds(t *testing.T) {
	d := openDisplay(t)
	mustHandle(t, d, append([]byte{dynvcData << 4, 3}, "whole"...))
	mustHandle(t, d, dataFirst(3, 6, []byte("hel")))
	mustHandle(t, d, append([]byte{dynvcData << 4, 3}, "lo!"...))
	mustHandle(t, d, dataFirst(3, 2, []byte("ok")))
	_, delivered := d.take()
	if len(delivered) != 3 || string(delivered[0].data) != "whole" || string(delivered[1].data) != "hello!" ||
		string(delivered[2].data) != "ok" || delivered[1].name != RDPDisplayControlChannel {
		t.Fatalf("delivered %+v", delivered)
	}
	for name, steps := range map[string][][]byte{
		"data on a channel not open":    {append([]byte{dynvcData << 4, 4}, "x"...)},
		"a first inside another":        {dataFirst(3, 6, []byte("a")), dataFirst(3, 6, []byte("a"))},
		"more than announced":           {dataFirst(3, 3, []byte("ab")), append([]byte{dynvcData << 4, 3}, "cd"...)},
		"first longer than its total":   {dataFirst(3, 1, []byte("ab"))},
		"a first of 0 bytes":            {dataFirst(3, 0, nil)},
		"a data with Sp":                {append([]byte{dynvcData<<4 | 1<<2, 3}, "x"...)},
		"an empty data":                 {{dynvcData << 4, 3}},
		"a first past 64 KiB":           {append([]byte{dynvcDataFirst<<4 | 2<<2, 3}, binary.LittleEndian.AppendUint32(nil, MaxRDPChannelMessage+1)...)},
		"a close of a channel not open": {{dynvcClose << 4, 4}},
		"a close with a tail":           {{dynvcClose << 4, 3, 0}},
	} {
		d := openDisplay(t)
		var err error
		for _, step := range steps {
			if _, err = d.handle(step); err != nil {
				break
			}
		}
		if !errors.Is(err, ErrRDPDynamicChannel) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestDynamicChannels_AnswerACloseAndForgetTheChannel(t *testing.T) {
	d := openDisplay(t)
	answers := mustHandle(t, d, []byte{dynvcClose << 4, 3})
	if len(answers) != 1 || !bytes.Equal(answers[0], []byte{0x40, 3}) {
		t.Fatalf("close answered % x", answers)
	}
	if _, err := d.handle(append([]byte{dynvcData << 4, 3}, "x"...)); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("data after the close: %v", err)
	}
	// Closed, the name may open again.
	answers = mustHandle(t, d, createRequest(0, 5, RDPDisplayControlChannel))
	if binary.LittleEndian.Uint32(answers[0][2:6]) != 0 {
		t.Fatalf("reopened: % x", answers)
	}
}

func TestDynamicChannels_SendOneDataPDUOnAnOpenChannel(t *testing.T) {
	d := openDisplay(t)
	pdu, err := d.dataPDU(RDPDisplayControlChannel, []byte("layout"))
	if err != nil || !bytes.Equal(pdu, append([]byte{0x30, 3}, "layout"...)) {
		t.Fatalf("% x %v", pdu, err)
	}
	if _, err := d.dataPDU("other", []byte("x")); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("a channel not open: %v", err)
	}
	for _, size := range []int{0, maxDynvcSendBytes + 1} {
		if _, err := d.dataPDU(RDPDisplayControlChannel, make([]byte, size)); !errors.Is(err, ErrRDPDynamicChannel) {
			t.Fatalf("%d bytes: %v", size, err)
		}
	}
	d.open[0x10000] = "big"
	if pdu, _ := d.dataPDU("big", []byte("x")); !bytes.Equal(pdu, []byte{0x32, 0, 0, 1, 0, 'x'}) {
		t.Fatalf("a 4-byte ID: % x", pdu)
	}
}

func TestEnableDynamicChannels_KeepsToTheClosedList(t *testing.T) {
	s := &CredSSPClientSession{mcsSettings: MCSClientSettings{DynamicChannels: true}}
	if err := s.EnableDynamicChannels([]string{"rdpsnd"}, nil, nil); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("a name outside the list: %v", err)
	}
	if err := (&CredSSPClientSession{}).EnableDynamicChannels([]string{RDPDisplayControlChannel}, nil, nil); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("drdynvc not announced: %v", err)
	}
	if err := s.EnableDynamicChannels([]string{RDPDisplayControlChannel}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableDynamicChannels([]string{RDPDisplayControlChannel}, nil, nil); !errors.Is(err, ErrRDPDynamicChannel) {
		t.Fatalf("enabled twice: %v", err)
	}
}

// The callbacks run with the session's lock released: one that sends on the channel it heard from,
// as the display control will, does not hang.
func TestEnableDynamicChannels_CallbacksMaySendWithoutHanging(t *testing.T) {
	s := &CredSSPClientSession{mcsSettings: MCSClientSettings{DynamicChannels: true}}
	sent := make(chan error, 8)
	if err := s.EnableDynamicChannels([]string{RDPDisplayControlChannel},
		func(name string) {
			sent <- s.SendDynamicChannelMessage(context.Background(), name, []byte("x"), time.Second)
		},
		func(name string, data []byte) error {
			sent <- s.SendDynamicChannelMessage(context.Background(), name, []byte("y"), time.Second)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.dynamicChannels.capsSeen = true
	handler := s.channelHandler
	s.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		// No transport: the answer to the create cannot be sent, which ends here, after the lock.
		done <- handler(RDPChannelDynamic, createRequest(0, 3, RDPDisplayControlChannel))
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an answer sent with no transport")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler hung")
	}
	// Opened and a message delivered, the callbacks' sends must return, not hang.
	s.mu.Lock()
	s.dynamicChannels.opened = []string{RDPDisplayControlChannel}
	s.dynamicChannels.delivered = []dynvcDelivery{{RDPDisplayControlChannel, []byte("caps")}}
	s.mu.Unlock()
	go func() { done <- handler(RDPChannelDynamic, []byte{dynvcData << 4, 3, 'z'}) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a callback that sends hung the reader")
	}
}

func FuzzDynamicChannels(f *testing.F) {
	f.Add(capsRequest(3), createRequest(0, 3, RDPDisplayControlChannel), dataFirst(3, 4, []byte("ab")))
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		d := newDynamic()
		for _, message := range [][]byte{a, b, c} {
			if _, err := d.handle(message); err != nil {
				return
			}
		}
		_, delivered := d.take()
		for _, delivery := range delivered {
			if len(delivery.data) == 0 || len(delivery.data) > MaxRDPChannelMessage {
				t.Fatalf("a %d-byte message delivered", len(delivery.data))
			}
		}
		if len(d.open) > 1 {
			t.Fatalf("%d channels open, the list holds one name", len(d.open))
		}
	})
}

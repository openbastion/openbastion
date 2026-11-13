package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// The clipboard of ADR-0096: the order of MS-RDPECLIP, text alone, each direction by its policy.

func serverCaps() []byte {
	data := make([]byte, 4+12)
	binary.LittleEndian.PutUint16(data[0:2], 1)
	binary.LittleEndian.PutUint16(data[4:6], cbCapsGeneral)
	binary.LittleEndian.PutUint16(data[6:8], 12)
	binary.LittleEndian.PutUint32(data[8:12], cbCapsVersion2)
	binary.LittleEndian.PutUint32(data[12:16], 0x02) // CB_USE_LONG_FORMAT_NAMES: the server's, not taken
	return clipboardMessage(cbClipCaps, 0, data)
}

func serverFormats(ids ...uint32) []byte {
	var data []byte
	for _, id := range ids {
		entry := make([]byte, 4+cbShortNameSize)
		binary.LittleEndian.PutUint32(entry[:4], id)
		data = append(data, entry...)
	}
	return clipboardMessage(cbFormatList, 0, data)
}

func readyClipboard(t *testing.T, toTarget, fromTarget bool) *rdpClipboard {
	t.Helper()
	c := &rdpClipboard{toTarget: toTarget, fromTarget: fromTarget}
	if _, err := c.handle(serverCaps()); err != nil {
		t.Fatal(err)
	}
	answers, err := c.handle(clipboardMessage(cbMonitorReady, 0, nil))
	if err != nil || len(answers) != 2 {
		t.Fatalf("monitor ready: %d answer(s), %v", len(answers), err)
	}
	return c
}

func TestClipboard_AnswersMonitorReadyWithShortNamesAndNoFiles(t *testing.T) {
	c := &rdpClipboard{toTarget: true, fromTarget: true}
	c.handle(serverCaps())
	answers, err := c.handle(clipboardMessage(cbMonitorReady, 0, nil))
	if err != nil || len(answers) != 2 {
		t.Fatalf("%d answer(s), %v", len(answers), err)
	}
	if !bytes.Equal(answers[0], clientCapabilities()) || binary.LittleEndian.Uint32(answers[0][20:24]) != 0 {
		t.Fatalf("capabilities % x: want version 2 and no general flag", answers[0])
	}
	if !bytes.Equal(answers[1], formatList(false)) {
		t.Fatalf("format list % x: nothing offered yet, want an empty list", answers[1])
	}
	// Without the right to paste, nothing is announced, whatever is held.
	c = &rdpClipboard{fromTarget: true, offered: []byte{'a', 0, 0, 0}}
	if answers, _ := c.handle(clipboardMessage(cbMonitorReady, 0, nil)); !bytes.Equal(answers[1], formatList(false)) {
		t.Fatalf("format list % x: a session that may not paste announced text", answers[1])
	}
	// The text offered before monitor ready goes in its format list.
	c = &rdpClipboard{toTarget: true, offered: []byte{'a', 0, 0, 0}}
	answers, _ = c.handle(clipboardMessage(cbMonitorReady, 0, nil))
	if !bytes.Equal(answers[1], formatList(true)) {
		t.Fatalf("format list % x: want CF_UNICODETEXT", answers[1])
	}
}

func TestClipboard_KeepsToTheOrderOfTheProtocol(t *testing.T) {
	for name, steps := range map[string][][]byte{
		"a format list before monitor ready": {serverFormats(cfUnicodeText)},
		"monitor ready twice":                {clipboardMessage(cbMonitorReady, 0, nil), clipboardMessage(cbMonitorReady, 0, nil)},
		"capabilities twice":                 {serverCaps(), serverCaps()},
		"a length that lies":                 {append(clipboardMessage(cbMonitorReady, 0, nil), 0)},
		"a header cut short":                 {{1, 0, 0}},
	} {
		c := &rdpClipboard{toTarget: true, fromTarget: true}
		var err error
		for _, step := range steps {
			if _, err = c.handle(step); err != nil {
				break
			}
		}
		if !errors.Is(err, ErrRDPClipboard) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestClipboard_RefusesWhatIsNotAnnounced(t *testing.T) {
	for name, message := range map[string][]byte{
		"file contents request": clipboardMessage(0x0008, 0, make([]byte, 28)),
		"lock":                  clipboardMessage(0x000a, 0, make([]byte, 4)),
		"temporary directory":   clipboardMessage(0x0006, 0, make([]byte, 520)),
		"an unknown type":       clipboardMessage(0x0042, 0, nil),
		"a long-names list":     clipboardMessage(cbFormatList, 0, []byte{13, 0, 0, 0, 'a', 0, 0, 0}),
	} {
		if _, err := readyClipboard(t, true, true).handle(message); !errors.Is(err, ErrRDPClipboard) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestClipboard_CopiesTextOnlyWhenTheSessionMay(t *testing.T) {
	c := readyClipboard(t, false, true)
	answers, err := c.handle(serverFormats(1, 13, 16, 0xc0a1))
	if err != nil || len(answers) != 1 || !bytes.Equal(answers[0], clipboardMessage(cbFormatListResponse, cbResponseOK, nil)) {
		t.Fatalf("the format list answered % x, %v", answers, err)
	}
	if offers, _ := c.take(); offers != 1 {
		t.Fatalf("%d offer(s) told, want 1: CF_UNICODETEXT is in the list", offers)
	}
	c.handle(serverFormats(1, 16)) // no CF_UNICODETEXT: nothing to copy
	if offers, _ := c.take(); offers != 0 {
		t.Fatal("an offer told for a list without CF_UNICODETEXT")
	}
	// The text, asked then answered.
	c.requested = true
	text, _ := encodeClipboardText("héllo 🌍")
	if _, err := c.handle(clipboardMessage(cbFormatDataResponse, cbResponseOK, text)); err != nil {
		t.Fatal(err)
	}
	if _, texts := c.take(); len(texts) != 1 || texts[0] != "héllo 🌍" {
		t.Fatalf("copied %q", texts)
	}
	// Without the right to copy, the list is answered and nothing is told.
	c = readyClipboard(t, true, false)
	c.handle(serverFormats(13))
	if offers, _ := c.take(); offers != 0 {
		t.Fatal("an offer told to a session that may not copy")
	}
	// A response nobody asked for is outside the protocol.
	if _, err := readyClipboard(t, true, true).handle(clipboardMessage(cbFormatDataResponse, cbResponseOK, text)); !errors.Is(err, ErrRDPClipboard) {
		t.Fatalf("a data response to no request: %v", err)
	}
}

func TestClipboard_PastesTextOnlyWhenTheSessionMay(t *testing.T) {
	request := clipboardMessage(cbFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, cfUnicodeText))
	fail := clipboardMessage(cbFormatDataResponse, cbResponseFail, nil)
	c := readyClipboard(t, true, false)
	if answers, _ := c.handle(request); len(answers) != 1 || !bytes.Equal(answers[0], fail) {
		t.Fatalf("nothing offered: % x, want a failure", answers)
	}
	c.offered, _ = encodeClipboardText("pasted")
	answers, err := c.handle(request)
	if err != nil || len(answers) != 1 || !bytes.Equal(answers[0], clipboardMessage(cbFormatDataResponse, cbResponseOK, c.offered)) {
		t.Fatalf("the text asked: % x, %v", answers, err)
	}
	other := clipboardMessage(cbFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, 1)) // CF_TEXT
	if answers, _ := c.handle(other); !bytes.Equal(answers[0], fail) {
		t.Fatal("a format other than CF_UNICODETEXT given")
	}
	c = readyClipboard(t, false, true)
	c.offered, _ = encodeClipboardText("pasted")
	if answers, _ := c.handle(request); !bytes.Equal(answers[0], fail) {
		t.Fatal("a text given by a session that may not paste")
	}
}

func TestClipboardText_StaysWithinItsBound(t *testing.T) {
	if _, err := encodeClipboardText(strings.Repeat("a", MaxRDPClipboardTextBytes/2)); err != nil {
		t.Fatalf("a text of exactly the bound: %v", err)
	}
	if _, err := encodeClipboardText(strings.Repeat("a", MaxRDPClipboardTextBytes/2+1)); !errors.Is(err, ErrRDPClipboard) {
		t.Fatalf("a text past the bound: %v", err)
	}
	if _, err := encodeClipboardText("\xff"); !errors.Is(err, ErrRDPClipboard) {
		t.Fatalf("a text that is not UTF-8: %v", err)
	}
	for name, data := range map[string][]byte{
		"no NUL":     {'a', 0},
		"odd length": {'a', 0, 0},
		"empty":      nil,
		"past bound": make([]byte, MaxRDPClipboardTextBytes+4),
	} {
		if _, err := decodeClipboardText(data); !errors.Is(err, ErrRDPClipboard) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
	if text, err := decodeClipboardText([]byte{'o', 0, 'k', 0, 0, 0, 'x', 0}); err != nil || text != "ok" {
		t.Fatalf("what follows the NUL kept: %q %v", text, err)
	}
}

func TestEnableClipboard_NeedsTheChannelAndADirection(t *testing.T) {
	if err := (&CredSSPClientSession{}).EnableClipboard(true, true, nil, nil); !errors.Is(err, ErrRDPClipboard) {
		t.Fatalf("cliprdr not announced: %v", err)
	}
	s := &CredSSPClientSession{mcsSettings: MCSClientSettings{ClipboardChannel: true}}
	if err := s.EnableClipboard(false, false, nil, nil); !errors.Is(err, ErrRDPClipboard) {
		t.Fatalf("no direction: %v", err)
	}
	if err := s.EnableClipboard(true, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.clipboard.ready = true // ready, so that only the missing right refuses
	if err := s.RequestClipboardText(t.Context()); !errors.Is(err, ErrRDPClipboard) {
		t.Fatalf("copying with only the right to paste: %v", err)
	}
}

func FuzzClipboard(f *testing.F) {
	f.Add(serverCaps(), clipboardMessage(cbMonitorReady, 0, nil), serverFormats(13))
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		clip := &rdpClipboard{toTarget: true, fromTarget: true, requested: true}
		for _, message := range [][]byte{a, b, c} {
			answers, err := clip.handle(message)
			if err != nil {
				return
			}
			for _, answer := range answers {
				if len(answer) > MaxRDPChannelMessage {
					t.Fatalf("an answer of %d bytes", len(answer))
				}
			}
		}
		_, texts := clip.take()
		for _, text := range texts {
			if len(text) > MaxRDPClipboardTextBytes*2 {
				t.Fatalf("a %d-byte text", len(text))
			}
		}
	})
}

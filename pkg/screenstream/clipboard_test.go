package screenstream

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func clipboardMessage(direction ClipboardDirection, text string) Message {
	return Message{Type: TypeClipboard, Sequence: 7, Timestamp: time.Unix(1, 5).UTC(), Direction: direction, ClipboardText: text}
}

// A clipboard text (ADR-0096) goes through whole, in either direction: empty, accented, astral,
// with its line ends, and up to the bound in UTF-16 units, the target's encoding.
func TestClipboard_RoundTrips(t *testing.T) {
	for _, text := range []string{"", "Pasted: é €", "\U0001F600 line\r\nnext\ttab",
		strings.Repeat("a", MaxClipboardTextUnits), strings.Repeat("\U0001F600", MaxClipboardTextUnits/2)} {
		for _, direction := range []ClipboardDirection{ClipboardToTarget, ClipboardFromTarget} {
			m := clipboardMessage(direction, text)
			data, err := Encode(m)
			if err != nil {
				t.Fatalf("%d units %v: %v", len(text), direction, err)
			}
			back, err := Decode(data)
			if err != nil || back.Type != TypeClipboard || back.Direction != direction || back.ClipboardText != text ||
				back.Sequence != 7 || !back.Timestamp.Equal(m.Timestamp) {
				t.Fatalf("round trip of %d bytes %v: %+v %v", len(text), direction, back.Direction, err)
			}
		}
	}
}

// Past the bound, without a direction, with a NUL or broken UTF-8, with a screen size or no
// sequence: refused, both ways.
func TestClipboard_RefusesWhatTheContractDoesNot(t *testing.T) {
	over := clipboardMessage(ClipboardToTarget, strings.Repeat("a", MaxClipboardTextUnits+1))
	if _, err := Encode(over); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("one unit past the bound: %v", err)
	}
	astral := clipboardMessage(ClipboardToTarget, "ab"+strings.Repeat("\U0001F600", MaxClipboardTextUnits/2))
	if _, err := Encode(astral); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("surrogate pairs counted as one unit: %v", err)
	}
	for name, m := range map[string]Message{
		"no direction":   clipboardMessage(0, "x"),
		"an unknown one": clipboardMessage(3, "x"),
		"a NUL":          clipboardMessage(ClipboardFromTarget, "a\x00b"),
		"broken UTF-8":   clipboardMessage(ClipboardFromTarget, "a\xffb"),
		"no sequence":    {Type: TypeClipboard, Timestamp: time.Unix(1, 0), Direction: ClipboardToTarget},
		"no time":        {Type: TypeClipboard, Sequence: 1, Direction: ClipboardToTarget},
		"a screen size":  {Type: TypeClipboard, Sequence: 1, Timestamp: time.Unix(1, 0), Width: 1, Height: 1, Direction: ClipboardToTarget},
	} {
		if _, err := Encode(m); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	good, _ := Encode(clipboardMessage(ClipboardToTarget, "abc"))
	for name, mutate := range map[string]func([]byte){
		"a reserved byte set": func(b []byte) { b[HeaderSize+2] = 1 },
		"a direction of 0":    func(b []byte) { b[HeaderSize] = 0 },
		"a NUL in the text":   func(b []byte) { b[HeaderSize+clipboardHeader+1] = 0 },
	} {
		b := append([]byte(nil), good...)
		mutate(b)
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	short := append([]byte(nil), good[:HeaderSize+2]...)
	short[31] = 2
	if _, err := Decode(short); err == nil {
		t.Error("a payload shorter than its header: decoded")
	}
}

package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func displayCaps(monitors, a, b uint32) []byte {
	out := binary.LittleEndian.AppendUint32(nil, displayControlCapsType)
	out = binary.LittleEndian.AppendUint32(out, displayControlCapsLength)
	out = binary.LittleEndian.AppendUint32(out, monitors)
	out = binary.LittleEndian.AppendUint32(out, a)
	return binary.LittleEndian.AppendUint32(out, b)
}

func TestParseDisplayControlCaps_StrictlyTheCapsPDU(t *testing.T) {
	caps, err := ParseDisplayControlCaps(displayCaps(16, 3840, 2400))
	if err != nil || caps != (RDPDisplayControlCaps{16, 3840, 2400}) {
		t.Fatalf("%+v %v", caps, err)
	}
	if !caps.Fits(2560, 1600) || caps.Fits(3841, 2400) {
		t.Fatal("Fits does not follow the area factors")
	}
	layout := binary.LittleEndian.AppendUint32(nil, displayControlLayoutType)
	for name, message := range map[string][]byte{
		"cut short":       displayCaps(16, 3840, 2400)[:19],
		"a byte too many": append(displayCaps(16, 3840, 2400), 0),
		"another type":    append(layout, displayCaps(16, 3840, 2400)[4:]...),
		"a wrong length":  append(append(binary.LittleEndian.AppendUint32(nil, displayControlCapsType), 21, 0, 0, 0), displayCaps(16, 3840, 2400)[8:]...),
		"no monitor":      displayCaps(0, 3840, 2400),
		"no area":         displayCaps(16, 0, 2400),
		"no area, other":  displayCaps(16, 3840, 0),
	} {
		if _, err := ParseDisplayControlCaps(message); !errors.Is(err, ErrRDPDisplayControl) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestMarshalDisplayControlLayout_OneMonitorPrimaryAtTheOrigin(t *testing.T) {
	got, err := MarshalDisplayControlLayout(1920, 1080)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		2, 0, 0, 0, 56, 0, 0, 0, 40, 0, 0, 0, 1, 0, 0, 0, // header, MonitorLayoutSize, NumMonitors
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // primary, Left, Top
		0x80, 7, 0, 0, 0x38, 4, 0, 0, // 1920 x 1080
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // no physical size, landscape
		100, 0, 0, 0, 100, 0, 0, 0, // 100 %
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("% x\nwant % x", got, want)
	}
	for _, size := range [][2]uint32{{1921, 1080}, {198, 1080}, {1920, 199}, {8194, 1080}, {1920, 8193}} {
		if _, err := MarshalDisplayControlLayout(size[0], size[1]); !errors.Is(err, ErrRDPDisplayControl) {
			t.Errorf("%d x %d: %v, want refused", size[0], size[1], err)
		}
	}
}

func FuzzParseDisplayControlCaps(f *testing.F) {
	f.Add(displayCaps(16, 3840, 2400))
	f.Fuzz(func(t *testing.T, message []byte) {
		if caps, err := ParseDisplayControlCaps(message); err == nil && (caps.MaxNumMonitors == 0 || len(message) != 20) {
			t.Fatalf("%+v from %d bytes", caps, len(message))
		}
	})
}

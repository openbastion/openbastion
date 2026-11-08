package rdp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

// Bytes captured from FreeRDP 3.15 (make test-rdp-interop). The fakes elsewhere in this package were
// written from the same reading of the specification as the client: these were not.

func realServerBytes(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestLicensing_AServerWithNothingToLicenseAnswersValidClientAtOnce(t *testing.T) {
	valid := realServerBytes(t, "0300002302f08068000303eb70801480000000ff031000070000000200000004000000")
	if !parseRDPServerLicenseSuccess(valid, mcsGlobalChannelID) {
		t.Fatal("the answer of a real server was refused")
	}
	// Only that answer ends licensing: anything else about the client is a refusal.
	for name, mutate := range map[string]func([]byte){
		"another status":     func(p []byte) { p[23] = 5 },
		"a state transition": func(p []byte) { p[27] = 1 },
		"another message":    func(p []byte) { p[19] = rdpLicenseRequest },
		"another channel":    func(p []byte) { p[11]++ },
	} {
		packet := append([]byte(nil), valid...)
		mutate(packet)
		if parseRDPServerLicenseSuccess(packet, mcsGlobalChannelID) {
			t.Errorf("%s: licensing was declared complete", name)
		}
	}
}

func TestDemandActive_ADescriptorMayEndWithItsTerminatorOnly(t *testing.T) {
	sets := mcsTestCapabilitySets()
	var caps []byte
	for _, set := range sets {
		caps = append(caps, set...)
	}
	combined := make([]byte, 4, 4+len(caps))
	binary.LittleEndian.PutUint16(combined[:2], uint16(len(sets)))
	combined = append(combined, caps...)
	build := func(source string) []byte {
		share := make([]byte, 14+len(source)+len(combined)+4)
		binary.LittleEndian.PutUint16(share[:2], uint16(len(share)))
		binary.LittleEndian.PutUint16(share[2:4], rdpDemandActivePDU)
		binary.LittleEndian.PutUint16(share[4:6], 1004) // Whichever channel the server speaks from.
		binary.LittleEndian.PutUint32(share[6:10], 0x000103ec)
		binary.LittleEndian.PutUint16(share[10:12], uint16(len(source)))
		binary.LittleEndian.PutUint16(share[12:14], uint16(len(combined)))
		copy(share[14:], source)
		copy(share[14+len(source):], combined)
		return share
	}
	for _, source := range []string{"RDP", "RDP\x00"} {
		if _, err := parseRDPDemandActiveData(build(source)); err != nil {
			t.Errorf("descriptor %q: %v", source, err)
		}
	}
	for _, source := range []string{"\x00RDP", "R\x00P\x00", "RDP\x01"} {
		if _, err := parseRDPDemandActiveData(build(source)); !errors.Is(err, ErrMCSConnection) {
			t.Errorf("descriptor %q: %v", source, err)
		}
	}
}

func fastPathUpdate(code byte, body []byte) []byte {
	update := []byte{code, byte(len(body)), byte(len(body) >> 8)}
	update = append(update, body...)
	return append([]byte{0, byte(len(update) + 2)}, update...)
}

func TestFastPath_OnlyAClosedListOfUpdatesIsIgnored(t *testing.T) {
	for _, code := range []byte{0x3, 0x5, 0x6, 0x8, 0x9, 0xa, 0xb} {
		if !rdpFastPathUpdateIsIgnored(fastPathUpdate(code, []byte{1, 2})) {
			t.Errorf("update %#x is the pointer or a synchronization", code)
		}
	}
	// What draws must never be passed over: skipping it would show the auditor another screen.
	for _, code := range []byte{0x0, 0x1, 0x2, 0x4, 0x7, 0xc, 0xf} {
		if rdpFastPathUpdateIsIgnored(fastPathUpdate(code, []byte{1, 2})) {
			t.Errorf("update %#x was ignored", code)
		}
	}
	fragment := fastPathUpdate(0x9, []byte{1, 2})
	fragment[2] |= 1 << 4
	if rdpFastPathUpdateIsIgnored(fragment) {
		t.Error("a fragment was ignored: what follows it is not known")
	}
	compressed := fastPathUpdate(0x9, []byte{1, 2})
	compressed[2] |= 1 << 6
	if rdpFastPathUpdateIsIgnored(compressed) {
		t.Error("a compressed update was ignored")
	}
	short := fastPathUpdate(0x9, []byte{1, 2})
	short[3]++
	if rdpFastPathUpdateIsIgnored(short) {
		t.Error("an update whose size lies was ignored")
	}
	long := fastPathUpdate(0x9, []byte{1, 2})
	long = append([]byte{0, 0x80, byte(len(long) + 1)}, long[2:]...)
	if !rdpFastPathUpdateIsIgnored(long) {
		t.Error("the long form of a small length")
	}
	if rdpFastPathUpdateIsIgnored([]byte{0, 3}) || rdpFastPathUpdateIsIgnored(nil) {
		t.Error("a truncated packet was ignored")
	}
}

func shareData(shareID uint32, pduType2, compressed byte) []byte {
	data := make([]byte, 22)
	binary.LittleEndian.PutUint16(data[:2], uint16(len(data)))
	binary.LittleEndian.PutUint16(data[2:4], rdpShareDataPDU)
	binary.LittleEndian.PutUint32(data[6:10], shareID)
	data[14], data[15] = pduType2, compressed
	return data
}

func TestShareData_OnlyWhatCarriesNoGraphicsIsIgnored(t *testing.T) {
	const share = uint32(0x000103ec)
	for _, kind := range []byte{0x1b, 0x26, 0x29, 0x2a, 0x2f} {
		if !rdpShareDataIsIgnored(shareData(share, kind, 0), share) {
			t.Errorf("share data %#x carries no graphics", kind)
		}
	}
	if rdpShareDataIsIgnored(shareData(share, rdpPDU2Update, 0), share) {
		t.Error("a graphics update was ignored")
	}
	if rdpShareDataIsIgnored(shareData(share, 0x30, 0), share) {
		t.Error("an unknown PDU was ignored")
	}
	if rdpShareDataIsIgnored(shareData(share+1, 0x1b, 0), share) {
		t.Error("a PDU of another share was ignored")
	}
	if rdpShareDataIsIgnored(shareData(share, 0x1b, 1), share) {
		t.Error("a compressed PDU was ignored")
	}
	lying := shareData(share, 0x1b, 0)
	lying[0]++
	if rdpShareDataIsIgnored(lying, share) {
		t.Error("a PDU whose length lies was ignored")
	}
	// The deactivation of a share is not information: it is refused, the stream ends.
	deactivate := realServerBytes(t, "0d001600ec03ec030100010000")
	if rdpShareDataIsIgnored(deactivate, share) {
		t.Error("a Deactivate All was ignored")
	}
}

// A run repeats the last raw value of its line, whichever segment gave it. FreeRDP's white line:
// 0x1f: one raw 0xff and a run of 15; 0xd2 and 0x03: runs without a raw value of their own.
func TestDecodeRDP6RLEPlane_ARunContinuesTheLineItIsIn(t *testing.T) {
	got, consumed, err := decodeRDP6RLEPlane(realServerBytes(t, "1fffd203"), 64, 1)
	if err != nil || consumed != 4 {
		t.Fatalf("%d, %v", consumed, err)
	}
	for x, value := range got {
		if value != 0xff {
			t.Fatalf("column %d: %#x", x, value)
		}
	}
	// A line starts over: a run without a raw value is a delta of 0, not the last line's value.
	second, _, err := decodeRDP6RLEPlane([]byte{0x13, 0xff, 0x04}, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	for x, value := range second[4:] {
		if value != 0xff {
			t.Fatalf("second line, column %d: %#x", x, value)
		}
	}
}

// The low bits of formatHeader are the color loss level (MS-RDPEGDI 2.2.2.5.1), and 0x10 is RLE.
func TestDecodeRDP6Bitmap_TheFormatBitsOfARealServer(t *testing.T) {
	// 0x30: RLE, no alpha. Three planes of one white line.
	plane := []byte{0x13, 0xff}
	stream := append([]byte{0x30}, append(append(append([]byte(nil), plane...), plane...), plane...)...)
	got, err := decodeRDP6Bitmap(stream, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range got {
		if value != 0xff {
			t.Fatalf("byte %d: %#x", i, value)
		}
	}
	if _, err := decodeRDP6Bitmap([]byte{0xc0, 0, 0, 0}, 4, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("reserved bits: %v", err)
	}
	if _, err := decodeRDP6Bitmap([]byte{0x08}, 4, 1); !errors.Is(err, ErrMCSConnection) {
		t.Fatalf("chroma subsampling without color loss: %v", err)
	}
}

// Each rectangle decodes its own bytes: the next one is not part of it.
func TestParseRDPBitmapUpdateData_SeveralCompressedRectanglesWithoutHeader(t *testing.T) {
	plane := []byte{0x13, 0xff}
	stream := append([]byte{0x30}, append(append(append([]byte(nil), plane...), plane...), plane...)...)
	var data []byte
	data = binary.LittleEndian.AppendUint16(data, 2)
	for _, top := range []uint16{0, 1} {
		for _, field := range []uint16{0, top, 3, top, 4, 1, 32, rdpBitmapCompressed | rdpBitmapNoCompHdr, uint16(len(stream))} {
			data = binary.LittleEndian.AppendUint16(data, field)
		}
		data = append(data, stream...)
	}
	update, err := parseRDPBitmapUpdateData(data, 8, 8)
	if err != nil || len(update.Rectangles) != 2 {
		t.Fatalf("%+v, %v", update, err)
	}
}

func TestClientCapabilities_AnnounceWhatARealServerNeeds(t *testing.T) {
	caps := marshalRDPClientCapabilitySets(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800}, 32)
	extra := binary.LittleEndian.Uint16(caps[14:16])
	if extra&rdpFastPathOutputSupported == 0 {
		t.Error("without FASTPATH_OUTPUT_SUPPORTED, FreeRDP cannot send a bitmap")
	}
	if extra&rdpBitmapNoCompHdr == 0 {
		t.Error("without NO_BITMAP_COMPRESSION_HDR, bitmapLength means two different things")
	}
	// TS_BITMAP_CAPABILITYSET follows the 24-byte general set.
	bitmap := caps[24 : 24+28]
	if binary.LittleEndian.Uint16(bitmap[0:2]) != rdpCapBitmap || binary.LittleEndian.Uint16(bitmap[20:22]) != 1 {
		t.Error("bitmapCompressionFlag MUST be TRUE: Windows answers FALSE with ERRINFO_BADCAPABILITIES (CI run #31)")
	}
	for _, bpp := range []uint16{15, 16, 32} {
		got := marshalRDPClientCapabilitySets(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800}, bpp)
		if binary.LittleEndian.Uint16(got[24+4:24+6]) != bpp {
			t.Errorf("preferredBitsPerPixel is not the server's %d", bpp)
		}
	}
}

func TestClientInfo_CarriesAnExtendedPacketThatSaysNothingOfTheProxy(t *testing.T) {
	extended := rdpExtendedInfoPacket()
	if got := binary.LittleEndian.Uint16(extended[0:2]); got != 2 {
		t.Fatalf("clientAddressFamily %d", got)
	}
	if binary.LittleEndian.Uint16(extended[2:4]) != 2 || extended[4] != 0 || extended[5] != 0 {
		t.Fatal("a client address is announced")
	}
	if binary.LittleEndian.Uint16(extended[6:8]) != 2 || extended[8] != 0 || extended[9] != 0 {
		t.Fatal("a client directory is announced")
	}
	if got := binary.LittleEndian.Uint16(extended[len(extended)-2:]); got != 0 {
		t.Fatalf("a reconnection cookie of %d bytes", got)
	}
}

func TestFramebuffer_UnchangedKnowsOnlyWhatRepaintsTheSamePixels(t *testing.T) {
	framebuffer, err := NewRDPFramebuffer(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	white := RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 0, Y: 0, Width: 2, Height: 1, Pixels: []byte{255, 255, 255, 255, 255, 255, 255, 255}}}}
	if framebuffer.Unchanged(white) {
		t.Fatal("white on a new framebuffer is a change")
	}
	if _, err := framebuffer.Apply(white, time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	if !framebuffer.Unchanged(white) {
		t.Fatal("the same pixels again are not a change")
	}
	other := RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 1, Y: 0, Width: 1, Height: 1, Pixels: []byte{0, 255, 255, 255}}}}
	if framebuffer.Unchanged(other) {
		t.Fatal("one pixel differs")
	}
	// What is not a plain replacement counts as a change: it is never skipped on a guess.
	// A pattern with the very pixels on screen would still change them.
	inverted := RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 0, Y: 0, Width: 2, Height: 1, operation: rdpBitmapRectanglePatInvert,
		Pixels: []byte{255, 255, 255, 255, 255, 255, 255, 255}}}}
	if framebuffer.Unchanged(inverted) {
		t.Fatal("an inversion was skipped")
	}
	outside := RDPBitmapUpdate{Rectangles: []RDPBitmapRectangle{{X: 2, Y: 0, Width: 1, Height: 1, Pixels: []byte{255, 255, 255, 255}}}}
	if framebuffer.Unchanged(outside) {
		t.Fatal("a rectangle outside the screen was judged")
	}
	if framebuffer.Unchanged(RDPBitmapUpdate{}) {
		t.Fatal("an empty update")
	}
}

// Windows Server 2022, left as installed (16 bpp), CI run #36: the first update after the
// finalization, as it came. The whole screen in one Fast-Path PDU, 260 tiles of 64 x 64, all
// Interleaved RLE without header (ADR-0083). The client refused it for its rectangle count.
func TestWindowsServer2022FirstUpdateAt16BPP(t *testing.T) {
	packet, err := os.ReadFile("testdata/windows-server-2022-first-update-16bpp.bin")
	if err != nil {
		t.Fatal(err)
	}
	update, err := parseRDPFastPathBitmapUpdateAt(packet, 1280, 800, 16)
	if err != nil || len(update.Rectangles) != 260 {
		t.Fatalf("%d rectangles, %v", len(update.Rectangles), err)
	}
	fb, err := NewRDPFramebuffer(1280, 800)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fb.Apply(update, time.Now()); err != nil {
		t.Fatalf("framebuffer: %v", err)
	}
	// At 32 bpp, the same PDU is refused: its rectangles say 16.
	if _, err := parseRDPFastPathBitmapUpdateAt(packet, 1280, 800, 32); err == nil {
		t.Fatal("a 16-bpp update accepted in a 32-bpp session")
	}
}

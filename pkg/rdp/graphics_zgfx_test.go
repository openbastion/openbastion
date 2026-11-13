package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// The RDP 8.0 bulk compression of ADR-0101 (MS-RDPEGFX 3.1.9.1): the spec's own examples, every row
// of its token table, the bounds, and what a target may not send.

// zgfxWriter writes a bit stream most significant bit first, as a target would.
type zgfxWriter struct {
	data []byte
	bits int
}

func (w *zgfxWriter) put(v uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		if w.bits%8 == 0 {
			w.data = append(w.data, 0)
		}
		w.data[len(w.data)-1] |= byte((v>>uint(i))&1) << (7 - uint(w.bits%8))
		w.bits++
	}
}

// pattern puts a string of 0 and 1, spaces ignored.
func (w *zgfxWriter) pattern(s string) {
	for _, c := range strings.ReplaceAll(s, " ", "") {
		w.put(uint32(c-'0'), 1)
	}
}

func (w *zgfxWriter) literal(b byte) { w.put(0, 1); w.put(uint32(b), 8) }

func (w *zgfxWriter) match(distance uint32, length int) {
	for i := len(zgfxTokens) - 1; i >= 0; i-- {
		token := zgfxTokens[i]
		if token.match && distance >= token.base && distance-token.base < 1<<token.valueBits {
			w.put(uint32(token.prefix), int(token.prefixBits))
			w.put(distance-token.base, int(token.valueBits))
			break
		}
	}
	if length == 3 {
		w.put(0, 1)
		return
	}
	ones := 1
	for length >= 1<<(ones+2) {
		ones++
	}
	w.put(1<<ones-1, ones)
	w.put(0, 1)
	w.put(uint32(length-1<<(ones+1)), ones+1)
}

func (w *zgfxWriter) run(raw []byte) {
	w.pattern("10001 00000")
	w.put(uint32(len(raw)), 15)
	w.bits = (w.bits + 7) &^ 7
	w.data = append(w.data, raw...)
	w.bits += 8 * len(raw)
}

// segment is the compressed segment: header, the stream, the count of its last byte's unused bits.
func (w *zgfxWriter) segment() []byte {
	out := append([]byte{zgfxTypeRDP8 | zgfxPacketCompress}, w.data...)
	return append(out, byte((8-w.bits%8)%8))
}

func single(segment []byte) []byte { return append([]byte{zgfxSegmentSingle}, segment...) }

func mustDecompress(t *testing.T, z *zgfxDecompressor, message []byte) []byte {
	t.Helper()
	out, err := z.segmentedData(message)
	if err != nil {
		t.Fatalf("% x: %v", message[:min(len(message), 32)], err)
	}
	return out
}

func TestZGFX_TheSpecExamples(t *testing.T) {
	// 3.1.9.1.2.5: "0 0100 1001 10001 00001 110 001 decodes to ten bytes of 0x49".
	var w zgfxWriter
	w.pattern("0 0100 1001 10001 00001 110 001")
	if out := mustDecompress(t, newZGFXDecompressor(), single(w.segment())); !bytes.Equal(out, bytes.Repeat([]byte{0x49}, 10)) {
		t.Fatalf("got % x", out)
	}
	// "10010 0001100 is a match with a distance of 44 (base value of 32 + 7 bits with a value of
	// 12)", here of length 3 ("0").
	z := newZGFXDecompressor()
	history := make([]byte, 50)
	for i := range history {
		history[i] = byte(i)
	}
	mustDecompress(t, z, single(append([]byte{zgfxTypeRDP8}, history...)))
	w = zgfxWriter{}
	w.pattern("10010 0001100 0")
	if out := mustDecompress(t, z, single(w.segment())); !bytes.Equal(out, history[6:9]) {
		t.Fatalf("distance 44 gave % x, want % x", out, history[6:9])
	}
}

func TestZGFX_EveryLiteralOfTheTable(t *testing.T) {
	// The spec's rows, copied apart from the table the decoder uses: its prefix, then its byte.
	var w zgfxWriter
	var want []byte
	for _, row := range []struct {
		prefix string
		b      byte
	}{
		{"11000", 0x00}, {"11001", 0x01}, {"110100", 0x02}, {"110101", 0x03}, {"110110", 0xff},
		{"1101110", 0x04}, {"1101111", 0x05}, {"1110000", 0x06}, {"1110001", 0x07}, {"1110010", 0x08},
		{"1110011", 0x09}, {"1110100", 0x0a}, {"1110101", 0x0b}, {"1110110", 0x3a}, {"1110111", 0x3b},
		{"1111000", 0x3c}, {"1111001", 0x3d}, {"1111010", 0x3e}, {"1111011", 0x3f}, {"1111100", 0x40},
		{"1111101", 0x80}, {"11111100", 0x0c}, {"11111101", 0x38}, {"11111110", 0x39}, {"11111111", 0x66},
	} {
		w.pattern(row.prefix)
		want = append(want, row.b)
	}
	// Every byte through the plain literal too, the ones with a code of their own included.
	for b := range 256 {
		w.literal(byte(b))
		want = append(want, byte(b))
	}
	if out := mustDecompress(t, newZGFXDecompressor(), single(w.segment())); !bytes.Equal(out, want) {
		t.Fatalf("got % x\nwant % x", out, want)
	}
}

// Every distance class at both ends, and every length class, against a history of 2,500,000
// bytes, then past its wrap.
func TestZGFX_EveryDistanceAndLength(t *testing.T) {
	z := newZGFXDecompressor()
	var all []byte
	feed := func(n int, seed byte) {
		for n > 0 {
			chunk := make([]byte, min(n, zgfxMaxSegmentOut))
			for i := range chunk {
				chunk[i] = byte(len(all)+i)*7 + seed
			}
			mustDecompress(t, z, single(append([]byte{zgfxTypeRDP8}, chunk...)))
			all = append(all, chunk...)
			n -= len(chunk)
		}
	}
	feed(zgfxHistorySize, 1)
	for _, token := range zgfxTokens {
		if !token.match {
			continue
		}
		top := token.base + 1<<token.valueBits - 1
		for _, distance := range []uint32{token.base, top} {
			if distance == 0 {
				continue // the unencoded run
			}
			distance = min(distance, zgfxHistorySize)
			var w zgfxWriter
			w.match(distance, 3)
			out := mustDecompress(t, z, single(w.segment()))
			from := len(all) - int(distance)
			if !bytes.Equal(out, all[from:from+3]) {
				t.Fatalf("distance %d gave % x, want % x", distance, out, all[from:from+3])
			}
			all = append(all, out...)
		}
	}
	for _, length := range []int{3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024,
		2047, 2048, 4095, 4096, 8191, 8192, 16383, 16384, 32767, 32768, 65535} {
		var w zgfxWriter
		w.match(1000, length)
		out := mustDecompress(t, z, single(w.segment()))
		source := append([]byte(nil), all[len(all)-1000:]...)
		for i := range length {
			source = append(source, source[i])
		}
		want := source[1000:]
		if !bytes.Equal(out, want) {
			t.Fatalf("length %d: %d bytes, not the %d copied", length, len(out), len(want))
		}
		all = append(all, out...)
	}
	if !z.full {
		t.Fatal("the history never wrapped")
	}
}

func TestZGFX_UnencodedRunsAndSegments(t *testing.T) {
	var w zgfxWriter
	w.literal('a')
	w.run([]byte("bcd"))
	w.match(4, 3)
	out := mustDecompress(t, newZGFXDecompressor(), single(w.segment()))
	if string(out) != "abcdabc" {
		t.Fatalf("got %q", out)
	}
	// Multipart: an unencoded segment, then a compressed one reaching back into it.
	var second zgfxWriter
	second.match(5, 5)
	first := append([]byte{zgfxTypeRDP8}, "hello"...)
	message := []byte{zgfxSegmentMulti}
	message = binary.LittleEndian.AppendUint16(message, 2)
	message = binary.LittleEndian.AppendUint32(message, 10)
	for _, segment := range [][]byte{first, second.segment()} {
		message = binary.LittleEndian.AppendUint32(message, uint32(len(segment)))
		message = append(message, segment...)
	}
	if out := mustDecompress(t, newZGFXDecompressor(), message); string(out) != "hellohello" {
		t.Fatalf("multipart gave %q", out)
	}
	// Reserved header bits change nothing (3.1.9.1.2.2).
	if out := mustDecompress(t, newZGFXDecompressor(), single([]byte{zgfxTypeRDP8 | 0xd0, 'x'})); string(out) != "x" {
		t.Fatalf("reserved bits: %q", out)
	}
}

func multipart(size uint32, segments ...[]byte) []byte {
	message := []byte{zgfxSegmentMulti}
	message = binary.LittleEndian.AppendUint16(message, uint16(len(segments)))
	message = binary.LittleEndian.AppendUint32(message, size)
	for _, segment := range segments {
		message = binary.LittleEndian.AppendUint32(message, uint32(len(segment)))
		message = append(message, segment...)
	}
	return message
}

func TestZGFX_RefusesWhatATargetMayNotSend(t *testing.T) {
	compressed := func(build func(w *zgfxWriter)) []byte {
		var w zgfxWriter
		build(&w)
		return single(w.segment())
	}
	raw := func(n int) []byte { return append([]byte{zgfxTypeRDP8}, make([]byte, n)...) }
	for name, message := range map[string][]byte{
		"a match before the history":    compressed(func(w *zgfxWriter) { w.literal(1); w.match(2, 3) }),
		"a match into an empty history": compressed(func(w *zgfxWriter) { w.match(1, 3) }),
		"a distance past 2,500,000": compressed(func(w *zgfxWriter) {
			w.pattern("10111101")
			w.put(1<<21-1, 21)
			w.put(0, 1)
		}),
		"more than 65,535 bytes":  compressed(func(w *zgfxWriter) { w.literal(1); w.match(1, 65535) }),
		"a literal cut short":     compressed(func(w *zgfxWriter) { w.pattern("0 0101") }),
		"a token cut short":       compressed(func(w *zgfxWriter) { w.pattern("1011") }),
		"a run past the stream":   compressed(func(w *zgfxWriter) { w.pattern("10001 00000"); w.put(9, 15) }),
		"a run cut short":         compressed(func(w *zgfxWriter) { w.pattern("10001 00000 0000") }),
		"a trailer above 7":       single([]byte{zgfxTypeRDP8 | zgfxPacketCompress, 0, 8}),
		"a trailer past the data": single([]byte{zgfxTypeRDP8 | zgfxPacketCompress, 7}),
		"another compression":     single([]byte{0x02, 'x'}),
		"an empty segment":        {zgfxSegmentSingle},
		"an unknown descriptor":   {0xe2, zgfxTypeRDP8, 'x'},
		"an unencoded 65,536":     single(raw(65536)),
		"multipart, short":        multipart(5, raw(4)),
		"multipart, long":         multipart(3, raw(4)),
		"multipart, no segment":   multipart(1),
		"multipart, empty size":   multipart(0, raw(1)),
		"multipart, a size past the message": append(multipart(1, raw(1))[:7],
			0xff, 0, 0, 0, zgfxTypeRDP8, 1),
		"multipart, bytes left over": append(multipart(1, raw(1)), 0),
		"multipart, header cut":      {zgfxSegmentMulti, 1, 0, 1},
	} {
		if _, err := newZGFXDecompressor().segmentedData(message); !errors.Is(err, ErrRDPGraphics) {
			t.Errorf("%s: %v", name, err)
		}
	} // Past 16 MiB announced, refused before anything is allocated for it.
	if _, err := newZGFXDecompressor().segmentedData(multipart(maxGraphicsMessage+1, raw(1))); err == nil || !strings.Contains(err.Error(), "segment(s) for") {
		t.Errorf("multipart past 16 MiB: %v", err)
	}
	// A length prefix of 15 ones is no length (3.1.9.1.2.3), its 16 bits there or not.
	var w zgfxWriter
	w.literal(1)
	w.pattern("10001 00001 111111111111111 0")
	w.put(0, 16)
	if _, err := newZGFXDecompressor().segmentedData(single(w.segment())); err == nil || !strings.Contains(err.Error(), "prefix of 15 ones") {
		t.Errorf("a length of 15 ones: %v", err)
	}
}

func FuzzZGFXSegmentedData(f *testing.F) {
	var w zgfxWriter
	w.pattern("0 0100 1001 10001 00001 110 001")
	f.Add(single(w.segment()))
	f.Add(multipart(10, append([]byte{zgfxTypeRDP8}, "hello"...), single(w.segment())[1:]))
	f.Fuzz(func(t *testing.T, message []byte) {
		z := newZGFXDecompressor()
		out, err := z.segmentedData(message)
		if err != nil {
			if !errors.Is(err, ErrRDPGraphics) {
				t.Fatalf("an error outside ErrRDPGraphics: %v", err)
			}
			return
		}
		if len(out) > maxGraphicsMessage || (message[0] == zgfxSegmentSingle && len(out) > zgfxMaxSegmentOut) {
			t.Fatalf("%d bytes out", len(out))
		}
	})
}

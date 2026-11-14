package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The RDP 8.0 bulk compression of the graphics pipeline (MS-RDPEGFX 3.1.9.1, "ZGFX"): every message
// the target sends on the graphics channel is an RDP_SEGMENTED_DATA (2.1), one segment or several,
// each compressed or not. A compressed segment is a bit stream of tokens, most significant bit
// first: a literal, or a match that copies bytes already output (up to 2,500,000 back), or an
// unencoded run. What the target sends is bounded: 65,535 bytes out of one segment (3.1.9.1.2.4), a
// whole message no larger than maxGraphicsMessage, a match never before the history's start.

const (
	zgfxHistorySize    = 2_500_000
	zgfxMaxSegmentOut  = 65_535
	zgfxSegmentSingle  = byte(0xe0)
	zgfxSegmentMulti   = byte(0xe1)
	zgfxTypeMask       = byte(0x0f)
	zgfxTypeRDP8       = byte(0x04)
	zgfxPacketCompress = byte(0x20)

	// maxGraphicsMessage bounds a message of the graphics channel, compressed as it comes and once
	// decompressed: a 32 bpp bitmap of 2048 x 2048 holds in it. A session keeps one such message
	// and the history (zgfxHistorySize) at a time.
	maxGraphicsMessage = 16 << 20
)

// ErrRDPGraphics reports a graphics pipeline message outside MS-RDPEGFX or its bounds.
var ErrRDPGraphics = errors.New("rdp: graphics pipeline message refused")

// zgfxToken is one row of the token table (3.1.9.1.2.3), its prefix of prefixBits bits: the plain
// literal (its byte follows, 8 bits), a match (its distance is base plus valueBits bits), or a
// literal of its own (the byte is base).
type zgfxToken struct {
	prefixBits uint8
	prefix     uint16
	valueBits  uint8
	literal    bool
	match      bool
	base       uint32
}

// zgfxTokens is the table of MS-RDPEGFX 3.1.9.1.2.3, row by row.
var zgfxTokens = []zgfxToken{
	{prefixBits: 1, prefix: 0b0, valueBits: 8, literal: true},
	{prefixBits: 5, prefix: 0b10001, valueBits: 5, match: true, base: 0},
	{prefixBits: 5, prefix: 0b10010, valueBits: 7, match: true, base: 32},
	{prefixBits: 5, prefix: 0b10011, valueBits: 9, match: true, base: 160},
	{prefixBits: 5, prefix: 0b10100, valueBits: 10, match: true, base: 672},
	{prefixBits: 5, prefix: 0b10101, valueBits: 12, match: true, base: 1696},
	{prefixBits: 6, prefix: 0b101100, valueBits: 14, match: true, base: 5792},
	{prefixBits: 6, prefix: 0b101101, valueBits: 15, match: true, base: 22176},
	{prefixBits: 7, prefix: 0b1011100, valueBits: 18, match: true, base: 54944},
	{prefixBits: 7, prefix: 0b1011101, valueBits: 20, match: true, base: 317088},
	{prefixBits: 8, prefix: 0b10111100, valueBits: 20, match: true, base: 1365664},
	{prefixBits: 8, prefix: 0b10111101, valueBits: 21, match: true, base: 2414240},
	{prefixBits: 5, prefix: 0b11000, base: 0x00},
	{prefixBits: 5, prefix: 0b11001, base: 0x01},
	{prefixBits: 6, prefix: 0b110100, base: 0x02},
	{prefixBits: 6, prefix: 0b110101, base: 0x03},
	{prefixBits: 6, prefix: 0b110110, base: 0xff},
	{prefixBits: 7, prefix: 0b1101110, base: 0x04},
	{prefixBits: 7, prefix: 0b1101111, base: 0x05},
	{prefixBits: 7, prefix: 0b1110000, base: 0x06},
	{prefixBits: 7, prefix: 0b1110001, base: 0x07},
	{prefixBits: 7, prefix: 0b1110010, base: 0x08},
	{prefixBits: 7, prefix: 0b1110011, base: 0x09},
	{prefixBits: 7, prefix: 0b1110100, base: 0x0a},
	{prefixBits: 7, prefix: 0b1110101, base: 0x0b},
	{prefixBits: 7, prefix: 0b1110110, base: 0x3a},
	{prefixBits: 7, prefix: 0b1110111, base: 0x3b},
	{prefixBits: 7, prefix: 0b1111000, base: 0x3c},
	{prefixBits: 7, prefix: 0b1111001, base: 0x3d},
	{prefixBits: 7, prefix: 0b1111010, base: 0x3e},
	{prefixBits: 7, prefix: 0b1111011, base: 0x3f},
	{prefixBits: 7, prefix: 0b1111100, base: 0x40},
	{prefixBits: 7, prefix: 0b1111101, base: 0x80},
	{prefixBits: 8, prefix: 0b11111100, base: 0x0c},
	{prefixBits: 8, prefix: 0b11111101, base: 0x38},
	{prefixBits: 8, prefix: 0b11111110, base: 0x39},
	{prefixBits: 8, prefix: 0b11111111, base: 0x66},
}

// zgfxTokenIndex finds a token by its prefix: zgfxTokenIndex[bits][prefix] is its row, plus one.
var zgfxTokenIndex = func() [9][256]uint8 {
	var index [9][256]uint8
	for i, token := range zgfxTokens {
		index[token.prefixBits][token.prefix] = uint8(i + 1)
	}
	return index
}()

// zgfxDecompressor holds the history of one graphics channel: every byte output, compressed
// segment or not, in a ring of zgfxHistorySize bytes (3.1.9.1.2).
type zgfxDecompressor struct {
	history []byte
	pos     int  // where the next byte goes
	full    bool // the ring has wrapped: every one of its bytes is history
}

func newZGFXDecompressor() *zgfxDecompressor {
	return &zgfxDecompressor{history: make([]byte, zgfxHistorySize)}
}

// available is how many bytes back a match may reach.
func (z *zgfxDecompressor) available() int {
	if z.full {
		return zgfxHistorySize
	}
	return z.pos
}

func (z *zgfxDecompressor) record(b byte) {
	z.history[z.pos] = b
	z.pos++
	if z.pos == zgfxHistorySize {
		z.pos, z.full = 0, true
	}
}

// zgfxBits reads a bit stream most significant bit first, up to limit bits.
type zgfxBits struct {
	data  []byte
	at    int // bits read
	limit int
}

func (b *zgfxBits) read(n int) (uint32, bool) {
	if n < 0 || n > 32 || b.limit-b.at < n {
		return 0, false
	}
	var v uint32
	for range n {
		bit := (b.data[b.at>>3] >> (7 - uint(b.at&7))) & 1
		v = v<<1 | uint32(bit)
		b.at++
	}
	return v, true
}

// segment decompresses one RDP8_BULK_ENCODED_DATA (2.2.5.3) and appends it to out.
func (z *zgfxDecompressor) segment(bulk []byte, out []byte) ([]byte, error) {
	if len(bulk) == 0 {
		return out, fmt.Errorf("%w: an empty segment", ErrRDPGraphics)
	}
	header, data := bulk[0], bulk[1:]
	// The four low bits say RDP 8.0; the others but PACKET_COMPRESSED are reserved (3.1.9.1.2.2),
	// and change nothing of what is decoded: they are not read.
	if header&zgfxTypeMask != zgfxTypeRDP8 {
		return out, fmt.Errorf("%w: compression type %d", ErrRDPGraphics, header&zgfxTypeMask)
	}
	start := len(out)
	if header&zgfxPacketCompress == 0 {
		if len(data) > zgfxMaxSegmentOut {
			return out, fmt.Errorf("%w: a %d-byte unencoded segment", ErrRDPGraphics, len(data))
		}
		for _, c := range data {
			z.record(c)
		}
		return append(out, data...), nil
	}
	// The last byte counts the unused bits of the one before it (3.1.9.1.2.4); its five high bits
	// are reserved.
	if len(data) < 1 || data[len(data)-1] > 7 {
		return out, fmt.Errorf("%w: a compressed segment's trailer", ErrRDPGraphics)
	}
	bits := zgfxBits{data: data, limit: (len(data)-1)*8 - int(data[len(data)-1])}
	if bits.limit < 0 {
		return out, fmt.Errorf("%w: a compressed segment's trailer", ErrRDPGraphics)
	}
	emit := func(c byte) error {
		if len(out)-start >= zgfxMaxSegmentOut {
			return fmt.Errorf("%w: a segment of more than %d bytes", ErrRDPGraphics, zgfxMaxSegmentOut)
		}
		out = append(out, c)
		z.record(c)
		return nil
	}
	for bits.at < bits.limit {
		token, err := readZGFXToken(&bits)
		if err != nil {
			return out, err
		}
		switch {
		case token.literal:
			v, ok := bits.read(8)
			if !ok {
				return out, fmt.Errorf("%w: a literal cut short", ErrRDPGraphics)
			}
			if err := emit(byte(v)); err != nil {
				return out, err
			}
		case !token.match:
			if err := emit(byte(token.base)); err != nil {
				return out, err
			}
		default:
			v, ok := bits.read(int(token.valueBits))
			if !ok {
				return out, fmt.Errorf("%w: a match distance cut short", ErrRDPGraphics)
			}
			distance := token.base + v
			if distance == 0 {
				// An unencoded run: a 15-bit count, then that many whole bytes.
				count, ok := bits.read(15)
				if !ok {
					return out, fmt.Errorf("%w: an unencoded run cut short", ErrRDPGraphics)
				}
				bits.at = (bits.at + 7) &^ 7
				if bits.limit-bits.at < int(count)*8 {
					return out, fmt.Errorf("%w: an unencoded run of %d bytes past the stream", ErrRDPGraphics, count)
				}
				for _, c := range data[bits.at>>3 : bits.at>>3+int(count)] {
					if err := emit(c); err != nil {
						return out, err
					}
				}
				bits.at += int(count) * 8
				continue
			}
			length, err := readZGFXLength(&bits)
			if err != nil {
				return out, err
			}
			if distance > zgfxHistorySize || int(distance) > z.available() {
				return out, fmt.Errorf("%w: a match %d bytes back, %d in the history", ErrRDPGraphics, distance, z.available())
			}
			// Byte by byte: a match may overlap what it outputs (distance 1, length 9 repeats a
			// byte, 3.1.9.1.2.5).
			for range length {
				from := z.pos - int(distance)
				if from < 0 {
					from += zgfxHistorySize
				}
				if err := emit(z.history[from]); err != nil {
					return out, err
				}
			}
		}
	}
	return out, nil
}

func readZGFXToken(bits *zgfxBits) (zgfxToken, error) {
	var prefix uint32
	for n := 1; n <= 8; n++ {
		bit, ok := bits.read(1)
		if !ok {
			return zgfxToken{}, fmt.Errorf("%w: a token cut short", ErrRDPGraphics)
		}
		prefix = prefix<<1 | bit
		if i := zgfxTokenIndex[n][prefix]; i != 0 {
			return zgfxTokens[i-1], nil
		}
	}
	// Every 8-bit prefix is a token or starts a shorter one: this is not reached.
	return zgfxToken{}, fmt.Errorf("%w: no token for prefix %08b", ErrRDPGraphics, prefix)
}

// readZGFXLength reads a match length (3.1.9.1.2.3): "0" is 3; n ones then a zero are followed by
// n+1 bits added to 2^(n+1), up to 14 ones (32768 to 65535).
func readZGFXLength(bits *zgfxBits) (int, error) {
	ones := 0
	for {
		bit, ok := bits.read(1)
		if !ok {
			return 0, fmt.Errorf("%w: a match length cut short", ErrRDPGraphics)
		}
		if bit == 0 {
			break
		}
		ones++
		if ones > 14 {
			return 0, fmt.Errorf("%w: a match length prefix of %d ones", ErrRDPGraphics, ones)
		}
	}
	if ones == 0 {
		return 3, nil
	}
	v, ok := bits.read(ones + 1)
	if !ok {
		return 0, fmt.Errorf("%w: a match length cut short", ErrRDPGraphics)
	}
	return 1<<(ones+1) + int(v), nil
}

// segmentedData decompresses one RDP_SEGMENTED_DATA (2.2.5.1): a single segment, or several whose
// output, put end to end, is uncompressedSize bytes exactly (3.1.9.1.2.1).
func (z *zgfxDecompressor) segmentedData(message []byte) ([]byte, error) {
	if len(message) < 2 {
		return nil, fmt.Errorf("%w: a %d-byte segmented message", ErrRDPGraphics, len(message))
	}
	switch message[0] {
	case zgfxSegmentSingle:
		return z.segment(message[1:], nil)
	case zgfxSegmentMulti:
		if len(message) < 7 {
			return nil, fmt.Errorf("%w: a multipart header cut short", ErrRDPGraphics)
		}
		count := int(binary.LittleEndian.Uint16(message[1:3]))
		size := binary.LittleEndian.Uint32(message[3:7])
		if count == 0 || size == 0 || size > maxGraphicsMessage {
			return nil, fmt.Errorf("%w: %d segment(s) for %d bytes", ErrRDPGraphics, count, size)
		}
		out := make([]byte, 0, size)
		rest := message[7:]
		for i := range count {
			if len(rest) < 4 {
				return nil, fmt.Errorf("%w: segment %d cut short", ErrRDPGraphics, i)
			}
			n := binary.LittleEndian.Uint32(rest[:4])
			if n == 0 || uint64(n) > uint64(len(rest)-4) {
				return nil, fmt.Errorf("%w: segment %d of %d bytes, %d left", ErrRDPGraphics, i, n, len(rest)-4)
			}
			var err error
			if out, err = z.segment(rest[4:4+n], out); err != nil {
				return nil, err
			}
			if uint64(len(out)) > uint64(size) {
				return nil, fmt.Errorf("%w: more than the %d bytes announced", ErrRDPGraphics, size)
			}
			rest = rest[4+n:]
		}
		if len(rest) != 0 || uint64(len(out)) != uint64(size) {
			return nil, fmt.Errorf("%w: %d bytes for %d announced, %d left over", ErrRDPGraphics, len(out), size, len(rest))
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: descriptor 0x%02x", ErrRDPGraphics, message[0])
}

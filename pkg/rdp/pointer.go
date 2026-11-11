package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
)

// The pointer the target shows, decoded and bounded (ADR-0091). The proxy draws it into each image
// it encodes, so that what the operator sees is what the Video Recorder acknowledges and an auditor
// replays (ADR-0071 §4). This file holds the parsers, the pointer cache and the drawing; it reads
// nothing from the network and keeps no image of the desktop.

// ErrRDPPointer is any pointer update outside the profile: it closes the session, like any other
// PDU this client does not accept.
var ErrRDPPointer = fmt.Errorf("%w: invalid pointer update", ErrMCSConnection)

const (
	// rdpPointerCacheSize is the number of shapes the client keeps, and the size it will announce
	// for both caches of the Pointer Capability Set (MS-RDPBCGR 2.2.7.1.5); FreeRDP announces 25.
	rdpPointerCacheSize = 25
	// rdpPointerMaxSide is the largest width and height of a shape when the client does not
	// announce large pointers (LARGE_POINTER_FLAG, MS-RDPBCGR 2.2.9.1.1.4.4): 32 pixels.
	rdpPointerMaxSide = 32

	rdpSystemPointerNull    = uint32(0x00000000)
	rdpSystemPointerDefault = uint32(0x00007f00)
)

// Fast-Path update codes of the pointer (MS-RDPBCGR 2.2.9.1.2.1).
const (
	rdpFastPathPointerHidden   = byte(0x5)
	rdpFastPathPointerDefault  = byte(0x6)
	rdpFastPathPointerPosition = byte(0x8)
	rdpFastPathPointerColor    = byte(0x9)
	rdpFastPathPointerCached   = byte(0xa)
	rdpFastPathPointerNew      = byte(0xb)
)

// messageType of a slow-path Pointer Update PDU (MS-RDPBCGR 2.2.9.1.1.4).
const (
	rdpPointerMessageSystem   = uint16(0x0001)
	rdpPointerMessagePosition = uint16(0x0003)
	rdpPointerMessageColor    = uint16(0x0006)
	rdpPointerMessageCached   = uint16(0x0007)
	rdpPointerMessageNew      = uint16(0x0008)
)

// RDPPointerKind says what a pointer update changes.
type RDPPointerKind uint8

const (
	RDPPointerHidden   RDPPointerKind = iota + 1 // the target hides its pointer
	RDPPointerDefault                            // the system's default arrow
	RDPPointerPosition                           // the target moves the pointer
	RDPPointerShape                              // a new shape, kept in the cache
	RDPPointerCached                             // a shape from the cache
)

// RDPPointerUpdate is one decoded pointer update.
type RDPPointerUpdate struct {
	Kind       RDPPointerKind
	X, Y       uint16 // RDPPointerPosition
	CacheIndex uint16 // RDPPointerShape and RDPPointerCached
	Shape      *RDPPointerImage
}

// RDPPointerImage is a decoded shape, top-down. Each pixel is either drawn over the desktop with its
// alpha (straight, not premultiplied), or, where XOR is set, combined with the desktop by an
// exclusive or of its colour, as the target's AND and XOR masks say (MS-RDPBCGR 2.2.9.1.1.4.4): a
// white XOR pixel inverts the desktop, a black one leaves it untouched.
type RDPPointerImage struct {
	Width, Height int
	HotX, HotY    int
	RGBA          []byte // Width*Height*4
	XOR           []bool // Width*Height
}

// parseRDPFastPathPointer decodes the payload of a Fast-Path pointer update: the bytes after its
// updateHeader and size, neither fragmented nor compressed.
func parseRDPFastPathPointer(code byte, payload []byte) (RDPPointerUpdate, error) {
	switch code {
	case rdpFastPathPointerHidden:
		if len(payload) != 0 {
			return RDPPointerUpdate{}, ErrRDPPointer
		}
		return RDPPointerUpdate{Kind: RDPPointerHidden}, nil
	case rdpFastPathPointerDefault:
		if len(payload) != 0 {
			return RDPPointerUpdate{}, ErrRDPPointer
		}
		return RDPPointerUpdate{Kind: RDPPointerDefault}, nil
	case rdpFastPathPointerPosition:
		return parseRDPPointerPosition(payload)
	case rdpFastPathPointerColor:
		return parseRDPColorPointer(payload, 24)
	case rdpFastPathPointerCached:
		return parseRDPCachedPointer(payload)
	case rdpFastPathPointerNew:
		return parseRDPNewPointer(payload)
	}
	return RDPPointerUpdate{}, ErrRDPPointer
}

// parseRDPPointerPDU decodes a slow-path Pointer Update PDU: the bytes after the Share Data Header
// (pduType2 0x1b), a messageType, two bytes of padding, then the attribute.
func parseRDPPointerPDU(data []byte) (RDPPointerUpdate, error) {
	if len(data) < 4 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	attribute := data[4:]
	switch binary.LittleEndian.Uint16(data[:2]) {
	case rdpPointerMessageSystem:
		if len(attribute) != 4 {
			return RDPPointerUpdate{}, ErrRDPPointer
		}
		switch binary.LittleEndian.Uint32(attribute) {
		case rdpSystemPointerNull:
			return RDPPointerUpdate{Kind: RDPPointerHidden}, nil
		case rdpSystemPointerDefault:
			return RDPPointerUpdate{Kind: RDPPointerDefault}, nil
		}
		return RDPPointerUpdate{}, ErrRDPPointer
	case rdpPointerMessagePosition:
		return parseRDPPointerPosition(attribute)
	case rdpPointerMessageColor:
		return parseRDPColorPointer(attribute, 24)
	case rdpPointerMessageCached:
		return parseRDPCachedPointer(attribute)
	case rdpPointerMessageNew:
		return parseRDPNewPointer(attribute)
	}
	return RDPPointerUpdate{}, ErrRDPPointer
}

// TS_POINTERPOSATTRIBUTE: xPos and yPos.
func parseRDPPointerPosition(data []byte) (RDPPointerUpdate, error) {
	if len(data) != 4 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	return RDPPointerUpdate{
		Kind: RDPPointerPosition,
		X:    binary.LittleEndian.Uint16(data[0:2]),
		Y:    binary.LittleEndian.Uint16(data[2:4]),
	}, nil
}

// TS_CACHEDPOINTERATTRIBUTE: a cache index.
func parseRDPCachedPointer(data []byte) (RDPPointerUpdate, error) {
	if len(data) != 2 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	index := binary.LittleEndian.Uint16(data)
	if index >= rdpPointerCacheSize {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	return RDPPointerUpdate{Kind: RDPPointerCached, CacheIndex: index}, nil
}

// TS_POINTERATTRIBUTE: xorBpp, then a colour pointer of that depth. Only 24 and 32 bits per pixel
// are decoded (ADR-0091); the other depths close the session.
func parseRDPNewPointer(data []byte) (RDPPointerUpdate, error) {
	if len(data) < 2 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	bpp := int(binary.LittleEndian.Uint16(data[:2]))
	if bpp != 24 && bpp != 32 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	return parseRDPColorPointer(data[2:], bpp)
}

// TS_COLORPOINTERATTRIBUTE (MS-RDPBCGR 2.2.9.1.1.4.4): cacheIndex, hotSpot, width, height,
// lengthAndMask, lengthXorMask, the XOR mask, the AND mask, and an optional byte of padding. Both
// masks are bottom-up and each of their scan lines is padded to two bytes. Every length must be the
// one width and height imply: nothing is read past them, and nothing else is left over.
func parseRDPColorPointer(data []byte, bpp int) (RDPPointerUpdate, error) {
	if len(data) < 14 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	index := binary.LittleEndian.Uint16(data[0:2])
	hotX := int(binary.LittleEndian.Uint16(data[2:4]))
	hotY := int(binary.LittleEndian.Uint16(data[4:6]))
	width := int(binary.LittleEndian.Uint16(data[6:8]))
	height := int(binary.LittleEndian.Uint16(data[8:10]))
	andLength := int(binary.LittleEndian.Uint16(data[10:12]))
	xorLength := int(binary.LittleEndian.Uint16(data[12:14]))
	if index >= rdpPointerCacheSize || width > rdpPointerMaxSide || height > rdpPointerMaxSide ||
		(width == 0) != (height == 0) {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	// An empty shape is legal and shows nothing; its hot spot can only be its origin.
	if width == 0 {
		if hotX != 0 || hotY != 0 {
			return RDPPointerUpdate{}, ErrRDPPointer
		}
	} else if hotX >= width || hotY >= height {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	xorLine := evenBytes((width*bpp + 7) / 8)
	andLine := evenBytes((width + 7) / 8)
	if xorLength != xorLine*height || andLength != andLine*height {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	masks := data[14:]
	if extra := len(masks) - xorLength - andLength; extra != 0 && extra != 1 {
		return RDPPointerUpdate{}, ErrRDPPointer
	}
	xorMask := masks[:xorLength]
	andMask := masks[xorLength : xorLength+andLength]

	shape := &RDPPointerImage{
		Width: width, Height: height, HotX: hotX, HotY: hotY,
		RGBA: make([]byte, width*height*4), XOR: make([]bool, width*height),
	}
	// A 32-bit shape whose alpha is zero everywhere carries no alpha: it is read as 24-bit.
	withAlpha := false
	if bpp == 32 {
		for y := 0; y < height && !withAlpha; y++ {
			for x := 0; x < width; x++ {
				if xorMask[y*xorLine+x*4+3] != 0 {
					withAlpha = true
					break
				}
			}
		}
	}
	step := bpp / 8
	for y := 0; y < height; y++ {
		source := height - 1 - y // bottom-up
		for x := 0; x < width; x++ {
			pixel := xorMask[source*xorLine+x*step:]
			blue, green, red := pixel[0], pixel[1], pixel[2]
			andBit := andMask[source*andLine+x/8]&(0x80>>(x%8)) != 0
			i := y*width + x
			out := shape.RGBA[i*4 : i*4+4]
			out[0], out[1], out[2] = red, green, blue
			switch {
			case withAlpha && !(andBit && pixel[3] == 0):
				out[3] = pixel[3]
			case andBit:
				// The desktop shows through, combined with the XOR colour: none when it is black.
				shape.XOR[i] = red|green|blue != 0
				if !shape.XOR[i] {
					out[0], out[1], out[2] = 0, 0, 0
				}
			default:
				out[3] = 0xff
			}
		}
	}
	return RDPPointerUpdate{Kind: RDPPointerShape, CacheIndex: index, Shape: shape}, nil
}

func evenBytes(n int) int { return (n + 1) &^ 1 }

// RDPPointer follows the pointer of one session: its shape, the shapes the target cached, whether it
// is hidden, and where it is. It is not safe for concurrent use; the session's reader owns it.
type RDPPointer struct {
	cache  [rdpPointerCacheSize]*RDPPointerImage
	shape  *RDPPointerImage
	hidden bool
	x, y   int
	placed bool // a position is known
}

// NewRDPPointer starts with the default arrow, at no known position: nothing is drawn until the
// operator or the target places it.
func NewRDPPointer() *RDPPointer { return &RDPPointer{shape: rdpDefaultPointer} }

// Apply follows one update from the target. A cached shape the target never sent closes the
// session: the cache is the client's, and a server that names an empty entry is outside the profile.
func (p *RDPPointer) Apply(update RDPPointerUpdate) error {
	switch update.Kind {
	case RDPPointerHidden:
		p.hidden = true
	case RDPPointerDefault:
		p.shape, p.hidden = rdpDefaultPointer, false
	case RDPPointerPosition:
		p.MoveTo(int(update.X), int(update.Y))
	case RDPPointerShape:
		if update.Shape == nil || update.CacheIndex >= rdpPointerCacheSize {
			return ErrRDPPointer
		}
		p.cache[update.CacheIndex] = update.Shape
		p.shape, p.hidden = update.Shape, false
	case RDPPointerCached:
		if update.CacheIndex >= rdpPointerCacheSize || p.cache[update.CacheIndex] == nil {
			return ErrRDPPointer
		}
		p.shape, p.hidden = p.cache[update.CacheIndex], false
	default:
		return ErrRDPPointer
	}
	return nil
}

// MoveTo places the pointer: where the operator's input sent it, or where the target moved it.
func (p *RDPPointer) MoveTo(x, y int) { p.x, p.y, p.placed = x, y, true }

// Reset forgets the cache and the shape, as a reactivation does (MS-RDPBCGR 1.3.1.3); the position
// stays, since the operator's mouse has not moved.
func (p *RDPPointer) Reset() {
	*p = RDPPointer{shape: rdpDefaultPointer, x: p.x, y: p.y, placed: p.placed}
}

// DrawOn draws the pointer over a copy of the desktop: the caller's image is the one that is
// encoded, never the framebuffer itself (ADR-0091 §1). The shape is clipped by the desktop, and
// nothing is drawn while the pointer is hidden or has no known position.
func (p *RDPPointer) DrawOn(desktop *image.RGBA) {
	if p == nil || desktop == nil || p.hidden || !p.placed || p.shape == nil {
		return
	}
	drawRDPPointer(desktop, p.shape, p.x, p.y)
}

func drawRDPPointer(desktop *image.RGBA, shape *RDPPointerImage, x, y int) {
	bounds := desktop.Bounds()
	left, top := x-shape.HotX, y-shape.HotY
	for row := 0; row < shape.Height; row++ {
		dy := top + row
		if dy < bounds.Min.Y || dy >= bounds.Max.Y {
			continue
		}
		for column := 0; column < shape.Width; column++ {
			dx := left + column
			if dx < bounds.Min.X || dx >= bounds.Max.X {
				continue
			}
			i := row*shape.Width + column
			source := shape.RGBA[i*4 : i*4+4]
			target := desktop.Pix[desktop.PixOffset(dx, dy):]
			if shape.XOR[i] {
				target[0] ^= source[0]
				target[1] ^= source[1]
				target[2] ^= source[2]
				continue
			}
			alpha := uint32(source[3])
			if alpha == 0 {
				continue
			}
			for c := 0; c < 3; c++ {
				target[c] = byte((uint32(source[c])*alpha + uint32(target[c])*(255-alpha) + 127) / 255)
			}
		}
	}
}

// rdpDefaultPointer is the arrow drawn for the system's default pointer: the shape of the target's
// own arrow is not sent (SYSPTR_DEFAULT names it), so the proxy has one of its own, black with a
// white outline, its hot spot at the tip.
var rdpDefaultPointer = mustRDPPointerFromArt([]string{
	"X...........",
	"XX..........",
	"XWX.........",
	"XWWX........",
	"XWWWX.......",
	"XWWWWX......",
	"XWWWWWX.....",
	"XWWWWWWX....",
	"XWWWWWWWX...",
	"XWWWWWWWWX..",
	"XWWWWWWWWWX.",
	"XWWWWWWXXXXX",
	"XWWWXWWX....",
	"XWWXXWWX....",
	"XWX..XWWX...",
	"XX...XWWX...",
	"X.....XWWX..",
	"......XWWX..",
	".......XX...",
})

// mustRDPPointerFromArt draws a shape from rows of text: X black, W white, anything else clear.
func mustRDPPointerFromArt(rows []string) *RDPPointerImage {
	if len(rows) == 0 || len(rows[0]) == 0 {
		panic(errors.New("rdp: empty pointer art"))
	}
	shape := &RDPPointerImage{Width: len(rows[0]), Height: len(rows)}
	shape.RGBA = make([]byte, shape.Width*shape.Height*4)
	shape.XOR = make([]bool, shape.Width*shape.Height)
	for y, row := range rows {
		if len(row) != shape.Width {
			panic(errors.New("rdp: ragged pointer art"))
		}
		for x, c := range row {
			out := shape.RGBA[(y*shape.Width+x)*4:]
			switch c {
			case 'X':
				out[3] = 0xff
			case 'W':
				out[0], out[1], out[2], out[3] = 0xff, 0xff, 0xff, 0xff
			}
		}
	}
	return shape
}

package vnc

import (
	"encoding/binary"
	"image"
	"io"
)

// The target's pointer, drawn into the frames (ADR-0091, increment 3). With the Cursor
// pseudo-encoding the target leaves its pointer out of the framebuffer and sends its shape; the
// proxy draws that shape where the operator put the pointer, on a copy of the framebuffer, so the
// frame shown is the frame recorded (ADR-0071 §4).

// maxCursorSide bounds a cursor's width, height and hot spot. RFB sets none; X cursor themes go to
// 64 pixels and more on large screens. Beyond it, the session ends, as for any update out of bounds.
const maxCursorSide = 128

// cursor is a decoded shape, top-down, straight RGBA: a pixel is opaque where the target's bitmask
// is set and clear where it is not. An empty cursor (0×0) is the target hiding its pointer.
type cursor struct {
	width, height int
	hotX, hotY    int
	rgba          []byte
}

// readCursor reads the body of a Cursor rectangle (encoding -239): width×height pixels in the
// session's pixel format (32 bits, little-endian, red at bit 16), then a bitmask of (width+7)/8
// bytes a row, most significant bit first. The rectangle's x and y are the hot spot.
func readCursor(r io.Reader, hotX, hotY, width, height uint16) (*cursor, error) {
	if width > maxCursorSide || height > maxCursorSide || hotX >= maxCursorSide || hotY >= maxCursorSide ||
		(width == 0) != (height == 0) {
		return nil, ErrInvalidFramebuffer
	}
	c := &cursor{width: int(width), height: int(height), hotX: int(hotX), hotY: int(hotY)}
	if width == 0 {
		return c, nil
	}
	pixels := make([]byte, c.width*c.height*4)
	if _, err := io.ReadFull(r, pixels); err != nil {
		return nil, err
	}
	maskLine := (c.width + 7) / 8
	mask := make([]byte, maskLine*c.height)
	if _, err := io.ReadFull(r, mask); err != nil {
		return nil, err
	}
	c.rgba = make([]byte, len(pixels))
	for y := 0; y < c.height; y++ {
		for x := 0; x < c.width; x++ {
			i := (y*c.width + x) * 4
			if mask[y*maskLine+x/8]&(0x80>>(x%8)) == 0 {
				continue
			}
			value := binary.LittleEndian.Uint32(pixels[i:])
			c.rgba[i], c.rgba[i+1], c.rgba[i+2], c.rgba[i+3] = byte(value>>16), byte(value>>8), byte(value), 0xff
		}
	}
	return c, nil
}

// drawOn draws the cursor with its hot spot at (x, y), clipped by the image.
func (c *cursor) drawOn(img *image.RGBA, x, y int) {
	if c == nil || c.width == 0 {
		return
	}
	bounds := img.Bounds()
	left, top := x-c.hotX, y-c.hotY
	for row := 0; row < c.height; row++ {
		dy := top + row
		if dy < bounds.Min.Y || dy >= bounds.Max.Y {
			continue
		}
		for column := 0; column < c.width; column++ {
			dx := left + column
			if dx < bounds.Min.X || dx >= bounds.Max.X {
				continue
			}
			source := c.rgba[(row*c.width+column)*4:]
			if source[3] == 0 {
				continue
			}
			copy(img.Pix[img.PixOffset(dx, dy):], source[:4])
		}
	}
}

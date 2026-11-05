package rdp

import (
	"bytes"
	"errors"
	"image"
	"image/draw"
	"image/png"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

const maxRDPFramebufferBytes = screenstream.MaxPixels * 4

var ErrRDPFramebuffer = errors.New("rdp: invalid framebuffer update")

// RDPFramebuffer maintains the complete desktop image. RDP Bitmap Updates are
// partial rectangles; the screenstream v1 contract carries complete PNG frames,
// so each accepted update is applied atomically and encoded as a full image.
// It is intentionally independent of network/session lifecycle.
type RDPFramebuffer struct {
	mu       sync.Mutex
	image    *image.RGBA
	sequence uint64
}

// NewRDPFramebuffer allocates a bounded 32-bit RGBA framebuffer.
func NewRDPFramebuffer(width, height uint16) (*RDPFramebuffer, error) {
	if width == 0 || height == 0 || uint64(width)*uint64(height) > screenstream.MaxPixels ||
		uint64(width)*uint64(height)*4 > maxRDPFramebufferBytes {
		return nil, ErrRDPFramebuffer
	}
	frame := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	// A not-yet-painted desktop is opaque black, never transparent.
	for i := 3; i < len(frame.Pix); i += 4 {
		frame.Pix[i] = 0xff
	}
	return &RDPFramebuffer{image: frame}, nil
}

// Apply validates every rectangle before changing the framebuffer, applies
// replacement, solid-brush, destination-only, and screen-copy operations, and returns the next complete
// PNG frame. Sequence numbers are strictly increasing and are committed only
// after PNG encoding succeeds.
func (f *RDPFramebuffer) Apply(update RDPBitmapUpdate, timestamp time.Time) (screenstream.Message, error) {
	if f == nil {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil || timestamp.IsZero() || len(update.Rectangles) == 0 ||
		len(update.Rectangles) > maxRDPBitmapRects || f.sequence == ^uint64(0) {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	bounds := f.image.Bounds()
	var totalPixels uint64
	for _, rect := range update.Rectangles {
		pixels := uint64(rect.Width) * uint64(rect.Height)
		if rect.operation == rdpBitmapRectangleLine {
			pixels = uint64(len(rect.linePoints))
			if rect.Width != 1 || rect.Height != 1 || len(rect.Pixels) != 0 || len(rect.linePoints) == 0 ||
				len(rect.linePoints) > maxRDPLinePixels || rect.lineColor[3] != 0xff {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
			for _, point := range rect.linePoints {
				if point[0] >= uint16(bounds.Dx()) || point[1] >= uint16(bounds.Dy()) {
					return screenstream.Message{}, ErrRDPFramebuffer
				}
			}
		}
		if rect.Width == 0 || rect.Height == 0 || uint32(rect.X)+uint32(rect.Width) > uint32(bounds.Dx()) ||
			uint32(rect.Y)+uint32(rect.Height) > uint32(bounds.Dy()) || pixels > screenstream.MaxPixels-totalPixels {
			return screenstream.Message{}, ErrRDPFramebuffer
		}
		switch rect.operation {
		case rdpBitmapRectangleReplace:
			if pixels*4 != uint64(len(rect.Pixels)) {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
		case rdpBitmapRectangleDstInvert:
			if len(rect.Pixels) != 0 {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
		case rdpBitmapRectanglePatInvert, rdpBitmapRectanglePatAnd, rdpBitmapRectanglePatOr:
			if pixels*4 != uint64(len(rect.Pixels)) {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
		case rdpBitmapRectangleScrCopy:
			if len(rect.Pixels) != 0 || uint32(rect.sourceX)+uint32(rect.Width) > uint32(bounds.Dx()) ||
				uint32(rect.sourceY)+uint32(rect.Height) > uint32(bounds.Dy()) {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
		case rdpBitmapRectangleLine:
			// Line points and color were validated above.
		default:
			return screenstream.Message{}, ErrRDPFramebuffer
		}
		totalPixels += pixels
	}
	previous := make([][]byte, len(update.Rectangles))
	for i, rect := range update.Rectangles {
		if rect.operation == rdpBitmapRectangleLine {
			previous[i] = make([]byte, len(rect.linePoints)*4)
			for pointIndex, point := range rect.linePoints {
				start := f.image.PixOffset(int(point[0]), int(point[1]))
				copy(previous[i][pointIndex*4:], f.image.Pix[start:start+4])
			}
		} else {
			previous[i] = make([]byte, int(rect.Width)*int(rect.Height)*4)
		}
		for y := 0; rect.operation != rdpBitmapRectangleLine && y < int(rect.Height); y++ {
			start := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
			copy(previous[i][y*int(rect.Width)*4:], f.image.Pix[start:start+int(rect.Width)*4])
		}
		switch rect.operation {
		case rdpBitmapRectangleReplace:
			dst := image.Rect(int(rect.X), int(rect.Y), int(rect.X)+int(rect.Width), int(rect.Y)+int(rect.Height))
			src := &image.RGBA{Pix: rect.Pixels, Stride: int(rect.Width) * 4, Rect: image.Rect(0, 0, int(rect.Width), int(rect.Height))}
			draw.Draw(f.image, dst, src, src.Bounds().Min, draw.Src)
		case rdpBitmapRectangleDstInvert:
			for y := 0; y < int(rect.Height); y++ {
				start := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
				for x := 0; x < int(rect.Width); x++ {
					offset := start + x*4
					f.image.Pix[offset] ^= 0xff
					f.image.Pix[offset+1] ^= 0xff
					f.image.Pix[offset+2] ^= 0xff
				}
			}
		case rdpBitmapRectanglePatInvert:
			for y := 0; y < int(rect.Height); y++ {
				start := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
				for x := 0; x < int(rect.Width); x++ {
					dstOffset := start + x*4
					srcOffset := (y*int(rect.Width) + x) * 4
					f.image.Pix[dstOffset] ^= rect.Pixels[srcOffset]
					f.image.Pix[dstOffset+1] ^= rect.Pixels[srcOffset+1]
					f.image.Pix[dstOffset+2] ^= rect.Pixels[srcOffset+2]
				}
			}
		case rdpBitmapRectanglePatAnd, rdpBitmapRectanglePatOr:
			for y := 0; y < int(rect.Height); y++ {
				start := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
				for x := 0; x < int(rect.Width); x++ {
					dstOffset := start + x*4
					srcOffset := (y*int(rect.Width) + x) * 4
					for channel := 0; channel < 3; channel++ {
						if rect.operation == rdpBitmapRectanglePatAnd {
							f.image.Pix[dstOffset+channel] &= rect.Pixels[srcOffset+channel]
						} else {
							f.image.Pix[dstOffset+channel] |= rect.Pixels[srcOffset+channel]
						}
					}
				}
			}
		case rdpBitmapRectangleLine:
			for _, point := range rect.linePoints {
				offset := f.image.PixOffset(int(point[0]), int(point[1]))
				copy(f.image.Pix[offset:offset+4], rect.lineColor[:])
			}
		case rdpBitmapRectangleScrCopy:
			source := make([]byte, int(rect.Width)*int(rect.Height)*4)
			for y := 0; y < int(rect.Height); y++ {
				sourceStart := f.image.PixOffset(int(rect.sourceX), int(rect.sourceY)+y)
				copy(source[y*int(rect.Width)*4:], f.image.Pix[sourceStart:sourceStart+int(rect.Width)*4])
			}
			for y := 0; y < int(rect.Height); y++ {
				destinationStart := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
				copy(f.image.Pix[destinationStart:destinationStart+int(rect.Width)*4], source[y*int(rect.Width)*4:])
			}
			clear(source)
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, f.image); err != nil || encoded.Len() == 0 || encoded.Len() > screenstream.MaxPNGBytes {
		for i := len(update.Rectangles) - 1; i >= 0; i-- {
			rect := update.Rectangles[i]
			if rect.operation == rdpBitmapRectangleLine {
				for pointIndex, point := range rect.linePoints {
					start := f.image.PixOffset(int(point[0]), int(point[1]))
					copy(f.image.Pix[start:start+4], previous[i][pointIndex*4:])
				}
			} else {
				for y := 0; y < int(rect.Height); y++ {
					start := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
					copy(f.image.Pix[start:start+int(rect.Width)*4], previous[i][y*int(rect.Width)*4:])
				}
			}
		}
		for _, old := range previous {
			clear(old)
		}
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	for _, old := range previous {
		clear(old)
	}
	f.sequence++
	message := screenstream.Message{
		Type: screenstream.TypeFrame, Sequence: f.sequence, Timestamp: timestamp.UTC(),
		Width: uint32(bounds.Dx()), Height: uint32(bounds.Dy()), PNG: encoded.Bytes(),
	}
	if _, err := screenstream.Encode(message); err != nil {
		f.sequence--
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	return message, nil
}

// Dimensions returns the fixed desktop dimensions, or zeroes for an invalid receiver.
func (f *RDPFramebuffer) Dimensions() (uint32, uint32) {
	if f == nil {
		return 0, 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil {
		return 0, 0
	}
	return uint32(f.image.Bounds().Dx()), uint32(f.image.Bounds().Dy())
}

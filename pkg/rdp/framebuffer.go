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

// applyRDPROP2 applies the supported two-operand raster operation to RGB while
// keeping the internal framebuffer alpha opaque.
func applyRDPROP2(destination []byte, pen [4]byte, operation byte) {
	switch operation {
	case rdpROP2Black:
		clear(destination[:3])
	case rdpROP2CopyPen:
		copy(destination[:3], pen[:3])
	case rdpROP2Not:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = ^destination[channel]
		}
	case rdpROP2XorPen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] ^= pen[channel]
		}
	case rdpROP2NotXorPen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = ^(destination[channel] ^ pen[channel])
		}
	case rdpROP2White:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = 0xff
		}
	}
	destination[3] = 0xff
}

// Apply validates every operation before changing the framebuffer, applies
// replacement, solid-brush, destination-only, line, polygon, ellipse and screen-copy
// operations, and returns the next complete PNG frame. Sequence numbers are
// strictly increasing and committed only after PNG encoding succeeds.
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
	polygonSpans := make([][]rdpBitmapSpan, len(update.Rectangles))
	ellipseSpans := make([][]rdpBitmapSpan, len(update.Rectangles))
	for index, rect := range update.Rectangles {
		pixels := uint64(rect.Width) * uint64(rect.Height)
		if rect.operation == rdpBitmapRectangleLine {
			pixels = uint64(len(rect.linePoints))
			if rect.Width != 1 || rect.Height != 1 || len(rect.Pixels) != 0 || len(rect.linePoints) == 0 ||
				len(rect.linePoints) > maxRDPLinePixels || rect.lineColor[3] != 0xff ||
				!isSupportedRDPROP2(rect.lineROP2) {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
			for _, point := range rect.linePoints {
				if point[0] >= uint16(bounds.Dx()) || point[1] >= uint16(bounds.Dy()) {
					return screenstream.Message{}, ErrRDPFramebuffer
				}
			}
		}
		if rect.operation == rdpBitmapRectanglePolygon {
			spans, polygonBounds, polygonPixels, polygonErr := rasterizeRDPPolygon(rect.polygonPoints, rect.polygonFillMode, uint16(bounds.Dx()), uint16(bounds.Dy()))
			if polygonErr != nil || !isSupportedRDPROP2(rect.polygonROP2) ||
				len(rect.Pixels) != 0 || len(rect.linePoints) != 0 || rect.polygonColor[3] != 0xff ||
				rect.X != polygonBounds[0] || rect.Y != polygonBounds[1] || rect.Width != polygonBounds[2] || rect.Height != polygonBounds[3] {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
			polygonSpans[index] = spans
			pixels = polygonPixels
		}
		if rect.operation == rdpBitmapRectangleEllipse {
			spans, ellipseBounds, ellipsePixels, ellipseErr := rasterizeRDPEllipse(rect.X, rect.Y, rect.Width, rect.Height, uint16(bounds.Dx()), uint16(bounds.Dy()))
			if ellipseErr != nil || !isSupportedRDPROP2(rect.ellipseROP2) ||
				len(rect.Pixels) != 0 || len(rect.linePoints) != 0 || len(rect.polygonPoints) != 0 || rect.ellipseColor[3] != 0xff ||
				rect.X != ellipseBounds[0] || rect.Y != ellipseBounds[1] || rect.Width != ellipseBounds[2] || rect.Height != ellipseBounds[3] {
				return screenstream.Message{}, ErrRDPFramebuffer
			}
			ellipseSpans[index] = spans
			pixels = ellipsePixels
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
		case rdpBitmapRectanglePolygon:
			// Polygon spans, bounds and color were validated above.
		case rdpBitmapRectangleEllipse:
			// Ellipse spans, bounds and color were validated above.
		default:
			return screenstream.Message{}, ErrRDPFramebuffer
		}
		totalPixels += pixels
	}
	previous := make([][]byte, len(update.Rectangles))
	for i, rect := range update.Rectangles {
		switch rect.operation {
		case rdpBitmapRectangleLine:
			previous[i] = make([]byte, len(rect.linePoints)*4)
			for pointIndex, point := range rect.linePoints {
				start := f.image.PixOffset(int(point[0]), int(point[1]))
				copy(previous[i][pointIndex*4:], f.image.Pix[start:start+4])
			}
		case rdpBitmapRectanglePolygon:
			var previousBytes int
			for _, span := range polygonSpans[i] {
				previousBytes += int(span.Width) * 4
			}
			previous[i] = make([]byte, 0, previousBytes)
			for _, span := range polygonSpans[i] {
				start := f.image.PixOffset(int(span.X), int(span.Y))
				end := start + int(span.Width)*4
				previous[i] = append(previous[i], f.image.Pix[start:end]...)
			}
		case rdpBitmapRectangleEllipse:
			var previousBytes int
			for _, span := range ellipseSpans[i] {
				previousBytes += int(span.Width) * 4
			}
			previous[i] = make([]byte, 0, previousBytes)
			for _, span := range ellipseSpans[i] {
				start := f.image.PixOffset(int(span.X), int(span.Y))
				end := start + int(span.Width)*4
				previous[i] = append(previous[i], f.image.Pix[start:end]...)
			}
		default:
			previous[i] = make([]byte, int(rect.Width)*int(rect.Height)*4)
			for y := 0; y < int(rect.Height); y++ {
				start := f.image.PixOffset(int(rect.X), int(rect.Y)+y)
				copy(previous[i][y*int(rect.Width)*4:], f.image.Pix[start:start+int(rect.Width)*4])
			}
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
				applyRDPROP2(f.image.Pix[offset:offset+4], rect.lineColor, rect.lineROP2)
			}
		case rdpBitmapRectanglePolygon:
			for _, span := range polygonSpans[i] {
				start := f.image.PixOffset(int(span.X), int(span.Y))
				for x := 0; x < int(span.Width); x++ {
					pixel := f.image.Pix[start+x*4 : start+x*4+4]
					applyRDPROP2(pixel, rect.polygonColor, rect.polygonROP2)
				}
			}
		case rdpBitmapRectangleEllipse:
			for _, span := range ellipseSpans[i] {
				start := f.image.PixOffset(int(span.X), int(span.Y))
				for x := 0; x < int(span.Width); x++ {
					pixel := f.image.Pix[start+x*4 : start+x*4+4]
					applyRDPROP2(pixel, rect.ellipseColor, rect.ellipseROP2)
				}
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
			switch rect.operation {
			case rdpBitmapRectangleLine:
				for pointIndex, point := range rect.linePoints {
					start := f.image.PixOffset(int(point[0]), int(point[1]))
					copy(f.image.Pix[start:start+4], previous[i][pointIndex*4:])
				}
			case rdpBitmapRectanglePolygon:
				pixelOffset := 0
				for _, span := range polygonSpans[i] {
					start := f.image.PixOffset(int(span.X), int(span.Y))
					length := int(span.Width) * 4
					copy(f.image.Pix[start:start+length], previous[i][pixelOffset:pixelOffset+length])
					pixelOffset += length
				}
			case rdpBitmapRectangleEllipse:
				pixelOffset := 0
				for _, span := range ellipseSpans[i] {
					start := f.image.PixOffset(int(span.X), int(span.Y))
					length := int(span.Width) * 4
					copy(f.image.Pix[start:start+length], previous[i][pixelOffset:pixelOffset+length])
					pixelOffset += length
				}
			default:
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

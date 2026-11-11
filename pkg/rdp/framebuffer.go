package rdp

import (
	"bytes"
	"errors"
	"fmt"
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
	// partial makes key frames and partial frames (ADR-0092) when set: EnablePartialFrames.
	partial *screenstream.FrameEncoder
}

// EnablePartialFrames has the frames be partial ones, of what changed since the frame before,
// anchored on key frames every keyInterval or keyFrames frames (ADR-0092). Zero takes the defaults.
func (f *RDPFramebuffer) EnablePartialFrames(keyInterval time.Duration, keyFrames int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.partial = &screenstream.FrameEncoder{KeyInterval: keyInterval, KeyFrames: keyFrames}
}

// ForceKeyFrame has the next frame be a key frame: after a reactivation (ADR-0092 §3).
func (f *RDPFramebuffer) ForceKeyFrame() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.partial != nil {
		f.partial.Reset()
	}
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

// Resize replaces the desktop with an opaque black one of a new size, as a reactivation leaves it
// (MS-RDPBCGR 1.3.1.3): the server draws it again. The sequence carries on, as the stream does.
// The same size changes nothing.
func (f *RDPFramebuffer) Resize(width, height uint16) error {
	fresh, err := NewRDPFramebuffer(width, height)
	if f == nil || err != nil {
		return ErrRDPFramebuffer
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil {
		return ErrRDPFramebuffer
	}
	if f.image.Bounds().Dx() != int(width) || f.image.Bounds().Dy() != int(height) {
		f.image = fresh.image
	}
	return nil
}

// applyRDPROP2 applies the supported two-operand raster operation to RGB while
// keeping the internal framebuffer alpha opaque.
func applyRDPROP2(destination []byte, pen [4]byte, operation byte) {
	switch operation {
	case rdpROP2Black:
		clear(destination[:3])
	case rdpROP2NotMergePen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = ^(destination[channel] | pen[channel])
		}
	case rdpROP2MergeNotPen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] |= ^pen[channel]
		}
	case rdpROP2MaskNotPen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] &= ^pen[channel]
		}
	case rdpROP2NotCopyPen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = ^pen[channel]
		}
	case rdpROP2MaskPenNot:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = pen[channel] & ^destination[channel]
		}
	case rdpROP2MaskPen:
		for channel := 0; channel < 3; channel++ {
			destination[channel] &= pen[channel]
		}
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
	case rdpROP2Nop:
		// R2_NOP preserves the destination RGB value.
	case rdpROP2White:
		for channel := 0; channel < 3; channel++ {
			destination[channel] = 0xff
		}
	}
	destination[3] = 0xff
}

// Unchanged reports that update only repaints what is already shown. A server may resend its screen
// many times a second (FreeRDP's shadow: about 50): each frame costs a PNG and a recorded,
// acknowledged segment, for nothing to see. Only plain replacements can be judged; anything else
// counts as a change, so that nothing is lost by being wrongly skipped.
func (f *RDPFramebuffer) Unchanged(update RDPBitmapUpdate) bool {
	if f == nil || len(update.Rectangles) == 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil {
		return false
	}
	bounds := f.image.Bounds()
	for _, rect := range update.Rectangles {
		rowBytes := int(rect.Width) * 4
		if rect.operation != rdpBitmapRectangleReplace || rect.Width == 0 || rect.Height == 0 ||
			int(rect.X)+int(rect.Width) > bounds.Dx() || int(rect.Y)+int(rect.Height) > bounds.Dy() ||
			len(rect.Pixels) != rowBytes*int(rect.Height) {
			return false
		}
		for row := 0; row < int(rect.Height); row++ {
			start := f.image.PixOffset(int(rect.X), int(rect.Y)+row)
			if !bytes.Equal(f.image.Pix[start:start+rowBytes], rect.Pixels[row*rowBytes:(row+1)*rowBytes]) {
				return false
			}
		}
	}
	return true
}

// Apply validates every operation before changing the framebuffer, applies
// replacement, solid-brush, destination-only, line, polygon, ellipse and screen-copy
// operations, and returns the next complete PNG frame. Sequence numbers are
// strictly increasing and committed only after PNG encoding succeeds.
func (f *RDPFramebuffer) Apply(update RDPBitmapUpdate, timestamp time.Time) (screenstream.Message, error) {
	return f.apply(update, timestamp, true)
}

// Draw applies an update without making a frame of it: the frames are taken at a cadence (Frame),
// not one per update (ADR-0071 §8). It validates exactly as Apply does, and leaves the
// framebuffer as it was on any refusal.
func (f *RDPFramebuffer) Draw(update RDPBitmapUpdate) error {
	_, err := f.apply(update, time.Now(), false)
	return err
}

// Frame encodes the desktop as it is now, as the next frame. A screen whose PNG is past 4 MiB
// cannot be recorded: screenstream.ErrFrameTooLarge, which ends the session as a recording loss.
func (f *RDPFramebuffer) Frame(timestamp time.Time) (screenstream.Message, error) {
	return f.FrameWithPointer(timestamp, nil)
}

// FrameWithPointer is Frame with the pointer drawn over the desktop (ADR-0091): on a copy, which
// is the image encoded, shown and recorded; the framebuffer itself stays the target's screen. A nil,
// hidden or unplaced pointer draws nothing, and the frame is Frame's.
func (f *RDPFramebuffer) FrameWithPointer(timestamp time.Time, pointer *RDPPointer) (screenstream.Message, error) {
	if f == nil {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil || timestamp.IsZero() || f.sequence == ^uint64(0) {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	picture := f.image
	if pointer.drawable() {
		picture = &image.RGBA{Pix: append([]byte(nil), f.image.Pix...), Stride: f.image.Stride, Rect: f.image.Rect}
		pointer.DrawOn(picture)
	}
	if f.partial != nil {
		// The pointer's old and new places are what differs from the frame before: two small
		// rectangles (ADR-0092 §4). An unchanged picture is screenstream.ErrUnchanged: no frame.
		message, err := f.partial.Encode(picture, f.sequence+1, timestamp)
		if errors.Is(err, screenstream.ErrUnchanged) {
			return screenstream.Message{}, err
		}
		if errors.Is(err, screenstream.ErrFrameTooLarge) {
			return screenstream.Message{}, fmt.Errorf("%w: %w", ErrRDPFramebuffer, err)
		}
		if err != nil {
			return screenstream.Message{}, ErrRDPFramebuffer
		}
		f.sequence++
		return message, nil
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, picture); err != nil || encoded.Len() == 0 {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	if encoded.Len() > screenstream.MaxPNGBytes {
		return screenstream.Message{}, fmt.Errorf("%w: %d-byte PNG: %w", ErrRDPFramebuffer, encoded.Len(), screenstream.ErrFrameTooLarge)
	}
	bounds := f.image.Bounds()
	message := screenstream.Message{
		Type: screenstream.TypeFrame, Sequence: f.sequence + 1, Timestamp: timestamp.UTC(),
		Width: uint32(bounds.Dx()), Height: uint32(bounds.Dy()), PNG: encoded.Bytes(),
	}
	if _, err := screenstream.Encode(message); err != nil {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	f.sequence++
	return message, nil
}

func (f *RDPFramebuffer) apply(update RDPBitmapUpdate, timestamp time.Time, encode bool) (screenstream.Message, error) {
	if f == nil {
		return screenstream.Message{}, ErrRDPFramebuffer
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil || timestamp.IsZero() || len(update.Rectangles) == 0 ||
		len(update.Rectangles) > maxRDPBitmapUpdateRects || f.sequence == ^uint64(0) {
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
	if !encode {
		for _, old := range previous {
			clear(old)
		}
		return screenstream.Message{}, nil
	}
	var encoded bytes.Buffer
	encodeErr := png.Encode(&encoded, f.image)
	if encodeErr != nil || encoded.Len() == 0 || encoded.Len() > screenstream.MaxPNGBytes {
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
		if encodeErr == nil && encoded.Len() > screenstream.MaxPNGBytes {
			// Not drawn, and said: a screen that cannot be recorded ends the session as a
			// recording loss (ADR-0070), never truncated.
			return screenstream.Message{}, fmt.Errorf("%w: %d-byte PNG: %w", ErrRDPFramebuffer, encoded.Len(), screenstream.ErrFrameTooLarge)
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

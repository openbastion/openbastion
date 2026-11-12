package screenstream

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"time"
)

// FrameEncoder makes the frames of ADR-0092: a key frame, then partial frames of what differs from
// the frame before, and a key frame again on a size change and at least every KeyInterval or
// KeyFrames frames. What differs is found by comparing the picture to the previous one, tile by
// tile: whatever drew it (a bitmap, an order, the pointer), the partial frame is exactly what
// changed, and composing it on the previous frame gives the picture back.
type FrameEncoder struct {
	// KeyInterval and KeyFrames bound the distance between two key frames (ADR-0092 §3): an
	// auditor can start a replay at any key frame without replaying the session before it.
	KeyInterval time.Duration
	KeyFrames   int

	last      *image.RGBA
	lastKeyAt time.Time
	sinceKey  int
}

// The defaults of ADR-0092 §3, and the tile the comparison works in.
const (
	DefaultKeyInterval = 10 * time.Second
	DefaultKeyFrames   = 300
	deltaTile          = 32
)

// ErrUnchanged is a picture that is the previous frame's, pixel for pixel: there is no frame to make.
var ErrUnchanged = errors.New("screenstream: the picture has not changed")

// Encode makes the frame of sequence for picture, which it does not keep: the caller may reuse it.
// A partial frame whose rectangles would cover more than half the picture, or be more than
// MaxDeltaRects, or not fit in MaxPNGBytes, is made a key frame instead (ADR-0092 §2). A key frame
// past MaxPNGBytes is ErrFrameTooLarge, as before.
func (e *FrameEncoder) Encode(picture *image.RGBA, sequence uint64, timestamp time.Time) (Message, error) {
	if picture == nil || sequence == 0 || timestamp.IsZero() {
		return Message{}, ErrMalformedMessage
	}
	bounds := picture.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	keyInterval, keyFrames := e.KeyInterval, e.KeyFrames
	if keyInterval <= 0 {
		keyInterval = DefaultKeyInterval
	}
	if keyFrames <= 0 {
		keyFrames = DefaultKeyFrames
	}
	key := e.last == nil || e.last.Bounds() != bounds ||
		timestamp.Sub(e.lastKeyAt) >= keyInterval || e.sinceKey+1 >= keyFrames
	if !key {
		rects, area := changedRects(e.last, picture)
		if len(rects) == 0 {
			return Message{}, ErrUnchanged
		}
		if len(rects) <= MaxDeltaRects && 2*area <= width*height {
			message := Message{Type: TypeFrameDelta, Sequence: sequence, Timestamp: timestamp.UTC(),
				Width: uint32(width), Height: uint32(height)}
			for _, r := range rects {
				encoded, err := encodePNG(picture.SubImage(r.Add(bounds.Min)))
				if err != nil {
					return Message{}, err
				}
				message.Rects = append(message.Rects, Rect{X: uint32(r.Min.X), Y: uint32(r.Min.Y),
					Width: uint32(r.Dx()), Height: uint32(r.Dy()), PNG: encoded})
			}
			if _, err := validateDelta(message); err == nil {
				e.remember(picture, false, timestamp)
				return message, nil
			} else if !errors.Is(err, ErrFrameTooLarge) {
				return Message{}, err
			}
			// Too large as rectangles: the whole picture, as a key frame.
		}
	}
	encoded, err := encodePNG(picture)
	if err != nil {
		return Message{}, err
	}
	if len(encoded) > MaxPNGBytes {
		return Message{}, fmt.Errorf("%w: %d-byte PNG", ErrFrameTooLarge, len(encoded))
	}
	message := Message{Type: TypeFrame, Sequence: sequence, Timestamp: timestamp.UTC(),
		Width: uint32(width), Height: uint32(height), PNG: encoded}
	if err := validateFrame(message); err != nil {
		return Message{}, err
	}
	e.remember(picture, true, timestamp)
	return message, nil
}

// Reset forgets the previous frame: the next one is a key frame.
func (e *FrameEncoder) Reset() { e.last = nil }

func (e *FrameEncoder) remember(picture *image.RGBA, key bool, timestamp time.Time) {
	bounds := picture.Bounds()
	if e.last == nil || e.last.Bounds() != bounds {
		e.last = image.NewRGBA(bounds)
	}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		copy(e.last.Pix[e.last.PixOffset(bounds.Min.X, y):e.last.PixOffset(bounds.Max.X-1, y)+4],
			picture.Pix[picture.PixOffset(bounds.Min.X, y):picture.PixOffset(bounds.Max.X-1, y)+4])
	}
	if key {
		e.lastKeyAt, e.sinceKey = timestamp, 0
	} else {
		e.sinceKey++
	}
}

// changedRects compares two pictures of the same bounds tile by tile, and returns the changed
// tiles as rectangles relative to the pictures' origin: the changed tiles of a row of tiles merged
// into runs, and a run merged with the one right above it when they span the same columns. It also
// returns the rectangles' total area.
func changedRects(previous, next *image.RGBA) ([]image.Rectangle, int) {
	bounds := next.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	columns, rows := (width+deltaTile-1)/deltaTile, (height+deltaTile-1)/deltaTile
	var rects []image.Rectangle
	open := map[[2]int]int{} // a run's columns -> its rectangle, for the row of tiles just above
	area := 0
	for row := 0; row < rows; row++ {
		y0, y1 := row*deltaTile, min((row+1)*deltaTile, height)
		changed := make([]bool, columns)
		for y := y0; y < y1; y++ {
			for column := 0; column < columns; column++ {
				if changed[column] {
					continue
				}
				x0, x1 := column*deltaTile, min((column+1)*deltaTile, width)
				a := previous.Pix[previous.PixOffset(bounds.Min.X+x0, bounds.Min.Y+y) : previous.PixOffset(bounds.Min.X+x1-1, bounds.Min.Y+y)+4]
				b := next.Pix[next.PixOffset(bounds.Min.X+x0, bounds.Min.Y+y) : next.PixOffset(bounds.Min.X+x1-1, bounds.Min.Y+y)+4]
				changed[column] = !bytes.Equal(a, b)
			}
		}
		nextOpen := map[[2]int]int{}
		for column := 0; column < columns; {
			if !changed[column] {
				column++
				continue
			}
			start := column
			for column < columns && changed[column] {
				column++
			}
			span := [2]int{start, column}
			x0, x1 := start*deltaTile, min(column*deltaTile, width)
			if i, ok := open[span]; ok {
				rects[i].Max.Y = y1
				nextOpen[span] = i
			} else {
				rects = append(rects, image.Rect(x0, y0, x1, y1))
				nextOpen[span] = len(rects) - 1
			}
			area += (x1 - x0) * (y1 - y0)
		}
		open = nextOpen
	}
	return rects, area
}

func encodePNG(img image.Image) ([]byte, error) {
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
	}
	return out.Bytes(), nil
}

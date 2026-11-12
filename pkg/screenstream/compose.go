package screenstream

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
)

// The reference composition of ADR-0092: what the operator's page and the auditor's replay do with
// key frames and partial frames, written once in Go so that tests can say what the screen is at any
// sequence. A key frame replaces the screen; a partial frame replaces the pixels of its rectangles,
// without blending, on the screen of the sequence just before it and on no other.

var (
	// ErrNoKeyFrame is a partial frame before any key frame: there is nothing to apply it to.
	ErrNoKeyFrame = errors.New("screenstream: partial frame without a key frame before it")
	// ErrSequenceGap is a partial frame that does not follow the previous frame: the screen it
	// changes is not the one composed.
	ErrSequenceGap = errors.New("screenstream: partial frame after a gap in the sequence")
)

// Composer holds the screen as composed so far. It is not safe for concurrent use.
type Composer struct {
	screen   *image.RGBA
	sequence uint64
}

// Apply composes one frame. Any refusal leaves the Composer unusable until the next key frame: a
// screen composed on a wrong base is never shown as right.
func (c *Composer) Apply(m Message) error {
	switch m.Type {
	case TypeFrame:
		if err := validateFrame(m); err != nil {
			c.screen = nil
			return err
		}
		decoded, err := decodePNG(m.PNG, m.Width, m.Height)
		if err != nil {
			c.screen = nil
			return err
		}
		c.screen, c.sequence = decoded, m.Sequence
		return nil
	case TypeFrameDelta:
		if _, err := validateDelta(m); err != nil {
			c.screen = nil
			return err
		}
		if c.screen == nil {
			return ErrNoKeyFrame
		}
		if m.Sequence != c.sequence+1 {
			c.screen = nil
			return ErrSequenceGap
		}
		if bounds := c.screen.Bounds(); uint32(bounds.Dx()) != m.Width || uint32(bounds.Dy()) != m.Height {
			c.screen = nil
			return fmt.Errorf("%w: partial frame of %dx%d on a screen of %dx%d", ErrMalformedMessage, m.Width, m.Height, bounds.Dx(), bounds.Dy())
		}
		// Decoded whole first: a bad rectangle changes nothing.
		patches := make([]*image.RGBA, len(m.Rects))
		for i, r := range m.Rects {
			patch, err := decodePNG(r.PNG, r.Width, r.Height)
			if err != nil {
				c.screen = nil
				return err
			}
			patches[i] = patch
		}
		for i, r := range m.Rects {
			at := image.Rect(int(r.X), int(r.Y), int(r.X+r.Width), int(r.Y+r.Height))
			draw.Draw(c.screen, at, patches[i], image.Point{}, draw.Src)
		}
		c.sequence = m.Sequence
		return nil
	}
	return ErrUnsupported
}

// Screen is a copy of the screen as composed, nil before a key frame or after a refusal.
func (c *Composer) Screen() *image.RGBA {
	if c.screen == nil {
		return nil
	}
	out := image.NewRGBA(c.screen.Bounds())
	copy(out.Pix, c.screen.Pix)
	return out
}

// Sequence is the sequence of the last frame composed.
func (c *Composer) Sequence() uint64 { return c.sequence }

// decodePNG decodes a PNG that must be exactly width x height, into straight RGBA.
func decodePNG(data []byte, width, height uint32) (*image.RGBA, error) {
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
	}
	if uint32(config.Width) != width || uint32(config.Height) != height {
		return nil, fmt.Errorf("%w: a PNG of %dx%d where %dx%d is announced", ErrMalformedMessage, config.Width, config.Height, width, height)
	}
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
	}
	out := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	draw.Draw(out, out.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	return out, nil
}

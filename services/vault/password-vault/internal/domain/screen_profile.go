package domain

import (
	"errors"
	"fmt"
)

// The screen profile of an RDP account (ADR-0132): what its administrator allows a session to
// use, and the default. The operator chooses within it when opening the screen; the Broker checks
// the choice against it, and the proxy applies it.
const (
	// ScreenChannelGraphics is the graphics pipeline (ADR-0101).
	ScreenChannelGraphics = "graphics"
	// ScreenChannelBitmap is the bitmap updates of the older protocol.
	ScreenChannelBitmap = "bitmap"
)

// ErrInvalidScreenProfile: a profile outside ADR-0132's bounds.
var ErrInvalidScreenProfile = errors.New("invalid screen profile")

type ScreenProfile struct {
	Channels          []string `json:"channels"`
	DefaultChannel    string   `json:"defaultChannel"`
	ColorDepths       []int    `json:"colorDepths"`
	DefaultColorDepth int      `json:"defaultColorDepth"`
}

// DefaultScreenProfile is what an account without a profile allows: everything, the graphics
// pipeline and 32 bits by default — the behaviour before ADR-0132.
func DefaultScreenProfile() ScreenProfile {
	return ScreenProfile{
		Channels: []string{ScreenChannelGraphics, ScreenChannelBitmap}, DefaultChannel: ScreenChannelGraphics,
		ColorDepths: []int{16, 32}, DefaultColorDepth: 32,
	}
}

// Validate checks the profile: each set non-empty, of known values, without a duplicate, and each
// default one of its set.
func (p ScreenProfile) Validate() error {
	if len(p.Channels) == 0 || len(p.Channels) > 2 {
		return fmt.Errorf("%w: one or two channels", ErrInvalidScreenProfile)
	}
	seen := map[string]bool{}
	for _, c := range p.Channels {
		if c != ScreenChannelGraphics && c != ScreenChannelBitmap {
			return fmt.Errorf("%w: unknown channel %q", ErrInvalidScreenProfile, c)
		}
		if seen[c] {
			return fmt.Errorf("%w: channel %q twice", ErrInvalidScreenProfile, c)
		}
		seen[c] = true
	}
	if !seen[p.DefaultChannel] {
		return fmt.Errorf("%w: the default channel is not one of the channels", ErrInvalidScreenProfile)
	}
	if len(p.ColorDepths) == 0 || len(p.ColorDepths) > 2 {
		return fmt.Errorf("%w: one or two colour depths", ErrInvalidScreenProfile)
	}
	depths := map[int]bool{}
	for _, d := range p.ColorDepths {
		if d != 16 && d != 32 {
			return fmt.Errorf("%w: unknown colour depth %d", ErrInvalidScreenProfile, d)
		}
		if depths[d] {
			return fmt.Errorf("%w: colour depth %d twice", ErrInvalidScreenProfile, d)
		}
		depths[d] = true
	}
	if !depths[p.DefaultColorDepth] {
		return fmt.Errorf("%w: the default colour depth is not one of the depths", ErrInvalidScreenProfile)
	}
	return nil
}

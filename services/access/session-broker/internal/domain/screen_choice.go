package domain

import (
	"errors"
	"fmt"
	"slices"
)

// The screen of an RDP session (ADR-0132): the channel and colour depth the operator chooses when
// opening the screen, within the profile the account's administrator set at the Vault.
const (
	ScreenChannelGraphics = "graphics" // the graphics pipeline (ADR-0101)
	ScreenChannelBitmap   = "bitmap"   // the bitmap updates of the older protocol
)

// ErrInvalidScreenChoice: a channel or colour depth that does not exist (400).
var ErrInvalidScreenChoice = errors.New("invalid screen choice")

// ScreenChoice is a session's screen: the operator's choice, then the one resolved. Zero values
// are "the account's default".
type ScreenChoice struct {
	Channel    string
	ColorDepth int
}

// ScreenProfile is what the account allows, as the Vault reads it (domain.ScreenProfile there).
type ScreenProfile struct {
	Channels          []string `json:"channels"`
	DefaultChannel    string   `json:"defaultChannel"`
	ColorDepths       []int    `json:"colorDepths"`
	DefaultColorDepth int      `json:"defaultColorDepth"`
}

// defaultScreenProfile is an account without a profile: everything, graphics and 32 bits.
var defaultScreenProfile = ScreenProfile{Channels: []string{ScreenChannelGraphics, ScreenChannelBitmap}, DefaultChannel: ScreenChannelGraphics,
	ColorDepths: []int{16, 32}, DefaultColorDepth: 32}

// ResolveScreen resolves the operator's choice against the account's profile (nil: everything
// allowed). A field left zero takes the profile's default; a value that does not exist is
// ErrInvalidScreenChoice; a value the profile does not allow is ErrForbidden. The result is
// always one of the profile's values: the proxy never sees the browser's word for it.
func ResolveScreen(profile *ScreenProfile, choice ScreenChoice) (ScreenChoice, error) {
	p := defaultScreenProfile
	if profile != nil {
		p = *profile
	}
	if choice.Channel != "" && choice.Channel != ScreenChannelGraphics && choice.Channel != ScreenChannelBitmap {
		return ScreenChoice{}, fmt.Errorf("%w: channel %q (graphics or bitmap)", ErrInvalidScreenChoice, choice.Channel)
	}
	if choice.ColorDepth != 0 && choice.ColorDepth != 16 && choice.ColorDepth != 32 {
		return ScreenChoice{}, fmt.Errorf("%w: colour depth %d (16 or 32)", ErrInvalidScreenChoice, choice.ColorDepth)
	}
	resolved := ScreenChoice{Channel: p.DefaultChannel, ColorDepth: p.DefaultColorDepth}
	if choice.Channel != "" {
		if !slices.Contains(p.Channels, choice.Channel) {
			return ScreenChoice{}, fmt.Errorf("%w: the account does not allow the %s channel", ErrForbidden, choice.Channel)
		}
		resolved.Channel = choice.Channel
	}
	if choice.ColorDepth != 0 {
		if !slices.Contains(p.ColorDepths, choice.ColorDepth) {
			return ScreenChoice{}, fmt.Errorf("%w: the account does not allow %d-bit colour", ErrForbidden, choice.ColorDepth)
		}
		resolved.ColorDepth = choice.ColorDepth
	}
	// A stored profile is validated by the Vault; a default outside its own set would be its bug,
	// and is refused rather than passed on.
	if !slices.Contains(p.Channels, resolved.Channel) || !slices.Contains(p.ColorDepths, resolved.ColorDepth) {
		return ScreenChoice{}, fmt.Errorf("%w: the account's screen profile is not consistent", ErrUnavailable)
	}
	return resolved, nil
}

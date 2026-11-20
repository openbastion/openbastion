package domain_test

import (
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// ADR-0132: the operator's choice resolved against the account's profile.
func TestResolveScreen(t *testing.T) {
	bitmapOnly := &domain.ScreenProfile{Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{16, 32}, DefaultColorDepth: 16}
	for _, c := range []struct {
		name    string
		profile *domain.ScreenProfile
		choice  domain.ScreenChoice
		want    domain.ScreenChoice
		err     error
	}{
		{"no profile, no choice: graphics, 32", nil, domain.ScreenChoice{}, domain.ScreenChoice{Channel: "graphics", ColorDepth: 32}, nil},
		{"no profile, bitmap and 16 chosen", nil, domain.ScreenChoice{Channel: "bitmap", ColorDepth: 16}, domain.ScreenChoice{Channel: "bitmap", ColorDepth: 16}, nil},
		{"the profile's defaults", bitmapOnly, domain.ScreenChoice{}, domain.ScreenChoice{Channel: "bitmap", ColorDepth: 16}, nil},
		{"a depth the profile allows", bitmapOnly, domain.ScreenChoice{ColorDepth: 32}, domain.ScreenChoice{Channel: "bitmap", ColorDepth: 32}, nil},
		{"a channel the profile does not allow", bitmapOnly, domain.ScreenChoice{Channel: "graphics"}, domain.ScreenChoice{}, domain.ErrForbidden},
		{"a depth the profile does not allow", &domain.ScreenProfile{Channels: []string{"graphics"}, DefaultChannel: "graphics", ColorDepths: []int{32}, DefaultColorDepth: 32},
			domain.ScreenChoice{ColorDepth: 16}, domain.ScreenChoice{}, domain.ErrForbidden},
		{"an unknown channel", nil, domain.ScreenChoice{Channel: "avc"}, domain.ScreenChoice{}, domain.ErrInvalidScreenChoice},
		{"an unknown depth", nil, domain.ScreenChoice{ColorDepth: 24}, domain.ScreenChoice{}, domain.ErrInvalidScreenChoice},
		{"an inconsistent stored profile", &domain.ScreenProfile{Channels: []string{"bitmap"}, DefaultChannel: "graphics", ColorDepths: []int{32}, DefaultColorDepth: 32},
			domain.ScreenChoice{}, domain.ScreenChoice{}, domain.ErrUnavailable},
	} {
		got, err := domain.ResolveScreen(c.profile, c.choice)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: %v, want %v", c.name, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

package domain_test

import (
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// ADR-0132: a profile's sets are non-empty, known and without a duplicate, and its defaults are in
// them; anything else is refused before it is stored.
func TestScreenProfile_Validate(t *testing.T) {
	if err := domain.DefaultScreenProfile().Validate(); err != nil {
		t.Fatalf("the default profile: %v", err)
	}
	ok := domain.ScreenProfile{Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{16}, DefaultColorDepth: 16}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a bitmap, 16-bit profile: %v", err)
	}
	for name, p := range map[string]domain.ScreenProfile{
		"no channel":          {DefaultChannel: "graphics", ColorDepths: []int{32}, DefaultColorDepth: 32},
		"unknown channel":     {Channels: []string{"avc"}, DefaultChannel: "avc", ColorDepths: []int{32}, DefaultColorDepth: 32},
		"channel twice":       {Channels: []string{"bitmap", "bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{32}, DefaultColorDepth: 32},
		"default not allowed": {Channels: []string{"bitmap"}, DefaultChannel: "graphics", ColorDepths: []int{32}, DefaultColorDepth: 32},
		"no depth":            {Channels: []string{"bitmap"}, DefaultChannel: "bitmap", DefaultColorDepth: 32},
		"unknown depth":       {Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{24}, DefaultColorDepth: 24},
		"depth twice":         {Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{16, 16}, DefaultColorDepth: 16},
		"depth not allowed":   {Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{16}, DefaultColorDepth: 32},
	} {
		if err := p.Validate(); !errors.Is(err, domain.ErrInvalidScreenProfile) {
			t.Errorf("%s: %v, want ErrInvalidScreenProfile", name, err)
		}
	}
}

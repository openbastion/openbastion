package main

import "testing"

// The on/off settings (RDP_ENABLED; SCREEN_CLIPBOARD at the screen proxy): absent is the default,
// on since the owner's decision of 13 November 2026; "false" shuts; anything else stops the service.
func TestSwitchFromEnv(t *testing.T) {
	for _, c := range []struct {
		value string
		def   bool
		want  bool
	}{{"", true, true}, {"", false, false}, {"true", false, true}, {"false", true, false}} {
		got, err := switchFromEnv("RDP_ENABLED", c.value, c.def)
		if err != nil || got != c.want {
			t.Errorf("%q (default %v): %v, %v; want %v", c.value, c.def, got, err, c.want)
		}
	}
	for _, value := range []string{"TRUE", "1", "yes", "off", " true"} {
		if _, err := switchFromEnv("RDP_ENABLED", value, true); err == nil {
			t.Errorf("%q: accepted", value)
		}
	}
}

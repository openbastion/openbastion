package application_test

import (
	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"testing"
)

func TestProxySelectorOnlyAdvertisesImplementedProtocols(t *testing.T) {
	selector := application.ProxySelector{}
	for protocol, want := range map[string]string{"ssh": "ssh-proxy", "vnc": "rdp-vnc-proxy", "rdp": "rdp-vnc-proxy"} {
		got, err := selector.Select(protocol)
		if err != nil || got != want {
			t.Errorf("Select(%q)=(%q,%v), want %q", protocol, got, err, want)
		}
	}
	for _, protocol := range []string{"unknown", ""} {
		if _, err := selector.Select(protocol); err == nil {
			t.Errorf("Select(%q) should refuse unknown protocol", protocol)
		}
	}
}

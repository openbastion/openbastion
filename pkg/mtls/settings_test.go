package mtls_test

import (
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseMode_ClosedByDefaultAndStrictAboutTypos(t *testing.T) {
	for in, want := range map[string]mtls.Mode{"": mtls.Required, "required": mtls.Required, " required ": mtls.Required, "disabled": mtls.Disabled} {
		got, err := mtls.ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	// A typo must not silently select either side — least of all the weak one.
	for _, bad := range []string{"disable", "off", "false", "0", "Disabled", "REQUIRED", "optional"} {
		if _, err := mtls.ParseMode(bad); err == nil {
			t.Errorf("ParseMode(%q) was accepted", bad)
		}
	}
}

func TestSettingsFromEnv(t *testing.T) {
	t.Run("the zero environment is Required, and refuses to start without an identity", func(t *testing.T) {
		_, err := mtls.SettingsFromEnv(envOf(nil))
		if err == nil {
			t.Fatal("no certificate configured, yet accepted")
		}
		for _, want := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CA_FILE", "refusing to start", "INTERNAL_TLS=disabled"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error does not mention %q: %v", want, err)
			}
		}
	})
	t.Run("naming only what is missing", func(t *testing.T) {
		_, err := mtls.SettingsFromEnv(envOf(map[string]string{"TLS_CERT_FILE": "c", "TLS_KEY_FILE": "k"}))
		if err == nil || !strings.Contains(err.Error(), "TLS_CA_FILE is not set") || strings.Contains(err.Error(), "TLS_CERT_FILE") {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("a complete configuration", func(t *testing.T) {
		s, err := mtls.SettingsFromEnv(envOf(map[string]string{"TLS_CERT_FILE": "c", "TLS_KEY_FILE": "k", "TLS_CA_FILE": "a"}))
		if err != nil || s.Mode != mtls.Required || s.TrustDomain != mtls.DefaultTrustDomain || s.ReloadInterval != mtls.DefaultReloadInterval {
			t.Fatalf("%+v, %v", s, err)
		}
	})
	t.Run("disabled needs nothing", func(t *testing.T) {
		s, err := mtls.SettingsFromEnv(envOf(map[string]string{"INTERNAL_TLS": "disabled"}))
		if err != nil || s.Mode != mtls.Disabled {
			t.Fatalf("%+v, %v", s, err)
		}
	})
	t.Run("an unknown mode, a bad trust domain and a bad interval are fatal", func(t *testing.T) {
		base := map[string]string{"TLS_CERT_FILE": "c", "TLS_KEY_FILE": "k", "TLS_CA_FILE": "a"}
		for name, extra := range map[string]map[string]string{
			"mode":     {"INTERNAL_TLS": "off"},
			"domain":   {"TLS_TRUST_DOMAIN": "Not A Domain"},
			"interval": {"TLS_RELOAD_INTERVAL": "soon"},
			"zero":     {"TLS_RELOAD_INTERVAL": "0s"},
		} {
			m := map[string]string{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range extra {
				m[k] = v
			}
			if _, err := mtls.SettingsFromEnv(envOf(m)); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
	t.Run("the reload interval is configurable", func(t *testing.T) {
		s, err := mtls.SettingsFromEnv(envOf(map[string]string{"TLS_CERT_FILE": "c", "TLS_KEY_FILE": "k", "TLS_CA_FILE": "a", "TLS_RELOAD_INTERVAL": "250ms"}))
		if err != nil || s.ReloadInterval != 250*time.Millisecond {
			t.Fatalf("%+v, %v", s, err)
		}
	})
}

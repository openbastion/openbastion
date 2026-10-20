package mtls

import (
	"fmt"
	"strings"
	"time"
)

// Mode says whether a service's internal traffic is mutually authenticated.
type Mode int

const (
	// Required is the default: a service that has no usable identity does not
	// start. Like RECORDING_POLICY=required (ADR-0008), a forgotten setting must
	// never select the weak behaviour.
	Required Mode = iota
	// Disabled is plain HTTP with no caller identity at all. It exists for local
	// development and must be asked for by name; every service announces it at
	// start-up.
	Disabled
)

func (m Mode) String() string {
	if m == Disabled {
		return "disabled"
	}
	return "required"
}

// ParseMode reads INTERNAL_TLS. The empty value is Required; anything that is
// not one of the two known values is an error — a typo must not silently pick
// either side.
func ParseMode(s string) (Mode, error) {
	switch strings.TrimSpace(s) {
	case "", "required":
		return Required, nil
	case "disabled":
		return Disabled, nil
	}
	return Required, fmt.Errorf(`INTERNAL_TLS must be "required" (the default) or "disabled" (development only), got %q`, s)
}

// DefaultReloadInterval is how often a running service looks again at its
// certificate files. A rotated certificate is picked up within this delay,
// without a restart.
const DefaultReloadInterval = 5 * time.Second

// Settings is everything a service needs to establish its identity.
type Settings struct {
	Mode Mode

	// CertFile is the service's certificate chain (leaf first), KeyFile its
	// private key and CAFile the bundle of authorities it trusts, all PEM.
	CertFile string
	KeyFile  string
	CAFile   string

	TrustDomain    string
	ReloadInterval time.Duration
}

// SettingsFromEnv reads TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE,
// TLS_TRUST_DOMAIN, TLS_RELOAD_INTERVAL and INTERNAL_TLS through getenv.
func SettingsFromEnv(getenv func(string) string) (Settings, error) {
	mode, err := ParseMode(getenv("INTERNAL_TLS"))
	if err != nil {
		return Settings{}, err
	}
	s := Settings{
		Mode:           mode,
		CertFile:       getenv("TLS_CERT_FILE"),
		KeyFile:        getenv("TLS_KEY_FILE"),
		CAFile:         getenv("TLS_CA_FILE"),
		TrustDomain:    getenv("TLS_TRUST_DOMAIN"),
		ReloadInterval: DefaultReloadInterval,
	}
	if s.TrustDomain == "" {
		s.TrustDomain = DefaultTrustDomain
	}
	if v := getenv("TLS_RELOAD_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Settings{}, fmt.Errorf("TLS_RELOAD_INTERVAL must be a positive duration such as 5s, got %q", v)
		}
		s.ReloadInterval = d
	}
	if mode == Disabled {
		return s, nil
	}
	if !ValidTrustDomain(s.TrustDomain) {
		return Settings{}, fmt.Errorf("TLS_TRUST_DOMAIN %q is not a valid trust domain", s.TrustDomain)
	}
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"TLS_CERT_FILE", s.CertFile}, {"TLS_KEY_FILE", s.KeyFile}, {"TLS_CA_FILE", s.CAFile},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return Settings{}, fmt.Errorf("INTERNAL_TLS is %q (the default), which authenticates every internal call, but %s not set — "+
			"refusing to start. Provide the service's certificate, key and CA, or set INTERNAL_TLS=disabled to run without (development only)",
			s.Mode, strings.Join(missing, ", ")+isOrAre(len(missing)))
	}
	return s, nil
}

func isOrAre(n int) string {
	if n == 1 {
		return " is"
	}
	return " are"
}

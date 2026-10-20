package mtls

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Runtime is what a service's main needs: its mode, and when mutual TLS is
// required, its identity, a listener that authenticates and authorizes callers,
// and clients that authenticate the services they call.
type Runtime struct {
	service string
	mode    Mode
	creds   *Credentials
}

// Setup reads the environment (INTERNAL_TLS, TLS_*) and establishes the
// identity of the named service. In Required mode it also insists that the
// certificate is that service's own: the Vault must not start with the broker's
// certificate, however valid.
func Setup(service string) (*Runtime, error) {
	s, err := SettingsFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	return SetupWith(service, s)
}

// SetupWith is Setup with explicit settings.
func SetupWith(service string, s Settings) (*Runtime, error) {
	if !ValidServiceName(service) {
		return nil, fmt.Errorf("mtls: %q is not a valid service name", service)
	}
	rt := &Runtime{service: service, mode: s.Mode}
	if s.Mode == Disabled {
		log.Printf("%s: WARNING INTERNAL_TLS=disabled — calls between services are neither encrypted nor authenticated, and any caller may claim any identity. Development only; never in production", service)
		return rt, nil
	}
	creds, err := NewCredentials(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", service, err)
	}
	if creds.Identity() != service {
		return nil, fmt.Errorf("%s: %s holds the certificate of %q, not of %q — refusing to start with another service's identity",
			service, s.CertFile, creds.Identity(), service)
	}
	log.Printf("%s: internal mTLS on as %s (trust domain %s, certificate valid until %s)",
		service, creds.Identity(), s.TrustDomain, creds.NotAfter().UTC().Format(time.RFC3339))
	rt.creds = creds
	return rt, nil
}

// Enabled reports whether internal traffic is mutually authenticated.
func (rt *Runtime) Enabled() bool { return rt.mode == Required }

// Credentials exposes the identity (nil when disabled), for tests and diagnostics.
func (rt *Runtime) Credentials() *Credentials { return rt.creds }

// DefaultURL is the URL a peer listening on hostPort is reached at when no
// environment variable says otherwise: https under mutual TLS, http otherwise.
func (rt *Runtime) DefaultURL(hostPort string) string {
	if rt.Enabled() {
		return "https://" + hostPort
	}
	return "http://" + hostPort
}

// Client returns the HTTP client for reaching the given peers. When mutual TLS is
// disabled it is http.DefaultClient, as before.
func (rt *Runtime) Client(peers ...Peer) (*http.Client, error) {
	if !rt.Enabled() {
		return http.DefaultClient, nil
	}
	return rt.creds.Client(peers...)
}

// Handler wraps h so that only the services the rules allow can call it. When
// mutual TLS is disabled there is no caller identity to check and h is returned
// as it is.
func (rt *Runtime) Handler(rules []Rule, h http.Handler) http.Handler {
	if !rt.Enabled() {
		return h
	}
	return Guard(rt.creds.TrustDomain(), rules, h)
}

// Server builds the service's HTTP server for addr.
func (rt *Runtime) Server(addr string, h http.Handler, rules []Rule) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           rt.Handler(rules, h),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if rt.Enabled() {
		srv.TLSConfig = rt.creds.ServerTLS()
	}
	return srv
}

// ServePublic serves h on addr as plain HTTP, whatever the mode. It is for the one
// service that faces users — the API Gateway — whose callers are people with
// bearer tokens, not services with certificates; TLS for them ends at the edge
// (the reverse proxy). Such a service still has an identity for its own outbound
// calls, through Client. Never use it for an internal listener.
func (rt *Runtime) ServePublic(addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	return srv.ListenAndServe()
}

// ListenAndServe serves h on addr until it fails.
func (rt *Runtime) ListenAndServe(addr string, h http.Handler, rules []Rule) error {
	srv := rt.Server(addr, h, rules)
	if rt.Enabled() {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

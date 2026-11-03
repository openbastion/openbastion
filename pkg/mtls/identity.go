// Package mtls is OpenBastion's service-to-service transport security
// (ADR-0010): mutual TLS in which a service's identity is read from its
// certificate — never from a field of the message — and in which every route
// states which services may call it.
//
// It depends on the standard library only, so every service can import it
// without dragging a dependency into its module.
package mtls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DefaultTrustDomain is the SPIFFE trust domain used when TLS_TRUST_DOMAIN is
// not set. All certificates of one deployment share a trust domain; a
// certificate from another one is not accepted even if the same CA signed it.
const DefaultTrustDomain = "openbastion.local"

// The service names of the platform (docs/architecture/system-overview.md). They are the identities that
// appear in certificates and in each service's caller rules.
const (
	APIGateway      = "api-gateway"
	Authentication  = "authentication"
	Authorization   = "authorization"
	SessionBroker   = "session-broker"
	SSHProxy        = "ssh-proxy"
	PasswordVault   = "password-vault"
	AuditService    = "audit-service"
	CommandRecorder = "command-recorder"
	VideoRecorder   = "video-recorder"
	SeaweedFS       = "seaweedfs"
	RDPVNCProxy     = "rdp-vnc-proxy"

	// AdminCLI is the operator's tooling. It is allowed on the few routes that
	// have no public surface (creating a local user, verifying the audit chain)
	// and nowhere else.
	AdminCLI = "admin-cli"
)

var serviceNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidServiceName reports whether s can be a service identity: a lowercase
// DNS-label-like name. Keeping the alphabet small keeps the identity free of
// anything a URL parser or a log line could mistake for structure.
func ValidServiceName(s string) bool { return serviceNameRE.MatchString(s) }

// ValidTrustDomain reports whether s can be a trust domain: lowercase DNS
// labels separated by dots.
func ValidTrustDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !serviceNameRE.MatchString(label) {
			return false
		}
	}
	return true
}

// SPIFFEID returns the identity URI of a service: spiffe://<trust domain>/<service>.
func SPIFFEID(trustDomain, service string) (*url.URL, error) {
	if !ValidTrustDomain(trustDomain) {
		return nil, fmt.Errorf("mtls: %q is not a valid trust domain", trustDomain)
	}
	if !ValidServiceName(service) {
		return nil, fmt.Errorf("mtls: %q is not a valid service name (lowercase letters, digits and dashes)", service)
	}
	return &url.URL{Scheme: "spiffe", Host: trustDomain, Path: "/" + service}, nil
}

// ErrNoIdentity is returned for a certificate that does not carry exactly one
// well-formed identity of this trust domain.
var ErrNoIdentity = errors.New("mtls: certificate carries no valid service identity")

// ServiceFromCertificate reads the identity a certificate vouches for.
//
// It is strict on purpose: exactly one URI SAN, spiffe scheme, the expected
// trust domain, a single path segment that is a valid service name, and nothing
// else (no port, user, query or fragment). A certificate that is almost an
// identity is not one — ambiguity here would be an authorization bug.
func ServiceFromCertificate(cert *x509.Certificate, trustDomain string) (string, error) {
	if cert == nil {
		return "", ErrNoIdentity
	}
	if len(cert.URIs) != 1 {
		return "", fmt.Errorf("%w: expected exactly one URI SAN, found %d", ErrNoIdentity, len(cert.URIs))
	}
	u := cert.URIs[0]
	switch {
	case u.Scheme != "spiffe":
		return "", fmt.Errorf("%w: scheme is %q, not spiffe", ErrNoIdentity, u.Scheme)
	case u.Host != trustDomain:
		return "", fmt.Errorf("%w: trust domain is %q, not %q", ErrNoIdentity, u.Host, trustDomain)
	case u.User != nil, u.RawQuery != "", u.Fragment != "", u.Opaque != "":
		return "", fmt.Errorf("%w: unexpected components in %q", ErrNoIdentity, u.String())
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == u.Path || !ValidServiceName(name) {
		return "", fmt.Errorf("%w: path %q is not /<service>", ErrNoIdentity, u.Path)
	}
	return name, nil
}

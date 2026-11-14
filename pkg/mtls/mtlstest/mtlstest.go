// Package mtlstest lets the tests of a service exercise its caller rules
// without a network: it dresses a request as coming from an authenticated peer.
package mtlstest

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

// TrustDomain is the trust domain of the identities this package mints. Pass it
// to mtls.Guard in tests.
const TrustDomain = "test.openbastion"

var (
	mu     sync.Mutex
	ca     *pki.CA
	issued = map[string]*x509.Certificate{}
)

// As returns a copy of r carrying the connection state of a TLS peer that proved
// to be service — what mtls.Guard sees behind a real mutual-TLS listener.
func As(r *http.Request, service string) *http.Request {
	cert, root := identity(service)
	r2 := r.Clone(r.Context())
	r2.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert, root}},
	}
	return r2
}

func identity(service string) (*x509.Certificate, *x509.Certificate) {
	mu.Lock()
	defer mu.Unlock()
	if ca == nil {
		var err error
		if ca, err = pki.NewCA(TrustDomain, 24*time.Hour, time.Now()); err != nil {
			panic(err)
		}
	}
	if c, ok := issued[service]; ok {
		return c, ca.Cert
	}
	leaf, err := ca.Issue(service, pki.IssueOptions{})
	if err != nil {
		panic(err)
	}
	issued[service] = leaf.Cert
	return leaf.Cert, ca.Cert
}

// Case is one expectation about a caller rule table: may Caller make Method
// Path?
type Case struct {
	Caller, Method, Path string
	Allowed              bool
}

// Allow and Deny build the expectations of a table, reading as a sentence.
func Allow(caller, method, path string) Case { return Case{caller, method, path, true} }
func Deny(caller, method, path string) Case  { return Case{caller, method, path, false} }

// Standard is every identity of a deployment, for "nobody else" assertions.
// Derive it from the PKI manifest so new service identities cannot silently escape route tests.
var Standard = append([]string(nil), pki.StandardServices...)

// Check runs the cases through mtls.Guard and fails on any disagreement. It also
// asserts the property that makes a table safe to extend: a route no rule
// mentions is refused to every service.
func Check(t *testing.T, rules []mtls.Rule, cases []Case) {
	t.Helper()
	reached := false
	h := mtls.Guard(TrustDomain, rules, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	try := func(caller, method, path string) bool {
		reached = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, As(httptest.NewRequest(method, path, nil), caller))
		return reached
	}
	for _, c := range cases {
		if got := try(c.Caller, c.Method, c.Path); got != c.Allowed {
			t.Errorf("%s %s %s: allowed=%v, want %v", c.Caller, c.Method, c.Path, got, c.Allowed)
		}
	}
	for _, svc := range Standard {
		for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
			if try(svc, m, "/no-rule-for-this-route") {
				t.Errorf("%s %s reached a route no rule allows", svc, m)
			}
		}
	}
}

// Route is a route a service registers.
type Route struct{ Method, Path string }

// CheckRoutes fails if a route the service registers is unreachable by every
// identity (someone forgot its rule), or if the mux does not know a route the
// table is written for (the rule has a typo). Fail-closed is the safe direction,
// but a service whose route nobody can call is broken all the same.
func CheckRoutes(t *testing.T, mux *http.ServeMux, rules []mtls.Rule, routes []Route) {
	t.Helper()
	for _, r := range routes {
		req := httptest.NewRequest(r.Method, r.Path, nil)
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("%s %s is not registered by the service", r.Method, r.Path)
			continue
		}
		reachable := false
		for _, svc := range Standard {
			ok := false
			h := mtls.Guard(TrustDomain, rules, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ok = true }))
			h.ServeHTTP(httptest.NewRecorder(), As(httptest.NewRequest(r.Method, r.Path, nil), svc))
			if ok {
				reachable = true
				break
			}
		}
		if !reachable {
			t.Errorf("%s %s is registered but no service may call it", r.Method, r.Path)
		}
	}
}

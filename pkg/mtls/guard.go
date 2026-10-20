package mtls

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"path"
	"strings"
)

// Any, in a rule's Callers, admits every authenticated service. It is meant for
// liveness and readiness endpoints, which carry nothing worth protecting beyond
// the connection itself.
const Any = "*"

// Rule says which services may call a route. A request that matches no rule is
// refused: a new route is unreachable until someone decides who may call it.
type Rule struct {
	Method  string   // "" matches every method
	Path    string   // exact, or a prefix when Prefix is set
	Prefix  bool     // Path is a subtree, like a ServeMux pattern ending in "/"
	Callers []string // service names, or Any
}

func (r Rule) matches(method, p string) bool {
	if r.Method != "" && r.Method != method {
		return false
	}
	if r.Prefix {
		return strings.HasPrefix(p, r.Path)
	}
	return p == r.Path
}

func (r Rule) admits(service string) bool {
	for _, c := range r.Callers {
		if c == Any || c == service {
			return true
		}
	}
	return false
}

type callerKey struct{}

// CallerFrom returns the service a request was authenticated as. It is set by
// Guard from the client certificate, and is the only place a handler should
// learn who is calling — never from the body.
func CallerFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(callerKey{}).(string)
	return s, ok && s != ""
}

// WithCaller returns a context in which the caller is service. Guard uses it;
// tests of handlers that depend on the caller use it to stand in for Guard.
func WithCaller(ctx context.Context, service string) context.Context {
	return context.WithValue(ctx, callerKey{}, service)
}

// Guard authorizes callers route by route, from the identity in their client
// certificate. mTLS authenticates; this is what authorizes.
//
// It panics on a malformed rule table: that is a programming error, and it must
// stop the service at start-up, not surface later as a hole.
func Guard(trustDomain string, rules []Rule, next http.Handler) http.Handler {
	for _, r := range rules {
		if !strings.HasPrefix(r.Path, "/") || len(r.Callers) == 0 {
			panic("mtls: rule " + r.Path + " needs an absolute path and at least one caller")
		}
		if r.Prefix && !strings.HasSuffix(r.Path, "/") {
			panic("mtls: prefix rule " + r.Path + " must end with a slash")
		}
		for _, c := range r.Callers {
			if c != Any && !ValidServiceName(c) {
				panic("mtls: rule " + r.Path + " names an invalid caller " + c)
			}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		service, status := authenticate(req.TLS, trustDomain)
		if status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}

		// The rules are matched on the path as the mux will see it. A path that
		// is not already in canonical form, or that carries an escaped
		// separator, could be read one way here and another there; internal
		// routes never need either, so such a request is refused outright.
		p := req.URL.Path
		if p == "" {
			p = "/"
		}
		clean := path.Clean(p)
		if strings.HasSuffix(p, "/") && clean != "/" {
			clean += "/"
		}
		if clean != p || req.URL.RawPath != "" {
			http.Error(w, "bad request path", http.StatusBadRequest)
			return
		}

		for _, rule := range rules {
			if !rule.matches(req.Method, p) {
				continue
			}
			if !rule.admits(service) {
				log.Printf("mtls: refused %s %s from %q — not an allowed caller", req.Method, p, service)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, req.WithContext(WithCaller(req.Context(), service)))
			return
		}
		log.Printf("mtls: refused %s %s from %q — no rule allows this route", req.Method, p, service)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// authenticate returns the service a TLS connection proved to be, or the HTTP
// status to answer with. The listener already demands a verified certificate;
// checking again here keeps Guard safe if it is ever mounted behind a listener
// that does not.
func authenticate(cs *tls.ConnectionState, trustDomain string) (string, int) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return "", http.StatusUnauthorized
	}
	service, err := ServiceFromCertificate(cs.PeerCertificates[0], trustDomain)
	if err != nil {
		return "", http.StatusForbidden
	}
	return service, 0
}

package interfaces

// Directory login through the Gateway (ADR-0061).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// LDAPInfoTTL is how long the Gateway remembers which directories and OIDC providers are on: the
// login page asks at every visit, and an address that holds nothing should not reach the
// Authentication Service at will.
const LDAPInfoTTL = 30 * time.Second

// providerInfo is all the login page may know of a provider or a directory (ADR-0076 §9).
type providerInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// providersCache remembers one listing, rebuilt from the fields it may hold, never the raw body.
type providersCache struct {
	mu      sync.Mutex
	enabled bool
	items   []providerInfo
	at      time.Time
}

// -- GET /auth/ldap and GET /auth/oidc (public) ----------------------------------------------

func (g *GatewayServer) handleLDAPInfo(w http.ResponseWriter, r *http.Request) {
	g.serveProviders(w, r, &g.ldapInfo, "/auth/v1/ldap", "directories")
}

func (g *GatewayServer) handleOIDCInfo(w http.ResponseWriter, r *http.Request) {
	g.serveProviders(w, r, &g.oidcInfo, "/auth/v1/oidc", "providers")
}

func (g *GatewayServer) serveProviders(w http.ResponseWriter, r *http.Request, c *providersCache, upstream, key string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) >= LDAPInfoTTL {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.authenticationURL+upstream, nil)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp, err := g.httpClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		var in map[string]json.RawMessage
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&in)
		resp.Body.Close()
		var enabled bool
		var items []providerInfo
		if err == nil {
			err = json.Unmarshal(in["enabled"], &enabled)
		}
		if err == nil && len(in[key]) > 0 {
			err = json.Unmarshal(in[key], &items)
		}
		if resp.StatusCode != http.StatusOK || err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		if items == nil {
			items = []providerInfo{}
		}
		c.enabled, c.items, c.at = enabled, items, time.Now()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"enabled": c.enabled, key: c.items})
}

// -- POST /auth/ldap/login (public) -------------------------------------------------------

// handleLDAPLogin forwards a directory login. It takes from the same per-address budget as a
// password login: an attacker who holds nothing can hammer it, and every failure counts towards the
// directory's own lockout. Only the directory, username and password are forwarded, rebuilt, never
// the raw body.
func (g *GatewayServer) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if d := g.loginLimiter.Take(g.clientKey(r)); !d.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(d.RetryAfterSeconds()))
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	var in struct {
		Directory string `json:"directory,omitempty"` // ADR-0076: required among several
		Username  string `json:"username"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		http.Error(w, "the body is not a login", http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.authenticationURL+"/auth/v1/ldap/login", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if rejectUpstreamError(w, resp) {
		return
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

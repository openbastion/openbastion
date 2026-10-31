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

// LDAPInfoTTL is how long the Gateway remembers whether directory login is on: the login page asks
// at every visit, and an address that holds nothing should not reach the Authentication Service at
// will.
const LDAPInfoTTL = 30 * time.Second

type ldapInfoCache struct {
	mu      sync.Mutex
	enabled bool
	at      time.Time
}

// -- GET /auth/ldap (public) --------------------------------------------------------------

func (g *GatewayServer) handleLDAPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c := &g.ldapInfo
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) >= LDAPInfoTTL {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.authenticationURL+"/auth/v1/ldap", nil)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp, err := g.httpClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		var in struct {
			Enabled bool `json:"enabled"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&in)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		c.enabled, c.at = in.Enabled, time.Now()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Enabled bool `json:"enabled"`
	}{c.enabled})
}

// -- POST /auth/ldap/login (public) -------------------------------------------------------

// handleLDAPLogin forwards a directory login. It takes from the same per-address budget as a
// password login: an attacker who holds nothing can hammer it, and every failure counts towards the
// directory's own lockout. Only username and password are forwarded, rebuilt, never the raw body.
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
		Username string `json:"username"`
		Password string `json:"password"`
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
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

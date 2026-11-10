package interfaces

// The second factor through the Gateway (ADR-0062).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// handleMFA forwards one step of the second factor. Each takes from the per-address login budget:
// a code is six digits, and an address that holds a challenge should not try many. Only the named
// fields are forwarded, rebuilt, never the raw body: a string field, or — written {name} — a JSON
// object (the browser's WebAuthn answer, ADR-0065), forwarded as it is.
func (g *GatewayServer) handleMFA(upstream string, fields ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if d := g.loginLimiter.Take(g.clientKey(r)); !d.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(d.RetryAfterSeconds()))
			http.Error(w, "too many login attempts", http.StatusTooManyRequests)
			return
		}
		var in map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
			http.Error(w, "the body cannot be read", http.StatusBadRequest)
			return
		}
		out := make(map[string]any, len(fields))
		for _, f := range fields {
			if strings.HasPrefix(f, "{") {
				name := strings.Trim(f, "{}")
				raw := in[name]
				if len(raw) == 0 || raw[0] != '{' || !json.Valid(raw) {
					http.Error(w, "the body cannot be read", http.StatusBadRequest)
					return
				}
				out[name] = raw
				continue
			}
			var v string
			if raw, ok := in[f]; ok && json.Unmarshal(raw, &v) != nil {
				http.Error(w, "the body cannot be read", http.StatusBadRequest)
				return
			}
			out[f] = v
		}
		body, _ := json.Marshal(out)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.authenticationURL+upstream, bytes.NewReader(body))
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
		if cc := resp.Header.Get("Cache-Control"); cc != "" {
			w.Header().Set("Cache-Control", cc) // the enrollment's secret is not to be kept
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
	}
}

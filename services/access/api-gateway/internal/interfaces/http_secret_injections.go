package interfaces

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	secretInjectionAuditAction   = "audit:secret-injections:read"
	secretInjectionAuditResource = "audit:secret-injections:all"
	maxSecretInjectionAuditBytes = 2 << 20
)

// handleSecretInjectionReconciliation is a read-only facade. The user identity and roles come
// only from requireAuth; the internal Audit Service sees only the Gateway's mTLS identity.
func (g *GatewayServer) handleSecretInjectionReconciliation(w http.ResponseWriter, r *http.Request, id identity) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if g.auditURL == "" || g.authorizationURL == "" {
		http.Error(w, "audit reconciliation unavailable", http.StatusServiceUnavailable)
		return
	}
	for key := range r.URL.Query() {
		if key != "limit" && key != "before" {
			http.Error(w, "unsupported query parameter", http.StatusBadRequest)
			return
		}
	}
	q := url.Values{}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			http.Error(w, "limit must be between 1 and 500", http.StatusBadRequest)
			return
		}
		q.Set("limit", strconv.Itoa(n))
	}
	if before := r.URL.Query().Get("before"); before != "" {
		if len(before) != 32 || strings.ToLower(before) != before {
			http.Error(w, "invalid reconciliation cursor", http.StatusBadRequest)
			return
		}
		for _, c := range before {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				http.Error(w, "invalid reconciliation cursor", http.StatusBadRequest)
				return
			}
		}
		q.Set("before", before)
	}

	// The exact question, asked where the Gateway may ask it (POST /authz/v1/capabilities): the
	// Authorization Service's mTLS rules keep check-access to the services that enforce their own
	// routes, and refused it to the Gateway, so that this route answered 503 under mutual TLS.
	allowed, err := g.askCapabilities(r.Context(), id.Roles, []capabilityQueryJSON{{Resource: secretInjectionAuditResource, Action: secretInjectionAuditAction}})
	if err != nil {
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	if !allowed[0] {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.auditURL+"/audit/v1/secret-injections?"+q.Encode(), nil)
	if err != nil {
		http.Error(w, "audit reconciliation unavailable", http.StatusServiceUnavailable)
		return
	}
	resp, err := g.httpClient.Do(upstream)
	if err != nil {
		http.Error(w, "audit reconciliation unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Do not relay internal Audit Service diagnostics or status details.
		http.Error(w, "audit reconciliation unavailable", http.StatusServiceUnavailable)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSecretInjectionAuditBytes+1))
	if err != nil || len(data) > maxSecretInjectionAuditBytes || !json.Valid(data) {
		http.Error(w, "audit reconciliation unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

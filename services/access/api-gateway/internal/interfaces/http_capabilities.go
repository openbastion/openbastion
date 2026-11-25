package interfaces

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// ADR-0131: GET /auth/me/capabilities tells the Admin UI which of its functions the caller may
// use, so that a page with nothing for them is absent and an action they may not take is greyed.
// It is a picture of the policies, never a grant: every route still asks the Authorization
// Service on its own resource, and a capability the UI shows can still be refused.
//
// The catalogue is closed and lives here: each name is what the services check, resource and
// action as their code writes them. "prefix" asks whether the action is allowed on at least one
// resource of the prefix (a policy on one account is enough); an exact entry asks CheckAccess's
// own question. A name with several entries is allowed when any of them is.
type capabilityCheck struct {
	resource string
	action   string
	prefix   bool
}

var capabilityCatalogue = []struct {
	name   string
	checks []capabilityCheck
}{
	// Password Vault (requireAdminAccess): the list asks the literal "*" resource.
	{"accounts.list", []capabilityCheck{{"vault:account-admin:*", "vault:account:list", false}}},
	{"accounts.onboard", []capabilityCheck{{"vault:account-admin:", "vault:account:onboard", true}}},
	{"accounts.rotate", []capabilityCheck{{"vault:account-admin:", "vault:account:rotate", true}}},
	{"accounts.disable", []capabilityCheck{{"vault:account-admin:", "vault:account:delete", true}}},
	{"accounts.pin", []capabilityCheck{{"vault:account-admin:", "vault:account:pin", true}}},
	{"accounts.approval", []capabilityCheck{{"vault:account-admin:", "vault:account:approval", true}}},
	{"accounts.screenProfile", []capabilityCheck{{"vault:account-admin:", "vault:account:screen-profile", true}}}, // ADR-0132
	{"accounts.kerberos", []capabilityCheck{{"vault:account-admin:", "vault:account:kerberos", true}}},            // ADR-0100
	// Authorization (requirePolicyAdmin).
	{"policies.create", []capabilityCheck{{"authz:policy-admin", "authz:policy:create", false}}},
	// ADR-0138 — the UI uses these only to expose relevant controls; every targeted route
	// still checks the exact user or manager resource independently.
	{"approvalHierarchy.read", []capabilityCheck{{"approval-hierarchy:user:", "approval-hierarchy:read", true}, {"approval-hierarchy:all", "approval-hierarchy:read", false}}},
	{"approvalHierarchy.manage", []capabilityCheck{{"approval-hierarchy:user:", "approval-hierarchy:manage", true}, {"approval-hierarchy:all", "approval-hierarchy:manage", false}}},
	{"approvalHierarchy.reports", []capabilityCheck{{"approval-hierarchy:reports:", "approval-hierarchy:read", true}, {"approval-hierarchy:all", "approval-hierarchy:read", false}}},
	// Session Broker.
	{"sessions.create", []capabilityCheck{{"vault:account:", "session:create", true}}},
	{"sessions.breakglass", []capabilityCheck{{"breakglass:account:", "session:breakglass", true}}},
	{"sessions.approve", []capabilityCheck{
		{"session-approve:account:", "session:approve", true},
		{"breakglass-approve:account:", "session:approve", true},
	}},
	{"sessions.read", []capabilityCheck{{"session-read:account:", "session:read", true}}},
	{"sessions.terminate", []capabilityCheck{{"session-terminate:account:", "session:terminate", true}}},
	{"secrets.inject", []capabilityCheck{{"secret:inject:account:", "secret:inject", true}}},
	{"secrets.paste", []capabilityCheck{{"secret:paste:account:", "secret:paste", true}}}, // ADR-0133
	// Command Recorder and Video Recorder.
	{"recordings.read", []capabilityCheck{{"recording:session:", "recording:session:read", true}}},
	// Gateway (handleSecretInjectionReconciliation).
	{"audit.secretInjections", []capabilityCheck{{secretInjectionAuditResource, secretInjectionAuditAction, false}}},
}

type capabilityQueryJSON struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Prefix   bool   `json:"prefix"`
}

// capabilitiesRequestBody is what the Gateway asks the Authorization Service.
type capabilitiesRequestBody struct {
	ActorRoles []string              `json:"actor_roles"`
	Queries    []capabilityQueryJSON `json:"queries"`
}

type capabilitiesResponseJSON struct {
	Capabilities map[string]bool `json:"capabilities"`
}

// handleCapabilities answers for the verified caller only: the roles come from requireAuth, the
// request carries nothing. Authorization unreachable or answering anything but the expected list
// is a 503 that says nothing of it: the UI then greys every action (fail closed).
func (g *GatewayServer) handleCapabilities(w http.ResponseWriter, r *http.Request, id identity) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "unsupported query parameter", http.StatusBadRequest)
		return
	}
	var queries []capabilityQueryJSON
	for _, c := range capabilityCatalogue {
		for _, check := range c.checks {
			queries = append(queries, capabilityQueryJSON{Resource: check.resource, Action: check.action, Prefix: check.prefix})
		}
	}
	allowed, err := g.askCapabilities(r.Context(), id.Roles, queries)
	if err != nil {
		http.Error(w, "capabilities unavailable", http.StatusServiceUnavailable)
		return
	}
	answer := struct{ Allowed []bool }{allowed}
	out := capabilitiesResponseJSON{Capabilities: make(map[string]bool, len(capabilityCatalogue))}
	i := 0
	for _, c := range capabilityCatalogue {
		allowed := false
		for range c.checks {
			allowed = allowed || answer.Allowed[i]
			i++
		}
		out.Capabilities[c.name] = allowed
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// errCapabilities: the Authorization Service did not answer the questions as asked. Never shown.
var errCapabilities = errors.New("capabilities unavailable")

// askCapabilities asks the Authorization Service queries for roles (POST /authz/v1/capabilities,
// the one decision route open to the Gateway, ADR-0131) and returns one answer per query, in
// order. Unreachable, refused, malformed, or a list of another length: an error, never "no".
func (g *GatewayServer) askCapabilities(ctx context.Context, roles []string, queries []capabilityQueryJSON) ([]bool, error) {
	body, _ := json.Marshal(capabilitiesRequestBody{ActorRoles: roles, Queries: queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.authorizationURL+"/authz/v1/capabilities", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var answer struct {
		Allowed []bool `json:"allowed"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&answer) != nil || len(answer.Allowed) != len(queries) {
		return nil, errCapabilities
	}
	return answer.Allowed, nil
}

package integration_test

// Since ADR-0064 the Authentication Service issues no token it could not write to the audit first.
// Most scenarios here are not about the audit: an Authentication Service they start without
// AUDIT_URL writes to this sink, which answers like the Audit Service and keeps what it was given.
// A scenario about the audit passes its own AUDIT_URL — a real Audit Service, or a dead address.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

type sunkEvent struct {
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Success      bool   `json:"success"`
}

var auditSink struct {
	once   sync.Once
	srv    *httptest.Server
	mu     sync.Mutex
	events []sunkEvent
}

func auditSinkURL() string {
	auditSink.once.Do(func() {
		auditSink.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/audit/v1/emit-event" {
				http.NotFound(w, r)
				return
			}
			var e sunkEvent
			if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&e); err != nil {
				http.Error(w, "bad event", http.StatusBadRequest)
				return
			}
			auditSink.mu.Lock()
			auditSink.events = append(auditSink.events, e)
			auditSink.mu.Unlock()
			_, _ = w.Write([]byte(`{"event_id":"sunk"}`))
		}))
	})
	return auditSink.srv.URL
}

// sunk returns the events the sink received for resourceID.
func sunk(resourceID string) []sunkEvent {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	var out []sunkEvent
	for _, e := range auditSink.events {
		if e.ResourceID == resourceID {
			out = append(out, e)
		}
	}
	return out
}

// builtFrom is the package each binary of buildBinary was built from: a binary is recognised by
// what it is, not by the name a scenario gave it (authn-39, authentication-61…).
var builtFrom sync.Map

// withAuditSink adds AUDIT_URL=<sink> to the environment of an Authentication Service started
// without one.
func withAuditSink(binPath string, env []string) []string {
	pkg, _ := builtFrom.Load(binPath)
	if p, _ := pkg.(string); !strings.HasSuffix(p, "/services/access/authentication/cmd/authentication") {
		return env
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "AUDIT_URL=") {
			return env
		}
	}
	return append([]string{"AUDIT_URL=" + auditSinkURL()}, env...)
}

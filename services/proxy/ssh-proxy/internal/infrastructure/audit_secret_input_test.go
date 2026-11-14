package infrastructure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

func TestAuditSecretInputSendsOnlySafeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		source  proxycore.SecretInputSource
		action  string
		details map[string]string
	}{
		{name: "Vault", source: proxycore.SecretInputVault, action: "session.secret_injection_started", details: map[string]string{
			"protocol": "ssh", "account_id": "db-prod",
		}},
		{name: "operator", source: proxycore.SecretInputOperator, action: "session.secret_paste_started", details: map[string]string{
			"protocol": "ssh", "account_id": "target-prod", "bytes": "8", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/audit/v1/emit-event" {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode audit event: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			evidence := proxycore.SecretInputEvidence{SessionID: "session-1", Protocol: "ssh", Source: tc.source, AccountID: "db-prod", Length: 8, SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
			if tc.source == proxycore.SecretInputOperator {
				evidence.AccountID = "target-prod"
			}
			client := &AuditHTTPClient{BaseURL: server.URL}
			if err := client.AuditSecretInput(context.Background(), evidence); err != nil {
				t.Fatal(err)
			}
			if got["action"] != tc.action || got["resource_type"] != "session" || got["resource_id"] != "session-1" {
				t.Fatalf("event identity = %#v", got)
			}
			gotDetails, ok := got["details"].(map[string]any)
			if !ok {
				t.Fatalf("details = %#v", got["details"])
			}
			for key, want := range tc.details {
				if gotDetails[key] != want {
					t.Errorf("details[%q] = %#v, want %q", key, gotDetails[key], want)
				}
			}
			encoded, _ := json.Marshal(got)
			if string(encoded) == "" || json.Valid(encoded) == false {
				t.Fatalf("invalid event JSON: %s", encoded)
			}
		})
	}
}

func TestAuditSecretInputResultRecordsCompletionOutcome(t *testing.T) {
	for _, tc := range []struct {
		success bool
		action  string
	}{{true, "session.secret_injected"}, {false, "session.secret_injection_failed"}} {
		t.Run(tc.action, func(t *testing.T) {
			var got map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := &AuditHTTPClient{BaseURL: server.URL}
			evidence := proxycore.SecretInputEvidence{SessionID: "s1", Protocol: "ssh", Source: proxycore.SecretInputVault, AccountID: "db-prod"}
			if err := client.AuditSecretInputResult(context.Background(), evidence, tc.success); err != nil {
				t.Fatal(err)
			}
			if got["action"] != tc.action || got["success"] != tc.success || got["resource_id"] != "s1" {
				t.Fatalf("event=%v", got)
			}
		})
	}
}

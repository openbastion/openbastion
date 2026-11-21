package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

// session.clipboard carries the direction, the size and the hash in its details (ADR-0068,
// ADR-0096 §5); the other events carry none, as before.

func TestAuditHTTPClient_SecretInputEventsContainOnlyVaultReference(t *testing.T) {
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		got = append(got, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := &infrastructure.AuditHTTPClient{BaseURL: server.URL}
	evidence := proxycore.SecretInputEvidence{SessionID: "s-vnc", InjectionID: "0123456789abcdef0123456789abcdef", Protocol: "vnc", Source: proxycore.SecretInputVault, AccountID: "account-prod"}
	if err := client.AuditSecretInput(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	if err := client.AuditSecretInputResult(context.Background(), evidence, true); err != nil {
		t.Fatal(err)
	}
	if err := client.AuditSecretInputResult(context.Background(), evidence, false); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events", len(got))
	}
	wantActions := []string{"session.secret_injection_started", "session.secret_injected", "session.secret_injection_failed"}
	for i, body := range got {
		details, _ := body["details"].(map[string]any)
		if body["action"] != wantActions[i] || body["resource_type"] != "session" || body["resource_id"] != "s-vnc" ||
			details["protocol"] != "vnc" || details["account_id"] != "account-prod" || details["injection_id"] != "0123456789abcdef0123456789abcdef" || len(details) != 3 {
			t.Fatalf("event %d = %#v", i, body)
		}
		for _, forbidden := range []string{"secret", "password", "length", "sha256", "value"} {
			if _, exists := body[forbidden]; exists {
				t.Fatalf("event leaked %q: %#v", forbidden, body)
			}
		}
	}
}

func TestAuditHTTPClient_ClipboardDetails(t *testing.T) {
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
	}))
	defer server.Close()
	client := &infrastructure.AuditHTTPClient{BaseURL: server.URL}
	event := proxycore.ClipboardEvent{Direction: screenstream.ClipboardFromTarget, Bytes: 6, SHA256: "ab12", Success: false, Reason: proxycore.ClipboardRefusedRate}
	if err := client.EmitClipboard(context.Background(), "s1", event); err != nil {
		t.Fatal(err)
	}
	if err := client.EmitEvent(context.Background(), "session.terminate", "session", "s1", true); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d events", len(got))
	}
	details, _ := got[0]["details"].(map[string]any)
	if got[0]["action"] != "session.clipboard" || got[0]["resource_id"] != "s1" || got[0]["success"] != false ||
		details["direction"] != "from-target" || details["bytes"] != "6" || details["sha256"] != "ab12" || details["reason"] != "rate" || len(details) != 4 {
		t.Fatalf("clipboard event %v", got[0])
	}
	if _, has := got[1]["details"]; has {
		t.Fatalf("an event without details sent some: %v", got[1])
	}
}

// ADR-0133: an operator's password is audited by its size, salted fingerprint and salt, under the
// names the SSH proxy writes; never its text.
func TestAuditHTTPClient_AnOperatorsPasswordIsAuditedByItsFingerprint(t *testing.T) {
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := &infrastructure.AuditHTTPClient{BaseURL: server.URL}
	evidence := proxycore.SecretInputEvidence{SessionID: "s-rdp", InjectionID: "0123456789abcdef0123456789abcdef", Protocol: "rdp", Source: proxycore.SecretInputOperator,
		AccountID: "account-prod", Length: 9, SHA256: strings.Repeat("b", 64), Salt: strings.Repeat("a", 32)}
	if err := client.AuditSecretInput(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	if err := client.AuditSecretInputResult(context.Background(), evidence, true); err != nil {
		t.Fatal(err)
	}
	if err := client.AuditSecretInputResult(context.Background(), evidence, false); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"session.secret_paste_started", "session.secret_pasted", "session.secret_paste_failed"} {
		details, _ := got[i]["details"].(map[string]any)
		if got[i]["action"] != want || details["bytes"] != "9" || details["sha256"] != strings.Repeat("b", 64) || details["salt"] != strings.Repeat("a", 32) || len(details) != 6 {
			t.Fatalf("event %d = %#v", i, got[i])
		}
	}
	// A Vault secret's evidence with a fingerprint, or an operator's without one, is refused.
	for _, bad := range []proxycore.SecretInputEvidence{
		{SessionID: "s", InjectionID: evidence.InjectionID, Protocol: "rdp", Source: proxycore.SecretInputVault, AccountID: "a", SHA256: strings.Repeat("b", 64)},
		{SessionID: "s", InjectionID: evidence.InjectionID, Protocol: "rdp", Source: proxycore.SecretInputOperator, AccountID: "a", Length: 9},
	} {
		if err := client.AuditSecretInput(context.Background(), bad); err == nil {
			t.Errorf("%+v audited", bad)
		}
	}
}

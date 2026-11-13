package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

// session.clipboard carries the direction, the size and the hash in its details (ADR-0068,
// ADR-0096 §5); the other events carry none, as before.
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

package infrastructure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The event the Audit Service receives is the one asked for, field for field, and anything
// but a 200 is an event that may not be in the trail (ADR-0022).
func TestAuditHTTPClient_SendsTheEventAndBelievesOnlyA200(t *testing.T) {
	var got emitEventRequestBody
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/audit/v1/emit-event" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := &AuditHTTPClient{BaseURL: srv.URL}

	if err := c.EmitEvent(context.Background(), "u_carol", "recording.read", "session", "s1", true); err != nil {
		t.Fatalf("a 200: %v", err)
	}
	want := emitEventRequestBody{ActorID: "u_carol", Action: "recording.read", ResourceType: "session", ResourceID: "s1", Success: true}
	if got != want {
		t.Fatalf("sent %+v, want %+v", got, want)
	}
	for _, s := range []int{http.StatusAccepted, http.StatusBadRequest, http.StatusForbidden, http.StatusServiceUnavailable} {
		status = s
		if err := c.EmitEvent(context.Background(), "u_carol", "recording.read", "session", "s1", true); err == nil {
			t.Fatalf("a %d was taken for an event in the trail", s)
		}
	}
	srv.Close()
	if err := c.EmitEvent(context.Background(), "u_carol", "recording.read", "session", "s1", true); err == nil {
		t.Fatal("an Audit Service that is not there was taken for an event in the trail")
	}
}

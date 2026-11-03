package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

func TestAuditHTTPClientUsesAuditIngestionContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit/v1/emit-event" || r.Method != http.MethodPost {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		for _, key := range []string{"actor_id", "action", "resource_type", "resource_id", "success"} {
			if _, ok := body[key]; !ok {
				t.Errorf("missing audit field %q: %v", key, body)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := &infrastructure.AuditHTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	if err := c.EmitEvent(context.Background(), "session.recording_unavailable", "session", "s1", false); err != nil {
		t.Fatal(err)
	}
}

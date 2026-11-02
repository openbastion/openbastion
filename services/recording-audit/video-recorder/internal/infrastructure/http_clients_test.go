package infrastructure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAuthorizationHTTPClientFailsClosedOnApprovalAndMalformedResponses(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		wantAllowed bool
		wantErr     bool
	}{
		{"allowed", `{"allowed":true,"requires_approval":false,"decision_reason":"policy"}`, true, false},
		{"approval required", `{"allowed":true,"requires_approval":true}`, false, false},
		{"unknown fields", `{"allowed":true,"unexpected":true}`, false, true},
		{"malformed", `not json`, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/authz/v1/check-access" {
					t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				var request struct {
					ActorRoles []string `json:"actor_roles"`
					Resource   string   `json:"resource"`
					Action     string   `json:"action"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				if !reflect.DeepEqual(request.ActorRoles, []string{"auditor"}) ||
					request.Resource != "recording:session:s1" || request.Action != "recording:session:read" {
					t.Fatalf("unexpected access check: %+v", request)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()

			client := AuthorizationHTTPClient{BaseURL: server.URL, Client: server.Client()}
			allowed, _, err := client.CheckAccess(context.Background(), []string{"auditor"}, "recording:session:s1", "recording:session:read")
			if allowed != test.wantAllowed || (err != nil) != test.wantErr {
				t.Fatalf("CheckAccess = %v, %v; want allowed=%v error=%v", allowed, err, test.wantAllowed, test.wantErr)
			}
		})
	}
}

func TestAuditHTTPClientRequiresSuccessfulStructuredAuditResponse(t *testing.T) {
	for _, test := range []struct {
		name, response string
		status         int
		wantErr        bool
	}{
		{"success", `{"event_id":"evt-1"}`, http.StatusOK, false},
		{"empty event", `{"event_id":""}`, http.StatusOK, true},
		{"bad body", `not json`, http.StatusOK, true},
		{"service failure", `{"event_id":"evt-1"}`, http.StatusServiceUnavailable, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/audit/v1/emit-event" {
					t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				var request map[string]any
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatalf("decode event: %v", err)
				}
				if request["actor_id"] != "u_reader" || request["action"] != "recording.read" ||
					request["resource_type"] != "session" || request["resource_id"] != "s1" || request["success"] != true {
					t.Fatalf("unexpected audit event: %+v", request)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()

			client := AuditHTTPClient{BaseURL: server.URL, Client: server.Client()}
			err := client.EmitEvent(context.Background(), "u_reader", "recording.read", "session", "s1", true)
			if (err != nil) != test.wantErr {
				t.Fatalf("EmitEvent error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestServiceEndpointRejectsNonOriginURLs(t *testing.T) {
	for _, base := range []string{
		"",
		"://bad",
		"https://user:password@authorization:8083",
		"https://authorization:8083/prefix",
		"https://authorization:8083/?next=other",
		"https://authorization:8083/#fragment",
		"ftp://authorization:8083",
	} {
		if _, err := serviceEndpoint(base, "/authz/v1/check-access"); err == nil {
			t.Errorf("accepted non-origin service URL %q", base)
		}
	}
	if _, err := serviceEndpoint("https://authorization:8083/", "/authz/v1/check-access"); err != nil {
		t.Fatalf("rejected valid service origin: %v", err)
	}
}

func TestClientsFailWhenNoHTTPClientIsConfigured(t *testing.T) {
	authorization := AuthorizationHTTPClient{BaseURL: "https://authorization:8083"}
	if _, _, err := authorization.CheckAccess(context.Background(), nil, "recording:session:s1", "recording:session:read"); err == nil {
		t.Fatal("authorization client without a transport was accepted")
	}
	audit := AuditHTTPClient{BaseURL: "https://audit-service:8082"}
	if err := audit.EmitEvent(context.Background(), "u1", "recording.read", "session", "s1", true); err == nil {
		t.Fatal("audit client without a transport was accepted")
	}
}

func TestDecodeResponseRejectsOversizedBody(t *testing.T) {
	if err := decodeResponse(&repeatReader{remaining: (16 << 10) + 1}, new(map[string]any)); err == nil {
		t.Fatal("oversized service response was accepted")
	}
}

type repeatReader struct{ remaining int }

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errors.New("unexpected end")
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = ' '
	}
	r.remaining -= n
	return n, nil
}

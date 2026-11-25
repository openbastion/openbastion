package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/infrastructure"
)

func TestUserDirectoryHTTPClientReturnsOnlyCurrentAuthorizationContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/auth/v1/internal/users/user_123/authorization-context" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user_id": "user_123", "exists": true, "active": false, "roles": []string{}})
	}))
	defer server.Close()
	client := &infrastructure.UserDirectoryHTTPClient{BaseURL: server.URL}
	got, err := client.GetAuthorizationContext(context.Background(), "user_123")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exists || got.Active || len(got.Roles) != 0 {
		t.Fatalf("disabled identity context: %+v", got)
	}
}

func TestAuthorizationHTTPClientAcceptsFullDecisionContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["resource"] != "approval-hierarchy:all" || body["action"] != "approval-hierarchy:read" {
			t.Fatalf("authorization request: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "requires_approval": false, "decision_reason": "policy_allow"})
	}))
	defer server.Close()
	client := &infrastructure.AuthorizationHTTPClient{BaseURL: server.URL}
	allowed, reason, err := client.CheckAccess(context.Background(), "user_admin", []string{"platform-admin"}, "approval-hierarchy:all", "approval-hierarchy:read")
	if err != nil || !allowed || reason != "policy_allow" {
		t.Fatalf("decision allowed=%v reason=%q err=%v", allowed, reason, err)
	}
}

func TestInternalHTTPClientsNeverFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected = true; w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/redirected", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := &infrastructure.UserDirectoryHTTPClient{BaseURL: source.URL}
	if _, err := client.GetAuthorizationContext(context.Background(), "user_123"); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected {
		t.Fatal("internal mTLS client followed a redirect to another endpoint")
	}
}

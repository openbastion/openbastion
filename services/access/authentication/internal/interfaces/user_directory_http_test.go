package interfaces

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

func userDirectoryServer(t *testing.T) (*httptest.Server, *infrastructure.InMemoryStore) {
	t.Helper()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuthenticationService(store, infrastructure.Argon2Hasher{}, infrastructure.NewTokenIssuer(make([]byte, 32)), time.Hour)
	h := NewHTTPServer(svc).Routes()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, store
}

func TestUserDirectoryAuthorizationContext_ReturnsCurrentRolesWithoutProfile(t *testing.T) {
	ts, store := userDirectoryServer(t)
	user := &domain.User{ID: "user_directory_1", Username: "private-login", DisplayName: "Private Name", Roles: []string{"dba", "auditor"}}
	if err := store.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	res, err := http.Get(ts.URL + "/auth/v1/internal/users/" + user.ID + "/authorization-context")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["user_id"] != user.ID || got["exists"] != true || got["active"] != true {
		t.Fatalf("unexpected authorization context: %#v", got)
	}
	roles, ok := got["roles"].([]any)
	if !ok || len(roles) != 2 || roles[0] != "dba" || roles[1] != "auditor" {
		t.Fatalf("roles = %#v, want [dba auditor]", got["roles"])
	}
	for _, forbidden := range []string{"username", "display_name", "password_hash", "identity_source", "external_subject"} {
		if _, exists := got[forbidden]; exists {
			t.Fatalf("response leaked %q: %#v", forbidden, got)
		}
	}
}

func TestUserDirectoryAuthorizationContext_DisabledUserHasNoRoles(t *testing.T) {
	ts, store := userDirectoryServer(t)
	disabledAt := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	user := &domain.User{ID: "user_disabled_1", Username: "disabled-login", Roles: []string{"platform-admin"}, DisabledAt: &disabledAt}
	if err := store.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(ts.URL + "/auth/v1/internal/users/" + user.ID + "/authorization-context")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || got["exists"] != true || got["active"] != false || len(got["roles"].([]any)) != 0 {
		t.Fatalf("disabled identity must have no authorization roles: status=%d body=%#v", res.StatusCode, got)
	}
}

func TestUserDirectoryAuthorizationContext_UnknownUserIsInactiveWithoutEnumeration(t *testing.T) {
	ts, _ := userDirectoryServer(t)
	res, err := http.Get(ts.URL + "/auth/v1/internal/users/not-found/authorization-context")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["exists"] != false || got["active"] != false || got["roles"] == nil || len(got["roles"].([]any)) != 0 {
		t.Fatalf("unknown identity must be inactive with no roles: %#v", got)
	}
}

func TestUserDirectoryAuthorizationContext_RejectsWrongMethodAndMalformedID(t *testing.T) {
	ts, _ := userDirectoryServer(t)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/auth/v1/internal/users/user_1/authorization-context", http.StatusMethodNotAllowed},
		{http.MethodGet, "/auth/v1/internal/users/user.bad/authorization-context", http.StatusBadRequest},
	} {
		req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, res.StatusCode, tc.want)
		}
	}
}

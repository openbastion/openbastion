package interfaces_test

// ADR-0043: POST /authz/v1/policies (relayed by the Gateway as POST /policies) answers a
// refusal with its reason, a duplicate with 409, and a failing store with a 503 that names
// nothing of it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/authorization/internal/application"
	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/internal/interfaces"
)

// store holds an admin policy, and fails Create with createErr.
type store struct{ createErr error }

func (s store) Create(context.Context, *domain.Policy) error { return s.createErr }
func (store) ForRoles(_ context.Context, roles []string) ([]*domain.Policy, error) {
	for _, r := range roles {
		if r == "platform-admin" {
			return []*domain.Policy{{Role: r, ResourcePattern: application.PolicyAdminResource, ActionPattern: "authz:policy:create", Effect: domain.EffectAllow}}, nil
		}
	}
	return nil, nil
}
func (store) Count(context.Context) (int, error) { return 1, nil }

func post(t *testing.T, s domain.PolicyRepository, roles []string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"name": "p", "role": "dba", "resourcePattern": "vault:account:a", "actionPattern": "vault:account:read", "effect": "allow", "createdBy": "u", "actorRoles": roles})
	rec := httptest.NewRecorder()
	interfaces.NewHTTPServer(application.NewAuthorizationService(s)).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/authz/v1/policies", bytes.NewReader(b)))
	return rec
}

func TestCreatePolicy_ARefusalSaysWhy_ADuplicateIs409_AFailureNamesNothing(t *testing.T) {
	failing := store{createErr: errors.New(`pq: could not connect to server at "10.9.8.1", port 5432`)}
	if rec := post(t, failing, []string{"platform-admin"}); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "10.9.8.1") || strings.Contains(rec.Body.String(), "pq:") {
		t.Fatalf("a failing store: %d %q", rec.Code, rec.Body.String())
	}
	if rec := post(t, store{createErr: domain.ErrAlreadyExists}, []string{"platform-admin"}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("a duplicate: %d %q", rec.Code, rec.Body.String())
	}
	if rec := post(t, store{}, []string{"dba"}); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "access denied") {
		t.Fatalf("a refusal: %d %q", rec.Code, rec.Body.String())
	}
	if rec := post(t, store{}, []string{"platform-admin"}); rec.Code != http.StatusCreated {
		t.Fatalf("an admin: %d %q", rec.Code, rec.Body.String())
	}
}

func TestCreatePolicy_ActionPatternIsPersistedAndLegacyOmissionDefaultsWildcard(t *testing.T) {
	var captured *domain.Policy
	st := captureStore{store: store{}, captured: &captured}
	rec := post(t, st, []string{"platform-admin"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if captured == nil || captured.ActionPattern != "vault:account:read" {
		t.Fatalf("action pattern not persisted: %+v", captured)
	}

	b, _ := json.Marshal(map[string]any{"name": "legacy", "role": "dba", "resourcePattern": "vault:account:a", "effect": "allow", "actorRoles": []string{"platform-admin"}})
	rec = httptest.NewRecorder()
	interfaces.NewHTTPServer(application.NewAuthorizationService(captureStore{store: store{}, captured: &captured})).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/authz/v1/policies", bytes.NewReader(b)))
	if rec.Code != http.StatusCreated || captured.ActionPattern != "*" {
		t.Fatalf("legacy default: status=%d policy=%+v", rec.Code, captured)
	}
}

type captureStore struct {
	store
	captured **domain.Policy
}

func (s captureStore) Create(_ context.Context, p *domain.Policy) error {
	*s.captured = p
	return s.store.createErr
}

func TestCreatePolicy_InvalidPatternReturnsBadRequest(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"name": "bad", "role": "dba", "resourcePattern": "vault:account:*", "actionPattern": "audit:*:read", "effect": "allow", "actorRoles": []string{"platform-admin"}})
	rec := httptest.NewRecorder()
	interfaces.NewHTTPServer(application.NewAuthorizationService(store{})).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/authz/v1/policies", bytes.NewReader(b)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

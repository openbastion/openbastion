package interfaces

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/application"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/infrastructure"
)

type testUsers map[string]domain.UserAuthorizationContext

func (u testUsers) GetAuthorizationContext(_ context.Context, id string) (domain.UserAuthorizationContext, error) {
	if user, ok := u[id]; ok {
		return user, nil
	}
	return domain.UserAuthorizationContext{UserID: id, Roles: []string{}}, nil
}

type testAuthorization struct {
	allowed bool
	err     error
}

func (a testAuthorization) CheckAccess(context.Context, string, []string, string, string) (bool, string, error) {
	return a.allowed, "", a.err
}

type testAudit struct{ err error }

func (a testAudit) EmitEvent(context.Context, string, string, string, string, map[string]string, bool) error {
	return a.err
}

func hierarchyHandler(auditErr error) http.Handler {
	users := testUsers{
		"user_admin": {UserID: "user_admin", Exists: true, Active: true, Roles: []string{"platform-admin"}},
		"user_a":     {UserID: "user_a", Exists: true, Active: true, Roles: []string{"operator"}},
		"user_b":     {UserID: "user_b", Exists: true, Active: true, Roles: []string{"operator"}},
		"user_c":     {UserID: "user_c", Exists: true, Active: true, Roles: []string{"operator"}},
	}
	service := application.NewHierarchyService(infrastructure.NewMemoryStore(), users, testAuthorization{allowed: true}, testAudit{err: auditErr})
	return NewHTTPServer(service).Routes()
}

func TestHierarchyHTTP_SetReadAndDeleteWithRevisionETag(t *testing.T) {
	h := hierarchyHandler(nil)
	put := httptest.NewRequest(http.MethodPut, "/internal/v1/approval-hierarchy/users/user_a/manager", strings.NewReader(`{"context":{"actor_user_id":"user_admin","actor_roles":["platform-admin"]},"manager_user_id":"user_b","expected_revision":0}`))
	put.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, put)
	if w.Code != http.StatusOK || w.Header().Get("ETag") != `"hierarchy-1"` {
		t.Fatalf("PUT status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/internal/v1/approval-hierarchy/users/user_a/manager?actor_user_id=user_admin&actor_roles=platform-admin", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, get)
	var response managerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || response.Manager == nil || response.Manager.ManagerUserID != "user_b" || response.Revision != 1 {
		t.Fatalf("GET response: status=%d %+v", w.Code, response)
	}

	deleteBody := `{"context":{"actor_user_id":"user_admin","actor_roles":["platform-admin"]},"expected_revision":1}`
	del := httptest.NewRequest(http.MethodDelete, "/internal/v1/approval-hierarchy/users/user_a/manager", strings.NewReader(deleteBody))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, del)
	if w.Code != http.StatusOK || w.Header().Get("ETag") != `"hierarchy-2"` {
		t.Fatalf("DELETE status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}
}

func TestHierarchyHTTP_CycleAndStaleRevisionAreConflicts(t *testing.T) {
	h := hierarchyHandler(nil)
	request := func(user, manager string, revision int) *httptest.ResponseRecorder {
		body := `{"context":{"actor_user_id":"user_admin","actor_roles":["platform-admin"]},"manager_user_id":"` + manager + `","expected_revision":` + strconv.Itoa(revision) + `}`
		req := httptest.NewRequest(http.MethodPut, "/internal/v1/approval-hierarchy/users/"+user+"/manager", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if got := request("user_a", "user_b", 0).Code; got != http.StatusOK {
		t.Fatalf("first mutation status=%d", got)
	}
	if got := request("user_b", "user_a", 1).Code; got != http.StatusConflict {
		t.Fatalf("cycle status=%d, want 409", got)
	}
	if got := request("user_c", "user_b", 0).Code; got != http.StatusConflict {
		t.Fatalf("stale revision status=%d, want 409", got)
	}
}

func TestHierarchyHTTP_FailsClosedOnAuditAndRejectsUntrustedFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.Handler
		body    string
		want    int
	}{
		{"audit unavailable", hierarchyHandler(errors.New("audit down")), `{"context":{"actor_user_id":"user_admin","actor_roles":["platform-admin"]},"manager_user_id":"user_b","expected_revision":0}`, http.StatusServiceUnavailable},
		{"unknown body field", hierarchyHandler(nil), `{"context":{"actor_user_id":"user_admin","actor_roles":["platform-admin"]},"manager_user_id":"user_b","expected_revision":0,"approver_user_id":"attacker"}`, http.StatusBadRequest},
		{"missing verified actor", hierarchyHandler(nil), `{"manager_user_id":"user_b","expected_revision":0}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/internal/v1/approval-hierarchy/users/user_a/manager", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

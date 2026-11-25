package interfaces_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type hierarchyAuthzCall struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type hierarchyWorkflow struct {
	server     *httptest.Server
	status     int
	lastMethod string
	lastPath   string
	lastQuery  url.Values
	lastBody   map[string]any
	response   any
	calls      int
}

func newHierarchyWorkflow(t *testing.T) *hierarchyWorkflow {
	t.Helper()
	m := &hierarchyWorkflow{status: http.StatusOK}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.calls++
		m.lastMethod, m.lastPath, m.lastQuery = r.Method, r.URL.Path, r.URL.Query()
		if r.Body != nil {
			data, _ := io.ReadAll(r.Body)
			if len(data) > 0 {
				_ = json.Unmarshal(data, &m.lastBody)
			}
		}
		if m.status != http.StatusOK {
			http.Error(w, "private workflow detail", m.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"hierarchy-7"`)
		_ = json.NewEncoder(w).Encode(m.response)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func newHierarchyGateway(t *testing.T, authzStatus int, allowed bool, workflow *hierarchyWorkflow, authzCalls *[]hierarchyAuthzCall) http.Handler {
	t.Helper()
	auth := newFakeTokenVerifierServer(t, "tok-admin", "user_admin", "admin", []string{"platform-admin", "sre"})
	t.Cleanup(auth.Close)
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call hierarchyAuthzCall
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		*authzCalls = append(*authzCalls, call)
		if authzStatus != http.StatusOK {
			http.Error(w, "private authz detail", authzStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": allowed, "requires_approval": false, "decision_reason": "test"})
	}))
	t.Cleanup(authz.Close)
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithWorkflowServiceURL(workflow.server.URL)
	return gw.Routes()
}

func hierarchyRequest(handler http.Handler, method, path, body, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-admin")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestApprovalHierarchy_ListChecksPermissionAndMapsInternalContract(t *testing.T) {
	workflow := newHierarchyWorkflow(t)
	workflow.response = map[string]any{
		"items": []any{map[string]any{"user_id": "user_a", "manager_user_id": "user_b", "revision": 4, "updated_at": "2026-11-24T12:00:00Z"}},
		"page":  1, "page_size": 20, "total_items": 1, "revision": 7,
	}
	var authzCalls []hierarchyAuthzCall
	handler := newHierarchyGateway(t, http.StatusOK, true, workflow, &authzCalls)
	rec := hierarchyRequest(handler, http.MethodGet, "/approval-hierarchy?managerUserId=user_b&page=1&pageSize=20", "", "")
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"hierarchy-7"` || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET: status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(authzCalls) != 1 || authzCalls[0].Resource != "approval-hierarchy:reports:user_b" || authzCalls[0].Action != "approval-hierarchy:read" || strings.Join(authzCalls[0].ActorRoles, ",") != "platform-admin,sre" {
		t.Fatalf("Authorization calls: %+v", authzCalls)
	}
	if workflow.calls != 1 || workflow.lastMethod != http.MethodGet || workflow.lastPath != "/internal/v1/approval-hierarchy" || workflow.lastQuery.Get("actor_user_id") != "user_admin" || strings.Join(workflow.lastQuery["actor_roles"], ",") != "platform-admin,sre" || workflow.lastQuery.Get("manager_user_id") != "user_b" {
		t.Fatalf("Workflow call: method=%s path=%s query=%v", workflow.lastMethod, workflow.lastPath, workflow.lastQuery)
	}
	var public map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	if public["totalItems"] != float64(1) || public["pageSize"] != float64(20) {
		t.Fatalf("public fields were not mapped: %#v", public)
	}
	if _, leaked := public["actor_user_id"]; leaked {
		t.Fatalf("internal actor leaked: %#v", public)
	}
	item := public["items"].([]any)[0].(map[string]any)
	if item["userId"] != "user_a" || item["managerUserId"] != "user_b" {
		t.Fatalf("public item: %#v", item)
	}
}

func TestApprovalHierarchy_PutUsesVerifiedIdentityAndIfMatch(t *testing.T) {
	workflow := newHierarchyWorkflow(t)
	workflow.response = map[string]any{"user_id": "user_a", "manager_user_id": "user_b", "revision": 1, "updated_at": "2026-11-24T12:00:00Z"}
	var authzCalls []hierarchyAuthzCall
	handler := newHierarchyGateway(t, http.StatusOK, true, workflow, &authzCalls)
	rec := hierarchyRequest(handler, http.MethodPut, "/approval-hierarchy/users/user_a/manager", `{"managerUserId":"user_b"}`, `"hierarchy-0"`)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"hierarchy-7"` {
		t.Fatalf("PUT: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(authzCalls) != 1 || authzCalls[0].Resource != "approval-hierarchy:user:user_a" || authzCalls[0].Action != "approval-hierarchy:manage" {
		t.Fatalf("Authorization calls: %+v", authzCalls)
	}
	if workflow.lastMethod != http.MethodPut || workflow.lastPath != "/internal/v1/approval-hierarchy/users/user_a/manager" {
		t.Fatalf("Workflow target: %s %s", workflow.lastMethod, workflow.lastPath)
	}
	if workflow.lastBody["manager_user_id"] != "user_b" || workflow.lastBody["expected_revision"] != float64(0) {
		t.Fatalf("Workflow body: %#v", workflow.lastBody)
	}
	ctx := workflow.lastBody["context"].(map[string]any)
	if ctx["actor_user_id"] != "user_admin" || strings.Join(anyStrings(ctx["actor_roles"]), ",") != "platform-admin,sre" {
		t.Fatalf("verified identity not injected: %#v", ctx)
	}
}

func TestApprovalHierarchy_RejectsAuthorizationAndMissingPreconditionBeforeWorkflow(t *testing.T) {
	workflow := newHierarchyWorkflow(t)
	var authzCalls []hierarchyAuthzCall
	handler := newHierarchyGateway(t, http.StatusOK, false, workflow, &authzCalls)
	rec := hierarchyRequest(handler, http.MethodPut, "/approval-hierarchy/users/user_a/manager", `{"managerUserId":"user_b"}`, `"hierarchy-0"`)
	if rec.Code != http.StatusForbidden || workflow.calls != 0 {
		t.Fatalf("denied request: status=%d workflow calls=%d", rec.Code, workflow.calls)
	}

	workflow2 := newHierarchyWorkflow(t)
	var authzCalls2 []hierarchyAuthzCall
	handler2 := newHierarchyGateway(t, http.StatusOK, true, workflow2, &authzCalls2)
	rec = hierarchyRequest(handler2, http.MethodPut, "/approval-hierarchy/users/user_a/manager", `{"managerUserId":"user_b"}`, "")
	if rec.Code != http.StatusBadRequest || workflow2.calls != 0 || len(authzCalls2) != 0 {
		t.Fatalf("missing If-Match: status=%d authz=%d workflow=%d", rec.Code, len(authzCalls2), workflow2.calls)
	}
}

func TestApprovalHierarchy_UpstreamErrorsAreSanitized(t *testing.T) {
	workflow := newHierarchyWorkflow(t)
	workflow.status = http.StatusServiceUnavailable
	var authzCalls []hierarchyAuthzCall
	handler := newHierarchyGateway(t, http.StatusOK, true, workflow, &authzCalls)
	rec := hierarchyRequest(handler, http.MethodGet, "/approval-hierarchy/users/user_a/manager", "", "")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "private workflow detail") {
		t.Fatalf("upstream error leaked: %d %s", rec.Code, rec.Body.String())
	}
}

func anyStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

package infrastructure_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func TestWorkflowHTTPClient_CreateUsesSystemContextAndStableSessionIdempotency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/approval-requests" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		contextValue := body["context"].(map[string]any)
		if len(contextValue) != 0 || body["request_id"] != "session_1" || body["resource_id"] != "session_1" || body["idempotency_key"] != "session_1" || body["requester_user_id"] != "user_a" {
			t.Fatalf("Workflow create request: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"request_id": "session_1", "resource_type": "session", "resource_id": "session_1", "requester_user_id": "user_a", "account_id": "acct_1", "ticket_reference": "CHG-1", "approver_user_id": "user_b", "hierarchy_revision": 4, "status": "pending", "decision_expires_at": "2026-11-24T12:10:00Z", "created_at": "2026-11-24T12:00:00Z", "revision": 1})
	}))
	defer server.Close()
	client := &infrastructure.WorkflowHTTPClient{BaseURL: server.URL}
	request, err := client.CreateApprovalRequest(context.Background(), domain.WorkflowApprovalInput{RequestID: "session_1", ResourceType: "session", ResourceID: "session_1", RequesterUserID: "user_a", AccountID: "acct_1", TicketReference: "CHG-1", DecisionExpiresAt: time.Date(2026, 11, 24, 12, 10, 0, 0, time.UTC), IdempotencyKey: "session_1"})
	if err != nil || request.ApproverUserID != "user_b" || request.HierarchyRevision != 4 || request.Status != domain.WorkflowApprovalPending {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestWorkflowHTTPClient_ListAndDecisionForwardVerifiedActor(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			if r.URL.Query().Get("actor_user_id") != "user_b" || strings.Join(r.URL.Query()["actor_roles"], ",") != "approver,sre" {
				t.Fatalf("list query: %v", r.URL.Query())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "page": 1, "page_size": 20, "total_items": 0, "truncated": false})
			return
		}
		if r.Method == http.MethodPost {
			if r.URL.Path != "/internal/v1/approval-requests/session_1/approve" {
				t.Fatalf("decision path: %s", r.URL.Path)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			ctx := body["context"].(map[string]any)
			if ctx["actor_user_id"] != "user_b" || body["expected_revision"] != float64(1) {
				t.Fatalf("decision body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"request_id": "session_1", "resource_type": "session", "resource_id": "session_1", "requester_user_id": "user_a", "account_id": "acct_1", "ticket_reference": "CHG-1", "approver_user_id": "user_b", "hierarchy_revision": 1, "status": "approved", "decision_expires_at": "2026-11-24T12:10:00Z", "created_at": "2026-11-24T12:00:00Z", "decided_at": "2026-11-24T12:01:00Z", "decided_by": "user_b", "revision": 2})
		}
	}))
	defer server.Close()
	client := &infrastructure.WorkflowHTTPClient{BaseURL: server.URL}
	if _, err := client.ListPendingApprovals(context.Background(), "user_b", []string{"approver", "sre"}, 1, 20); err != nil {
		t.Fatal(err)
	}
	request, err := client.DecideApprovalRequest(context.Background(), "session_1", "user_b", []string{"stale"}, 1, domain.WorkflowApprovalApproved, "")
	if err != nil || request.Status != domain.WorkflowApprovalApproved || request.DecidedBy != "user_b" || calls != 2 {
		t.Fatalf("request=%+v calls=%d err=%v", request, calls, err)
	}
}

func TestWorkflowHTTPClient_MapsPermanentAndTransientFailures(t *testing.T) {
	for status, want := range map[int]error{http.StatusForbidden: domain.ErrWorkflowPermanent, http.StatusBadRequest: domain.ErrWorkflowPermanent, http.StatusConflict: domain.ErrConflict, http.StatusNotFound: domain.ErrNotFound, http.StatusServiceUnavailable: domain.ErrUnavailable} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "private upstream detail", status) }))
		client := &infrastructure.WorkflowHTTPClient{BaseURL: server.URL}
		_, err := client.GetApprovalRequest(context.Background(), "session_1")
		server.Close()
		if err == nil || !errors.Is(err, want) || strings.Contains(err.Error(), "private upstream detail") {
			t.Fatalf("status=%d err=%v want=%v", status, err, want)
		}
	}
}

func TestWorkflowHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected = true; w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := &infrastructure.WorkflowHTTPClient{BaseURL: source.URL}
	if _, err := client.GetApprovalRequest(context.Background(), "session_1"); err == nil {
		t.Fatal("redirect accepted")
	}
	if redirected {
		t.Fatal("mTLS Workflow client followed redirect")
	}
}

package interfaces

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/application"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/infrastructure"
)

type approvalTestUsers map[string]domain.UserAuthorizationContext

func (u approvalTestUsers) GetAuthorizationContext(_ context.Context, id string) (domain.UserAuthorizationContext, error) {
	if value, ok := u[id]; ok {
		return value, nil
	}
	return domain.UserAuthorizationContext{UserID: id, Roles: []string{}}, nil
}

type approvalTestAuthz struct{}

func (approvalTestAuthz) CheckAccess(context.Context, string, []string, string, string) (bool, string, error) {
	return true, "", nil
}

type approvalTestAudit struct{}

func (approvalTestAudit) EmitEvent(context.Context, string, string, string, string, map[string]string, bool) error {
	return nil
}

func approvalHTTPHandler(t *testing.T) http.Handler {
	t.Helper()
	store := infrastructure.NewMemoryStore()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	if _, _, err := store.SetManager(context.Background(), "user_a", "user_b", 0, now, domain.AuditOutboxEvent{ID: "hierarchy", ActorID: "user_admin", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	users := approvalTestUsers{
		"user_a": {UserID: "user_a", Exists: true, Active: true, Roles: []string{"operator"}},
		"user_b": {UserID: "user_b", Exists: true, Active: true, Roles: []string{"approver"}},
	}
	approvals := application.NewApprovalService(store, store, users, approvalTestAuthz{}, approvalTestAudit{}).WithClock(func() time.Time { return now })
	return NewHTTPServer(nil).WithApprovalService(approvals).Routes()
}

func TestApprovalHTTP_CreateListDecideAndCancel(t *testing.T) {
	h := approvalHTTPHandler(t)
	create := `{"context":{},"request_id":"session_http_1","resource_type":"session","resource_id":"session_http_1","requester_user_id":"user_a","account_id":"acct_1","ticket_reference":"CHG-1","decision_expires_at":"2026-11-24T12:10:00Z","idempotency_key":"session_http_1"}`
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/approval-requests", strings.NewReader(create))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created approvalRequestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ApproverUserID != "user_b" || created.HierarchyRevision != 1 || created.Status != "pending" || created.Revision != 1 {
		t.Fatalf("created response: %+v", created)
	}

	list := httptest.NewRequest(http.MethodGet, "/internal/v1/approval-requests?actor_user_id=user_b&actor_roles=stale-role&page=1&page_size=10", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, list)
	var page approvalPageResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(page.Items) != 1 || page.Items[0].RequestID != "session_http_1" {
		t.Fatalf("list status=%d page=%+v body=%s", w.Code, page, w.Body.String())
	}

	approveBody := `{"context":{"actor_user_id":"user_b","actor_roles":["stale-role"]},"expected_revision":1,"reason":"approved"}`
	approve := httptest.NewRequest(http.MethodPost, "/internal/v1/approval-requests/session_http_1/approve", strings.NewReader(approveBody))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, approve)
	if w.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", w.Code, w.Body.String())
	}
	var decided approvalRequestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &decided); err != nil {
		t.Fatal(err)
	}
	if decided.Status != "approved" || decided.DecidedBy != "user_b" || decided.Revision != 2 {
		t.Fatalf("decided response: %+v", decided)
	}

	get := httptest.NewRequest(http.MethodGet, "/internal/v1/approval-requests/session_http_1", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, get)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"approved"`) {
		t.Fatalf("get request: %d %s", w.Code, w.Body.String())
	}

	create2 := strings.ReplaceAll(create, "session_http_1", "session_http_2")
	create2 = strings.ReplaceAll(create2, "CHG-1", "CHG-2")
	create = create2
	req = httptest.NewRequest(http.MethodPost, "/internal/v1/approval-requests", strings.NewReader(create))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second create status=%d body=%s", w.Code, w.Body.String())
	}
	cancelBody := `{"context":{},"expected_revision":1,"reason_code":"session_expired"}`
	cancel := httptest.NewRequest(http.MethodPost, "/internal/v1/approval-requests/session_http_2/cancel", strings.NewReader(cancelBody))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, cancel)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"cancelled"`) {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
}

func TestApprovalHTTP_CreateRequiresSystemContextAndRejectsSpoofedActor(t *testing.T) {
	h := approvalHTTPHandler(t)
	base := `"request_id":"session_spoof","resource_type":"session","resource_id":"session_spoof","requester_user_id":"user_a","account_id":"acct_1","ticket_reference":"CHG-1","decision_expires_at":"2026-11-24T12:10:00Z","idempotency_key":"session_spoof"`
	for _, body := range []string{
		`{` + base + `}`,
		`{"context":{"actor_user_id":"user_a","actor_roles":["platform-admin"]},` + base + `}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/approval-requests", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("spoofed/missing context status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

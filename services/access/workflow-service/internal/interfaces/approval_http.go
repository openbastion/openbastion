package interfaces

import (
	"io"
	"net/http"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

type createApprovalHTTPRequest struct {
	Context           *requestContext `json:"context"`
	RequestID         string          `json:"request_id"`
	ResourceType      string          `json:"resource_type"`
	ResourceID        string          `json:"resource_id"`
	RequesterUserID   string          `json:"requester_user_id"`
	AccountID         string          `json:"account_id"`
	TicketReference   string          `json:"ticket_reference"`
	DecisionExpiresAt time.Time       `json:"decision_expires_at"`
	IdempotencyKey    string          `json:"idempotency_key"`
}

type decideApprovalHTTPRequest struct {
	Context          *requestContext `json:"context"`
	ExpectedRevision *uint64         `json:"expected_revision"`
	Reason           string          `json:"reason"`
}

type cancelApprovalHTTPRequest struct {
	Context          *requestContext `json:"context"`
	ExpectedRevision *uint64         `json:"expected_revision"`
	ReasonCode       string          `json:"reason_code"`
}

type approvalRequestResponse struct {
	RequestID         string     `json:"request_id"`
	ResourceType      string     `json:"resource_type"`
	ResourceID        string     `json:"resource_id"`
	RequesterUserID   string     `json:"requester_user_id"`
	AccountID         string     `json:"account_id"`
	TicketReference   string     `json:"ticket_reference"`
	ApproverUserID    string     `json:"approver_user_id"`
	HierarchyRevision uint64     `json:"hierarchy_revision"`
	Status            string     `json:"status"`
	DecisionExpiresAt time.Time  `json:"decision_expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
	DecidedBy         string     `json:"decided_by"`
	DecidedAt         *time.Time `json:"decided_at"`
	DecisionReason    string     `json:"decision_reason"`
	Revision          uint64     `json:"revision"`
}

type approvalPageResponse struct {
	Items      []approvalRequestResponse `json:"items"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalItems int                       `json:"total_items"`
	Truncated  bool                      `json:"truncated"`
}

func (s *HTTPServer) handleCreateApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		http.Error(w, "workflow service unavailable", http.StatusServiceUnavailable)
		return
	}
	var req createApprovalHTTPRequest
	if !decodeBody(w, r, &req) {
		return
	}
	// The Broker worker is a system caller. The requester is copied from its
	// durable session row and is never accepted as the actor of this RPC.
	if req.Context == nil || req.Context.ActorUserID != "" || len(req.Context.ActorRoles) != 0 {
		http.Error(w, "invalid system request context", http.StatusBadRequest)
		return
	}
	created, err := s.approvals.CreateApprovalRequest(r.Context(), domain.CreateApprovalInput{
		RequestID: req.RequestID, ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		RequesterUserID: req.RequesterUserID, AccountID: req.AccountID, TicketReference: req.TicketReference,
		DecisionExpiresAt: req.DecisionExpiresAt, IdempotencyKey: req.IdempotencyKey,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approvalResponse(created))
}

func (s *HTTPServer) handleGetApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		http.Error(w, "workflow service unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	if !approvalBodyAbsent(w, r) {
		return
	}
	request, err := s.approvals.GetApprovalRequest(r.Context(), r.PathValue("request_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approvalResponse(request))
}

func (s *HTTPServer) handleListPendingApprovals(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		http.Error(w, "workflow service unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, ok := contextFromQuery(w, r, "page", "page_size")
	if !ok {
		return
	}
	if !approvalBodyAbsent(w, r) {
		return
	}
	page, pageSize, _, ok := hierarchyQuery(w, r.URL.Query(), false)
	if !ok {
		return
	}
	result, err := s.approvals.ListPendingApprovals(r.Context(), ctx.ActorUserID, ctx.ActorRoles, page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	items := make([]approvalRequestResponse, 0, len(result.Items))
	for i := range result.Items {
		items = append(items, approvalResponse(&result.Items[i]))
	}
	writeJSON(w, http.StatusOK, approvalPageResponse{Items: items, Page: result.Page, PageSize: result.PageSize, TotalItems: result.TotalItems, Truncated: result.Truncated})
}

func (s *HTTPServer) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	s.handleDecideApprovalRequest(w, r, domain.ApprovalApproved)
}
func (s *HTTPServer) handleRejectRequest(w http.ResponseWriter, r *http.Request) {
	s.handleDecideApprovalRequest(w, r, domain.ApprovalRejected)
}

func (s *HTTPServer) handleDecideApprovalRequest(w http.ResponseWriter, r *http.Request, decision domain.ApprovalStatus) {
	if s.approvals == nil {
		http.Error(w, "workflow service unavailable", http.StatusServiceUnavailable)
		return
	}
	var req decideApprovalHTTPRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ExpectedRevision == nil || req.Context == nil || req.Context.ActorUserID == "" {
		http.Error(w, "context.actor_user_id and expected_revision are required", http.StatusBadRequest)
		return
	}
	updated, err := s.approvals.DecideApprovalRequest(r.Context(), r.PathValue("request_id"), req.Context.ActorUserID, req.Context.ActorRoles, *req.ExpectedRevision, decision, req.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approvalResponse(updated))
}

func (s *HTTPServer) handleCancelApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		http.Error(w, "workflow service unavailable", http.StatusServiceUnavailable)
		return
	}
	var req cancelApprovalHTTPRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ExpectedRevision == nil || req.Context == nil || req.Context.ActorUserID != "" || len(req.Context.ActorRoles) != 0 {
		http.Error(w, "expected_revision and system request context are required", http.StatusBadRequest)
		return
	}
	updated, err := s.approvals.CancelApprovalRequest(r.Context(), r.PathValue("request_id"), *req.ExpectedRevision, req.ReasonCode)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, approvalResponse(updated))
}

func approvalBodyAbsent(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	_ = r.Body.Close()
	if err != nil || len(data) != 0 {
		http.Error(w, "request body is not allowed", http.StatusBadRequest)
		return false
	}
	return true
}

func approvalResponse(request *domain.ApprovalRequest) approvalRequestResponse {
	return approvalRequestResponse{
		RequestID: request.ID, ResourceType: request.ResourceType, ResourceID: request.ResourceID,
		RequesterUserID: request.RequesterUserID, AccountID: request.AccountID, TicketReference: request.TicketReference,
		ApproverUserID: request.ApproverUserID, HierarchyRevision: request.HierarchyRevision, Status: string(request.Status),
		DecisionExpiresAt: request.DecisionExpiresAt, CreatedAt: request.CreatedAt, DecidedBy: request.DecidedBy,
		DecidedAt: request.DecidedAt, DecisionReason: request.DecisionReason, Revision: request.Revision,
	}
}

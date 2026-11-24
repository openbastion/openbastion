package interfaces

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/application"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

const maxHierarchyBody = 16 << 10

type HTTPServer struct {
	svc       *application.HierarchyService
	approvals *application.ApprovalService
	metrics   http.Handler
}

func NewHTTPServer(svc *application.HierarchyService) *HTTPServer { return &HTTPServer{svc: svc} }

func (s *HTTPServer) WithApprovalService(approvals *application.ApprovalService) *HTTPServer {
	s.approvals = approvals
	return s
}

func (s *HTTPServer) WithMetrics(handler http.Handler) *HTTPServer {
	s.metrics = handler
	return s
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/approval-hierarchy", s.handleListHierarchy)
	mux.HandleFunc("GET /internal/v1/approval-hierarchy/users/{user_id}/manager", s.handleGetManager)
	mux.HandleFunc("GET /internal/v1/approval-hierarchy/users/{manager_user_id}/reports", s.handleListReports)
	mux.HandleFunc("PUT /internal/v1/approval-hierarchy/users/{user_id}/manager", s.handleSetManager)
	mux.HandleFunc("DELETE /internal/v1/approval-hierarchy/users/{user_id}/manager", s.handleDeleteManager)
	mux.HandleFunc("POST /internal/v1/approval-requests", s.handleCreateApprovalRequest)
	mux.HandleFunc("GET /internal/v1/approval-requests", s.handleListPendingApprovals)
	mux.HandleFunc("GET /internal/v1/approval-requests/{request_id}", s.handleGetApprovalRequest)
	mux.HandleFunc("POST /internal/v1/approval-requests/{request_id}/approve", s.handleApproveRequest)
	mux.HandleFunc("POST /internal/v1/approval-requests/{request_id}/reject", s.handleRejectRequest)
	mux.HandleFunc("POST /internal/v1/approval-requests/{request_id}/cancel", s.handleCancelApprovalRequest)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	if s.metrics != nil {
		mux.Handle("/metrics", s.metrics)
	} else {
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		})
	}
	return mux
}

type requestContext struct {
	ActorUserID string   `json:"actor_user_id"`
	ActorRoles  []string `json:"actor_roles"`
}

type setManagerRequest struct {
	Context          requestContext `json:"context"`
	ManagerUserID    string         `json:"manager_user_id"`
	ExpectedRevision *uint64        `json:"expected_revision"`
}

type deleteManagerRequest struct {
	Context          requestContext `json:"context"`
	ExpectedRevision *uint64        `json:"expected_revision"`
}

type managerRelationResponse struct {
	UserID        string    `json:"user_id"`
	ManagerUserID string    `json:"manager_user_id"`
	Revision      uint64    `json:"revision"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type managerResponse struct {
	UserID   string                   `json:"user_id"`
	Manager  *managerRelationResponse `json:"manager"`
	Revision uint64                   `json:"revision"`
}

type hierarchyPageResponse struct {
	Items      []managerRelationResponse `json:"items"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalItems int                       `json:"total_items"`
	Revision   uint64                    `json:"revision"`
}

type directReportResponse struct {
	UserID    string    `json:"user_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type directReportsPageResponse struct {
	Items      []directReportResponse `json:"items"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalItems int                    `json:"total_items"`
	Revision   uint64                 `json:"revision"`
}

type mutationResponse struct {
	Revision uint64 `json:"revision"`
}

func (s *HTTPServer) handleGetManager(w http.ResponseWriter, r *http.Request) {
	ctx, ok := contextFromQuery(w, r)
	if !ok {
		return
	}
	userID := r.PathValue("user_id")
	relation, revision, err := s.svc.GetManager(r.Context(), ctx.ActorUserID, ctx.ActorRoles, userID)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("ETag", hierarchyETag(revision))
	w.Header().Set("Cache-Control", "no-store")
	out := managerResponse{UserID: userID, Revision: revision}
	if relation != nil {
		out.Manager = &managerRelationResponse{UserID: relation.SubordinateUserID, ManagerUserID: relation.ManagerUserID, Revision: relation.Revision, UpdatedAt: relation.UpdatedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *HTTPServer) handleListHierarchy(w http.ResponseWriter, r *http.Request) {
	ctx, ok := contextFromQuery(w, r, "page", "page_size", "manager_user_id")
	if !ok {
		return
	}
	page, pageSize, manager, ok := hierarchyQuery(w, r.URL.Query(), false)
	if !ok {
		return
	}
	result, err := s.svc.ListHierarchy(r.Context(), ctx.ActorUserID, ctx.ActorRoles, manager, page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("ETag", hierarchyETag(result.Revision))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, pageResponse(result))
}

func (s *HTTPServer) handleListReports(w http.ResponseWriter, r *http.Request) {
	ctx, ok := contextFromQuery(w, r, "page", "page_size")
	if !ok {
		return
	}
	page, pageSize, _, ok := hierarchyQuery(w, r.URL.Query(), true)
	if !ok {
		return
	}
	result, err := s.svc.ListHierarchy(r.Context(), ctx.ActorUserID, ctx.ActorRoles, r.PathValue("manager_user_id"), page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("ETag", hierarchyETag(result.Revision))
	w.Header().Set("Cache-Control", "no-store")
	items := make([]directReportResponse, 0, len(result.Items))
	for _, relation := range result.Items {
		items = append(items, directReportResponse{UserID: relation.SubordinateUserID, UpdatedAt: relation.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, directReportsPageResponse{Items: items, Page: result.Page, PageSize: result.PageSize, TotalItems: result.TotalItems, Revision: result.Revision})
}

func (s *HTTPServer) handleSetManager(w http.ResponseWriter, r *http.Request) {
	var req setManagerRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ExpectedRevision == nil || req.ManagerUserID == "" {
		http.Error(w, "expected_revision and manager_user_id are required", http.StatusBadRequest)
		return
	}
	relation, revision, err := s.svc.SetManager(r.Context(), req.Context.ActorUserID, req.Context.ActorRoles, r.PathValue("user_id"), req.ManagerUserID, *req.ExpectedRevision)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("ETag", hierarchyETag(revision))
	writeJSON(w, http.StatusOK, managerRelationResponse{UserID: relation.SubordinateUserID, ManagerUserID: relation.ManagerUserID, Revision: revision, UpdatedAt: relation.UpdatedAt})
}

func (s *HTTPServer) handleDeleteManager(w http.ResponseWriter, r *http.Request) {
	var req deleteManagerRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ExpectedRevision == nil {
		http.Error(w, "expected_revision is required", http.StatusBadRequest)
		return
	}
	revision, err := s.svc.DeleteManager(r.Context(), req.Context.ActorUserID, req.Context.ActorRoles, r.PathValue("user_id"), *req.ExpectedRevision)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("ETag", hierarchyETag(revision))
	writeJSON(w, http.StatusOK, mutationResponse{Revision: revision})
}

func contextFromQuery(w http.ResponseWriter, r *http.Request, allowedExtra ...string) (requestContext, bool) {
	if len(r.URL.RawQuery) > 4096 {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return requestContext{}, false
	}
	values := r.URL.Query()
	allowed := map[string]bool{"actor_user_id": true, "actor_roles": true}
	for _, key := range allowedExtra {
		allowed[key] = true
	}
	for key := range values {
		if !allowed[key] {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return requestContext{}, false
		}
	}
	actor := values["actor_user_id"]
	if len(actor) != 1 || actor[0] == "" {
		http.Error(w, "invalid request context", http.StatusBadRequest)
		return requestContext{}, false
	}
	roles := values["actor_roles"]
	if len(roles) > 64 {
		http.Error(w, "invalid request context", http.StatusBadRequest)
		return requestContext{}, false
	}
	for _, role := range roles {
		if role == "" || len(role) > 128 || strings.ContainsAny(role, ",\r\n") {
			http.Error(w, "invalid request context", http.StatusBadRequest)
			return requestContext{}, false
		}
	}
	return requestContext{ActorUserID: actor[0], ActorRoles: append([]string{}, roles...)}, true
}

func hierarchyQuery(w http.ResponseWriter, values url.Values, reports bool) (page, pageSize int, manager string, ok bool) {
	page, pageSize = 1, 20
	for key, entries := range values {
		if key == "actor_user_id" || key == "actor_roles" {
			continue
		}
		if len(entries) != 1 || entries[0] == "" {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return 0, 0, "", false
		}
		switch key {
		case "page":
			n, err := strconv.Atoi(entries[0])
			if err != nil || n < 1 || n > 1_000_000 {
				http.Error(w, "invalid page", http.StatusBadRequest)
				return 0, 0, "", false
			}
			page = n
		case "page_size":
			n, err := strconv.Atoi(entries[0])
			if err != nil || n < 1 || n > 100 {
				http.Error(w, "invalid page_size", http.StatusBadRequest)
				return 0, 0, "", false
			}
			pageSize = n
		case "manager_user_id":
			if reports {
				http.Error(w, "invalid query", http.StatusBadRequest)
				return 0, 0, "", false
			}
			manager = entries[0]
		default:
			http.Error(w, "invalid query", http.StatusBadRequest)
			return 0, 0, "", false
		}
	}
	return page, pageSize, manager, true
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHierarchyBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid request body", http.StatusBadRequest)
		}
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func pageResponse(page domain.HierarchyPage) hierarchyPageResponse {
	items := make([]managerRelationResponse, 0, len(page.Items))
	for _, relation := range page.Items {
		items = append(items, managerRelationResponse{UserID: relation.SubordinateUserID, ManagerUserID: relation.ManagerUserID, Revision: relation.Revision, UpdatedAt: relation.UpdatedAt})
	}
	return hierarchyPageResponse{Items: items, Page: page.Page, PageSize: page.PageSize, TotalItems: page.TotalItems, Revision: page.Revision}
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalid):
		http.Error(w, "invalid hierarchy request", http.StatusBadRequest)
	case errors.Is(err, domain.ErrForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, domain.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, domain.ErrConflict), errors.Is(err, domain.ErrCycle), errors.Is(err, domain.ErrExpired), errors.Is(err, domain.ErrIdempotencyConflict):
		http.Error(w, "hierarchy revision conflict or cycle", http.StatusConflict)
	default:
		log.Printf("workflow-service: hierarchy operation unavailable: %v", err)
		http.Error(w, "hierarchy service unavailable", http.StatusServiceUnavailable)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func hierarchyETag(revision uint64) string {
	return `"hierarchy-` + strconv.FormatUint(revision, 10) + `"`
}

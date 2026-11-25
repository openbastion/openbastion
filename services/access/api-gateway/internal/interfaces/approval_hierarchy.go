package interfaces

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"
)

const (
	approvalHierarchyReadAction   = "approval-hierarchy:read"
	approvalHierarchyManageAction = "approval-hierarchy:manage"
	approvalHierarchyAllResource  = "approval-hierarchy:all"
	maxApprovalHierarchyBody      = 16 << 10
	maxApprovalHierarchyResponse  = 64 << 10
)

type approvalHierarchyAccessRequest struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type approvalHierarchyAccessResponse struct {
	Allowed          bool   `json:"allowed"`
	RequiresApproval bool   `json:"requires_approval"`
	DecisionReason   string `json:"decision_reason"`
}

type workflowRequestContext struct {
	ActorUserID string   `json:"actor_user_id"`
	ActorRoles  []string `json:"actor_roles"`
}

type workflowManagerRelation struct {
	UserID        string    `json:"user_id"`
	ManagerUserID string    `json:"manager_user_id"`
	Revision      uint64    `json:"revision"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type workflowManagerResponse struct {
	UserID   string                   `json:"user_id"`
	Manager  *workflowManagerRelation `json:"manager"`
	Revision uint64                   `json:"revision"`
}

type workflowHierarchyPage struct {
	Items      []workflowManagerRelation `json:"items"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalItems int                       `json:"total_items"`
	Revision   uint64                    `json:"revision"`
}

type workflowDirectReport struct {
	UserID    string    `json:"user_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type workflowReportsPage struct {
	Items      []workflowDirectReport `json:"items"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalItems int                    `json:"total_items"`
	Revision   uint64                 `json:"revision"`
}

type workflowMutationResponse struct {
	Revision uint64 `json:"revision"`
}

type publicManagerSummary struct {
	UserID    string    `json:"userId"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type publicManagerResponse struct {
	UserID   string                `json:"userId"`
	Manager  *publicManagerSummary `json:"manager"`
	Revision uint64                `json:"revision"`
}

type publicHierarchyItem struct {
	UserID        string    `json:"userId"`
	ManagerUserID string    `json:"managerUserId"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type publicHierarchyPage struct {
	Items      []publicHierarchyItem `json:"items"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"pageSize"`
	TotalItems int                   `json:"totalItems"`
	Revision   uint64                `json:"revision"`
}

type publicManagerMutation struct {
	UserID        string    `json:"userId"`
	ManagerUserID string    `json:"managerUserId"`
	Revision      uint64    `json:"revision"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type publicHierarchyDelete struct {
	Revision uint64 `json:"revision"`
}

type publicSetManagerRequest struct {
	ManagerUserID string `json:"managerUserId"`
}

type workflowSetManagerRequest struct {
	Context          workflowRequestContext `json:"context"`
	ManagerUserID    string                 `json:"manager_user_id"`
	ExpectedRevision uint64                 `json:"expected_revision"`
}

type workflowDeleteManagerRequest struct {
	Context          workflowRequestContext `json:"context"`
	ExpectedRevision uint64                 `json:"expected_revision"`
}

// handleApprovalHierarchyCollection is the public hierarchy collection. The
// Gateway derives the actor from the verified bearer token and never forwards
// client-supplied identity or role claims.
func (g *GatewayServer) handleApprovalHierarchyCollection(w http.ResponseWriter, r *http.Request, id identity) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !approvalHierarchyNoBody(w, r) {
		return
	}
	values, err := neturl.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 4096 {
		http.Error(w, "invalid hierarchy query", http.StatusBadRequest)
		return
	}
	page, pageSize, managerID, ok := parsePublicHierarchyQuery(w, values, true)
	if !ok {
		return
	}
	resource := approvalHierarchyAllResource
	if managerID != "" {
		resource = "approval-hierarchy:reports:" + managerID
	}
	if !g.requireApprovalHierarchyAccess(w, r.Context(), id.Roles, resource, approvalHierarchyReadAction, managerID != "") {
		return
	}
	query := workflowActorQuery(id)
	query.Set("page", strconv.Itoa(page))
	query.Set("page_size", strconv.Itoa(pageSize))
	if managerID != "" {
		query.Set("manager_user_id", managerID)
	}
	resp, err := g.callWorkflow(r.Context(), http.MethodGet, "/internal/v1/approval-hierarchy?"+query.Encode(), nil)
	if err != nil {
		workflowUnavailable(w)
		return
	}
	defer resp.Body.Close()
	if !workflowSuccess(w, resp) {
		return
	}
	var internal workflowHierarchyPage
	if !decodeWorkflowResponse(resp.Body, &internal) {
		workflowUnavailable(w)
		return
	}
	copyWorkflowETag(w, resp)
	items := make([]publicHierarchyItem, 0, len(internal.Items))
	for _, item := range internal.Items {
		items = append(items, publicHierarchyItem{UserID: item.UserID, ManagerUserID: item.ManagerUserID, UpdatedAt: item.UpdatedAt})
	}
	writeGatewayJSON(w, http.StatusOK, publicHierarchyPage{Items: items, Page: internal.Page, PageSize: internal.PageSize, TotalItems: internal.TotalItems, Revision: internal.Revision})
}

func (g *GatewayServer) handleApprovalHierarchyItem(w http.ResponseWriter, r *http.Request, id identity) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	segments, ok := approvalHierarchyPathSegments(r.URL.EscapedPath())
	if !ok {
		http.Error(w, "invalid hierarchy path", http.StatusBadRequest)
		return
	}
	if len(segments) != 3 || segments[0] != "users" || !validApprovalHierarchyUserID(segments[1]) {
		http.NotFound(w, r)
		return
	}
	userID, action := segments[1], segments[2]
	switch action {
	case "manager":
		g.handleApprovalManager(w, r, id, userID)
	case "reports":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		g.handleApprovalReports(w, r, id, userID)
	default:
		http.NotFound(w, r)
	}
}

func (g *GatewayServer) handleApprovalManager(w http.ResponseWriter, r *http.Request, id identity, userID string) {
	resource := "approval-hierarchy:user:" + userID
	switch r.Method {
	case http.MethodGet:
		if !approvalHierarchyNoBody(w, r) {
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "invalid hierarchy query", http.StatusBadRequest)
			return
		}
		if !g.requireApprovalHierarchyAccess(w, r.Context(), id.Roles, resource, approvalHierarchyReadAction, true) {
			return
		}
		query := workflowActorQuery(id)
		resp, err := g.callWorkflow(r.Context(), http.MethodGet, "/internal/v1/approval-hierarchy/users/"+neturl.PathEscape(userID)+"/manager?"+query.Encode(), nil)
		if err != nil {
			workflowUnavailable(w)
			return
		}
		defer resp.Body.Close()
		if !workflowSuccess(w, resp) {
			return
		}
		var internal workflowManagerResponse
		if !decodeWorkflowResponse(resp.Body, &internal) {
			workflowUnavailable(w)
			return
		}
		copyWorkflowETag(w, resp)
		out := publicManagerResponse{UserID: internal.UserID, Revision: internal.Revision}
		if internal.Manager != nil {
			out.Manager = &publicManagerSummary{UserID: internal.Manager.ManagerUserID, UpdatedAt: internal.Manager.UpdatedAt}
		}
		writeGatewayJSON(w, http.StatusOK, out)
	case http.MethodPut:
		var body publicSetManagerRequest
		if !decodeApprovalHierarchyBody(w, r, &body) {
			return
		}
		if !validApprovalHierarchyUserID(body.ManagerUserID) {
			http.Error(w, "managerUserId is required", http.StatusBadRequest)
			return
		}
		revision, ok := parseHierarchyIfMatch(w, r)
		if !ok {
			return
		}
		if !g.requireApprovalHierarchyAccess(w, r.Context(), id.Roles, resource, approvalHierarchyManageAction, true) {
			return
		}
		internalBody, _ := json.Marshal(workflowSetManagerRequest{Context: workflowRequestContext{ActorUserID: id.UserID, ActorRoles: id.Roles}, ManagerUserID: body.ManagerUserID, ExpectedRevision: revision})
		resp, err := g.callWorkflow(r.Context(), http.MethodPut, "/internal/v1/approval-hierarchy/users/"+neturl.PathEscape(userID)+"/manager", internalBody)
		if err != nil {
			workflowUnavailable(w)
			return
		}
		defer resp.Body.Close()
		if !workflowSuccess(w, resp) {
			return
		}
		var internal workflowManagerRelation
		if !decodeWorkflowResponse(resp.Body, &internal) {
			workflowUnavailable(w)
			return
		}
		copyWorkflowETag(w, resp)
		writeGatewayJSON(w, http.StatusOK, publicManagerMutation{UserID: internal.UserID, ManagerUserID: internal.ManagerUserID, Revision: internal.Revision, UpdatedAt: internal.UpdatedAt})
	case http.MethodDelete:
		if !approvalHierarchyNoBody(w, r) {
			return
		}
		revision, ok := parseHierarchyIfMatch(w, r)
		if !ok {
			return
		}
		if !g.requireApprovalHierarchyAccess(w, r.Context(), id.Roles, resource, approvalHierarchyManageAction, true) {
			return
		}
		internalBody, _ := json.Marshal(workflowDeleteManagerRequest{Context: workflowRequestContext{ActorUserID: id.UserID, ActorRoles: id.Roles}, ExpectedRevision: revision})
		resp, err := g.callWorkflow(r.Context(), http.MethodDelete, "/internal/v1/approval-hierarchy/users/"+neturl.PathEscape(userID)+"/manager", internalBody)
		if err != nil {
			workflowUnavailable(w)
			return
		}
		defer resp.Body.Close()
		if !workflowSuccess(w, resp) {
			return
		}
		var internal workflowMutationResponse
		if !decodeWorkflowResponse(resp.Body, &internal) {
			workflowUnavailable(w)
			return
		}
		copyWorkflowETag(w, resp)
		writeGatewayJSON(w, http.StatusOK, publicHierarchyDelete{Revision: internal.Revision})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *GatewayServer) handleApprovalReports(w http.ResponseWriter, r *http.Request, id identity, managerID string) {
	if !approvalHierarchyNoBody(w, r) {
		return
	}
	values, err := neturl.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 4096 {
		http.Error(w, "invalid hierarchy query", http.StatusBadRequest)
		return
	}
	page, pageSize, _, ok := parsePublicHierarchyQuery(w, values, false)
	if !ok {
		return
	}
	if !g.requireApprovalHierarchyAccess(w, r.Context(), id.Roles, "approval-hierarchy:reports:"+managerID, approvalHierarchyReadAction, true) {
		return
	}
	query := workflowActorQuery(id)
	query.Set("page", strconv.Itoa(page))
	query.Set("page_size", strconv.Itoa(pageSize))
	resp, err := g.callWorkflow(r.Context(), http.MethodGet, "/internal/v1/approval-hierarchy/users/"+neturl.PathEscape(managerID)+"/reports?"+query.Encode(), nil)
	if err != nil {
		workflowUnavailable(w)
		return
	}
	defer resp.Body.Close()
	if !workflowSuccess(w, resp) {
		return
	}
	var internal workflowReportsPage
	if !decodeWorkflowResponse(resp.Body, &internal) {
		workflowUnavailable(w)
		return
	}
	copyWorkflowETag(w, resp)
	items := make([]publicHierarchyItem, 0, len(internal.Items))
	for _, item := range internal.Items {
		items = append(items, publicHierarchyItem{UserID: item.UserID, ManagerUserID: managerID, UpdatedAt: item.UpdatedAt})
	}
	writeGatewayJSON(w, http.StatusOK, publicHierarchyPage{Items: items, Page: internal.Page, PageSize: internal.PageSize, TotalItems: internal.TotalItems, Revision: internal.Revision})
}

func (g *GatewayServer) requireApprovalHierarchyAccess(w http.ResponseWriter, ctx context.Context, roles []string, resource, action string, allowAll bool) bool {
	allowed, err := g.checkApprovalHierarchyAccess(ctx, roles, resource, action)
	if err == nil && !allowed && allowAll && resource != approvalHierarchyAllResource {
		allowed, err = g.checkApprovalHierarchyAccess(ctx, roles, approvalHierarchyAllResource, action)
	}
	if err != nil {
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return false
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (g *GatewayServer) checkApprovalHierarchyAccess(ctx context.Context, roles []string, resource, action string) (bool, error) {
	if g.authorizationURL == "" || g.httpClient == nil {
		return false, errors.New("authorization unavailable")
	}
	body, err := json.Marshal(approvalHierarchyAccessRequest{ActorRoles: roles, Resource: resource, Action: action})
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.authorizationURL+"/authz/v1/check-access", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.doWorkflowRequest(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("authorization decision unavailable")
	}
	var decision approvalHierarchyAccessResponse
	if !decodeWorkflowResponse(resp.Body, &decision) {
		return false, errors.New("invalid authorization response")
	}
	return decision.Allowed, nil
}

func (g *GatewayServer) callWorkflow(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if g.workflowServiceURL == "" || g.httpClient == nil {
		return nil, errors.New("workflow service unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.workflowServiceURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return g.doWorkflowRequest(req)
}

func (g *GatewayServer) doWorkflowRequest(req *http.Request) (*http.Response, error) {
	client := g.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	redirectFree := *client
	redirectFree.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return redirectFree.Do(req)
}

func workflowActorQuery(id identity) neturl.Values {
	query := neturl.Values{}
	query.Set("actor_user_id", id.UserID)
	for _, role := range id.Roles {
		query.Add("actor_roles", role)
	}
	return query
}

func workflowSuccess(w http.ResponseWriter, resp *http.Response) bool {
	if resp.StatusCode == http.StatusOK {
		return true
	}
	switch resp.StatusCode {
	case http.StatusBadRequest:
		http.Error(w, "invalid hierarchy request", http.StatusBadRequest)
	case http.StatusForbidden:
		http.Error(w, "forbidden", http.StatusForbidden)
	case http.StatusNotFound:
		http.Error(w, "not found", http.StatusNotFound)
	case http.StatusConflict:
		http.Error(w, "hierarchy revision conflict or cycle", http.StatusConflict)
	default:
		workflowUnavailable(w)
	}
	return false
}

func workflowUnavailable(w http.ResponseWriter) {
	http.Error(w, "workflow service unavailable", http.StatusServiceUnavailable)
}

func decodeWorkflowResponse(body io.Reader, target any) bool {
	dec := json.NewDecoder(io.LimitReader(body, maxApprovalHierarchyResponse+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return false
	}
	var extra any
	return errors.Is(dec.Decode(&extra), io.EOF)
}

func decodeApprovalHierarchyBody(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxApprovalHierarchyBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		http.Error(w, "invalid hierarchy request", http.StatusBadRequest)
		return false
	}
	var extra any
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		http.Error(w, "invalid hierarchy request", http.StatusBadRequest)
		return false
	}
	return true
}

func approvalHierarchyNoBody(w http.ResponseWriter, r *http.Request) bool {
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

func parsePublicHierarchyQuery(w http.ResponseWriter, values neturl.Values, allowManager bool) (int, int, string, bool) {
	page, pageSize, manager := 1, 20, ""
	for key, entries := range values {
		if len(entries) != 1 || entries[0] == "" {
			http.Error(w, "invalid hierarchy query", http.StatusBadRequest)
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
		case "pageSize":
			n, err := strconv.Atoi(entries[0])
			if err != nil || n < 1 || n > 100 {
				http.Error(w, "invalid pageSize", http.StatusBadRequest)
				return 0, 0, "", false
			}
			pageSize = n
		case "managerUserId":
			if !allowManager || !validApprovalHierarchyUserID(entries[0]) {
				http.Error(w, "invalid managerUserId", http.StatusBadRequest)
				return 0, 0, "", false
			}
			manager = entries[0]
		default:
			http.Error(w, "invalid hierarchy query", http.StatusBadRequest)
			return 0, 0, "", false
		}
	}
	return page, pageSize, manager, true
}

func parseHierarchyIfMatch(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	raw := r.Header.Get("If-Match")
	if len(raw) < len(`"hierarchy-0"`) || !strings.HasPrefix(raw, `"hierarchy-`) || !strings.HasSuffix(raw, `"`) {
		http.Error(w, "If-Match with the current hierarchy ETag is required", http.StatusBadRequest)
		return 0, false
	}
	number := strings.TrimSuffix(strings.TrimPrefix(raw, `"hierarchy-`), `"`)
	revision, err := strconv.ParseUint(number, 10, 64)
	if err != nil || strconv.FormatUint(revision, 10) != number {
		http.Error(w, "invalid hierarchy If-Match", http.StatusBadRequest)
		return 0, false
	}
	return revision, true
}

func approvalHierarchyPathSegments(escapedPath string) ([]string, bool) {
	if strings.Contains(strings.ToLower(escapedPath), "%2f") || strings.Contains(strings.ToLower(escapedPath), "%5c") {
		return nil, false
	}
	path := strings.TrimPrefix(escapedPath, "/approval-hierarchy/")
	if path == escapedPath || path == "" || strings.Contains(path, "//") {
		return nil, false
	}
	parts := strings.Split(path, "/")
	for i := range parts {
		decoded, err := neturl.PathUnescape(parts[i])
		if err != nil || decoded == "" || strings.ContainsAny(decoded, "/\\\\") {
			return nil, false
		}
		parts[i] = decoded
	}
	return parts, true
}

func validApprovalHierarchyUserID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func copyWorkflowETag(w http.ResponseWriter, resp *http.Response) {
	if etag := resp.Header.Get("ETag"); etag != "" {
		w.Header().Set("ETag", etag)
	}
}

func writeGatewayJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

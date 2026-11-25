package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const workflowResponseLimit = 128 << 10

type WorkflowHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

type workflowContext struct {
	ActorUserID string   `json:"actor_user_id,omitempty"`
	ActorRoles  []string `json:"actor_roles,omitempty"`
}

type workflowCreateRequest struct {
	Context           workflowContext `json:"context"`
	RequestID         string          `json:"request_id"`
	ResourceType      string          `json:"resource_type"`
	ResourceID        string          `json:"resource_id"`
	RequesterUserID   string          `json:"requester_user_id"`
	AccountID         string          `json:"account_id"`
	TicketReference   string          `json:"ticket_reference"`
	DecisionExpiresAt time.Time       `json:"decision_expires_at"`
	IdempotencyKey    string          `json:"idempotency_key"`
}

type workflowDecisionRequest struct {
	Context          workflowContext `json:"context"`
	ExpectedRevision uint64          `json:"expected_revision"`
	Reason           string          `json:"reason"`
}

type workflowCancelRequest struct {
	Context          workflowContext `json:"context"`
	ExpectedRevision uint64          `json:"expected_revision"`
	ReasonCode       string          `json:"reason_code"`
}

type workflowRequestResponse struct {
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
	DecidedAt         *time.Time `json:"decided_at"`
	DecidedBy         string     `json:"decided_by"`
	DecisionReason    string     `json:"decision_reason"`
	Revision          uint64     `json:"revision"`
}

type workflowPageResponse struct {
	Items      []workflowRequestResponse `json:"items"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalItems int                       `json:"total_items"`
	Truncated  bool                      `json:"truncated"`
}

func (c *WorkflowHTTPClient) CreateApprovalRequest(ctx context.Context, input domain.WorkflowApprovalInput) (*domain.WorkflowApprovalRequest, error) {
	body, err := json.Marshal(workflowCreateRequest{
		Context: workflowContext{}, RequestID: input.RequestID, ResourceType: input.ResourceType,
		ResourceID: input.ResourceID, RequesterUserID: input.RequesterUserID, AccountID: input.AccountID,
		TicketReference: input.TicketReference, DecisionExpiresAt: input.DecisionExpiresAt, IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/internal/v1/approval-requests", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := workflowStatusError(resp); err != nil {
		return nil, err
	}
	var out workflowRequestResponse
	if err := decodeWorkflowBody(resp.Body, &out); err != nil {
		return nil, err
	}
	return mapWorkflowRequest(out)
}

func (c *WorkflowHTTPClient) GetApprovalRequest(ctx context.Context, requestID string) (*domain.WorkflowApprovalRequest, error) {
	resp, err := c.do(ctx, http.MethodGet, "/internal/v1/approval-requests/"+url.PathEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := workflowStatusError(resp); err != nil {
		return nil, err
	}
	var out workflowRequestResponse
	if err := decodeWorkflowBody(resp.Body, &out); err != nil {
		return nil, err
	}
	return mapWorkflowRequest(out)
}

func (c *WorkflowHTTPClient) ListPendingApprovals(ctx context.Context, actorID string, roles []string, page, pageSize int) (domain.WorkflowApprovalPage, error) {
	query := url.Values{}
	query.Set("actor_user_id", actorID)
	for _, role := range roles {
		query.Add("actor_roles", role)
	}
	query.Set("page", strconv.Itoa(page))
	query.Set("page_size", strconv.Itoa(pageSize))
	resp, err := c.do(ctx, http.MethodGet, "/internal/v1/approval-requests?"+query.Encode(), nil)
	if err != nil {
		return domain.WorkflowApprovalPage{}, err
	}
	defer resp.Body.Close()
	if err := workflowStatusError(resp); err != nil {
		return domain.WorkflowApprovalPage{}, err
	}
	var out workflowPageResponse
	if err := decodeWorkflowBody(resp.Body, &out); err != nil {
		return domain.WorkflowApprovalPage{}, err
	}
	items := make([]domain.WorkflowApprovalRequest, 0, len(out.Items))
	for _, item := range out.Items {
		mapped, err := mapWorkflowRequest(item)
		if err != nil {
			return domain.WorkflowApprovalPage{}, err
		}
		items = append(items, *mapped)
	}
	return domain.WorkflowApprovalPage{Items: items, Page: out.Page, PageSize: out.PageSize, TotalItems: out.TotalItems, Truncated: out.Truncated}, nil
}

func (c *WorkflowHTTPClient) DecideApprovalRequest(ctx context.Context, requestID, actorID string, roles []string, expected uint64, decision domain.WorkflowApprovalStatus, reason string) (*domain.WorkflowApprovalRequest, error) {
	endpoint := ""
	switch decision {
	case domain.WorkflowApprovalApproved:
		endpoint = "approve"
	case domain.WorkflowApprovalRejected:
		endpoint = "reject"
	default:
		return nil, domain.ErrConflict
	}
	body, err := json.Marshal(workflowDecisionRequest{Context: workflowContext{ActorUserID: actorID, ActorRoles: roles}, ExpectedRevision: expected, Reason: reason})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/internal/v1/approval-requests/"+url.PathEscape(requestID)+"/"+endpoint, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := workflowStatusError(resp); err != nil {
		return nil, err
	}
	var out workflowRequestResponse
	if err := decodeWorkflowBody(resp.Body, &out); err != nil {
		return nil, err
	}
	return mapWorkflowRequest(out)
}

func (c *WorkflowHTTPClient) CancelApprovalRequest(ctx context.Context, requestID string, expected uint64, reasonCode string) (*domain.WorkflowApprovalRequest, error) {
	body, err := json.Marshal(workflowCancelRequest{Context: workflowContext{}, ExpectedRevision: expected, ReasonCode: reasonCode})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/internal/v1/approval-requests/"+url.PathEscape(requestID)+"/cancel", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := workflowStatusError(resp); err != nil {
		return nil, err
	}
	var out workflowRequestResponse
	if err := decodeWorkflowBody(resp.Body, &out); err != nil {
		return nil, err
	}
	return mapWorkflowRequest(out)
}

func (c *WorkflowHTTPClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return nil, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	bounded := *client
	bounded.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if bounded.Timeout == 0 {
		bounded.Timeout = 5 * time.Second
	}
	return bounded.Do(req)
}

func workflowStatusError(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusForbidden:
		return domain.ErrWorkflowPermanent
	case http.StatusNotFound:
		return domain.ErrNotFound
	case http.StatusConflict:
		return domain.ErrConflict
	default:
		return fmt.Errorf("%w: Workflow Service returned HTTP %d", domain.ErrUnavailable, resp.StatusCode)
	}
}

func decodeWorkflowBody(body io.Reader, target any) error {
	dec := json.NewDecoder(io.LimitReader(body, workflowResponseLimit+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid Workflow Service response", domain.ErrUnavailable)
	}
	var extra any
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return fmt.Errorf("%w: trailing Workflow Service response data", domain.ErrUnavailable)
	}
	return nil
}

func mapWorkflowRequest(in workflowRequestResponse) (*domain.WorkflowApprovalRequest, error) {
	status := domain.WorkflowApprovalStatus(in.Status)
	switch status {
	case domain.WorkflowApprovalPending, domain.WorkflowApprovalApproved, domain.WorkflowApprovalRejected, domain.WorkflowApprovalExpired, domain.WorkflowApprovalCancelled:
	default:
		return nil, fmt.Errorf("%w: unknown Workflow approval status", domain.ErrUnavailable)
	}
	return &domain.WorkflowApprovalRequest{
		RequestID: in.RequestID, ResourceType: in.ResourceType, ResourceID: in.ResourceID,
		RequesterUserID: in.RequesterUserID, AccountID: in.AccountID, TicketReference: in.TicketReference,
		ApproverUserID: in.ApproverUserID, HierarchyRevision: in.HierarchyRevision, Status: status,
		DecisionExpiresAt: in.DecisionExpiresAt, CreatedAt: in.CreatedAt, DecidedAt: in.DecidedAt,
		DecidedBy: in.DecidedBy, DecisionReason: in.DecisionReason, Revision: in.Revision,
	}, nil
}

var _ application.WorkflowApprovalClient = (*WorkflowHTTPClient)(nil)

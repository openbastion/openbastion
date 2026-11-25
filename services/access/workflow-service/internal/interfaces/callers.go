package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodGet, Path: "/internal/v1/approval-hierarchy", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodGet, Path: "/internal/v1/approval-hierarchy/users/{user_id}/manager", Template: true, Callers: []string{mtls.APIGateway}},
		{Method: http.MethodGet, Path: "/internal/v1/approval-hierarchy/users/{manager_user_id}/reports", Template: true, Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPut, Path: "/internal/v1/approval-hierarchy/users/{user_id}/manager", Template: true, Callers: []string{mtls.APIGateway}},
		{Method: http.MethodDelete, Path: "/internal/v1/approval-hierarchy/users/{user_id}/manager", Template: true, Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/internal/v1/approval-requests", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/internal/v1/approval-requests", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/internal/v1/approval-requests/{request_id}", Template: true, Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/internal/v1/approval-requests/{request_id}/approve", Template: true, Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/internal/v1/approval-requests/{request_id}/reject", Template: true, Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/internal/v1/approval-requests/{request_id}/cancel", Template: true, Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/metrics", Callers: []string{mtls.Any}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

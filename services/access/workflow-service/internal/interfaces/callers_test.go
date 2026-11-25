package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("api-gateway", "GET", "/internal/v1/approval-hierarchy"),
		mtlstest.Allow("api-gateway", "GET", "/internal/v1/approval-hierarchy/users/user_123/manager"),
		mtlstest.Allow("api-gateway", "GET", "/internal/v1/approval-hierarchy/users/user_456/reports"),
		mtlstest.Allow("api-gateway", "PUT", "/internal/v1/approval-hierarchy/users/user_123/manager"),
		mtlstest.Allow("api-gateway", "DELETE", "/internal/v1/approval-hierarchy/users/user_123/manager"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/approval-requests"),
		mtlstest.Allow("session-broker", "GET", "/internal/v1/approval-requests"),
		mtlstest.Allow("session-broker", "GET", "/internal/v1/approval-requests/session_123"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/approval-requests/session_123/approve"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/approval-requests/session_123/reject"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/approval-requests/session_123/cancel"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/approval-requests"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/approval-requests/session_123/approve"),
		mtlstest.Deny("session-broker", "PUT", "/internal/v1/approval-hierarchy/users/user_123/manager"),
		mtlstest.Deny("admin-cli", "GET", "/internal/v1/approval-hierarchy"),
		mtlstest.Deny("workflow-service", "GET", "/internal/v1/approval-hierarchy/users/user_123/manager"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/approval-hierarchy/users/user_123/manager"),
		mtlstest.Deny("api-gateway", "GET", "/internal/v1/approval-hierarchy/users/user_123/secrets"),
		mtlstest.Allow("api-gateway", "GET", "/healthz"),
		mtlstest.Allow("admin-cli", "GET", "/metrics"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "GET", Path: "/internal/v1/approval-hierarchy"},
		{Method: "GET", Path: "/internal/v1/approval-hierarchy/users/user_123/manager"},
		{Method: "GET", Path: "/internal/v1/approval-hierarchy/users/user_456/reports"},
		{Method: "PUT", Path: "/internal/v1/approval-hierarchy/users/user_123/manager"},
		{Method: "DELETE", Path: "/internal/v1/approval-hierarchy/users/user_123/manager"},
		{Method: "POST", Path: "/internal/v1/approval-requests"},
		{Method: "GET", Path: "/internal/v1/approval-requests"},
		{Method: "GET", Path: "/internal/v1/approval-requests/session_123"},
		{Method: "POST", Path: "/internal/v1/approval-requests/session_123/approve"},
		{Method: "POST", Path: "/internal/v1/approval-requests/session_123/reject"},
		{Method: "POST", Path: "/internal/v1/approval-requests/session_123/cancel"},
		{Method: "GET", Path: "/metrics"},
		{Method: "GET", Path: "/healthz"},
	})
}

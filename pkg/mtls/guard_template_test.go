package mtls

import (
	"net/http"
	"testing"
)

func TestPathTemplateMatchesOnlyOneNonEmptySegment(t *testing.T) {
	rule := Rule{Method: "GET", Path: "/users/{user_id}/authorization-context", Template: true, Callers: []string{"workflow-service"}}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/users/user_1/authorization-context", true},
		{"/users/a-b/authorization-context", true},
		{"/users//authorization-context", false},
		{"/users/a/b/authorization-context", false},
		{"/users/user_1/secrets", false},
		{"/users/user_1/authorization-context/extra", false},
	} {
		if got := rule.matches("GET", tc.path); got != tc.want {
			t.Errorf("matches(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestGuardRejectsMalformedPathTemplates(t *testing.T) {
	for _, pattern := range []string{
		"/users/{}/manager",
		"/users/{user-id}/manager",
		"/users/user_{id}/manager",
		"/users/{user_id/manager",
		"/users/{user_id}//manager",
		"/users/{user_id}/../manager",
		"/users/{user_id}/manager?raw=1",
	} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("Guard accepted malformed template %q", pattern)
				}
			}()
			_ = Guard(DefaultTrustDomain, []Rule{{Method: "GET", Path: pattern, Template: true, Callers: []string{"workflow-service"}}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		})
	}
}

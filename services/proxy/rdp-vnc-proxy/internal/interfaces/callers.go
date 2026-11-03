package interfaces

import (
	"github.com/openbastion/openbastion/pkg/mtls"
	"net/http"
)

func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodPost, Path: "/internal/v1/establish-session", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/internal/v1/revoke-session", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/internal/v1/screen", Callers: []string{mtls.APIGateway}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

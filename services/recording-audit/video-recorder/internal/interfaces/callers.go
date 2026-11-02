package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

func HTTPCallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodGet, Path: "/readyz", Callers: []string{mtls.Any}},
		{Method: http.MethodGet, Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

type GRPCRule struct {
	Method  string
	Callers []string
}

func GRPCCallerRules() []GRPCRule {
	return []GRPCRule{
		{Method: "/openbastion.recording.v1.VideoRecording/StreamVideoSegments", Callers: []string{mtls.RDPVNCProxy}},
		{Method: "/openbastion.recording.v1.VideoRecording/GetVideoSegment", Callers: []string{mtls.APIGateway}},
		{Method: "/openbastion.recording.v1.VideoRecording/CheckReadiness", Callers: []string{mtls.RDPVNCProxy}},
	}
}

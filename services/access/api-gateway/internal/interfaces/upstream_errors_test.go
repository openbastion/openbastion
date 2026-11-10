package interfaces

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectUpstreamErrorDoesNotRelayBody(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantStatus int
		wantBody   string
	}{
		{name: "bad request", status: http.StatusBadRequest, wantStatus: http.StatusBadRequest, wantBody: "invalid request"},
		{name: "unauthorized", status: http.StatusUnauthorized, wantStatus: http.StatusUnauthorized, wantBody: "authentication failed"},
		{name: "forbidden", status: http.StatusForbidden, wantStatus: http.StatusForbidden, wantBody: "access denied"},
		{name: "not found", status: http.StatusNotFound, wantStatus: http.StatusNotFound, wantBody: "not found"},
		{name: "conflict", status: http.StatusConflict, wantStatus: http.StatusConflict, wantBody: "request conflict"},
		{name: "rate limited", status: http.StatusTooManyRequests, wantStatus: http.StatusTooManyRequests, wantBody: "too many requests"},
		{name: "internal error", status: http.StatusInternalServerError, wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
		{name: "bad gateway", status: http.StatusBadGateway, wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
		{name: "redirect", status: http.StatusFound, wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			upstream := &http.Response{StatusCode: tt.status, Body: io.NopCloser(strings.NewReader("dial tcp 10.0.0.7:8080: internal-service-token"))}
			if !rejectUpstreamError(recorder, upstream) {
				t.Fatal("expected upstream error to be rejected")
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if strings.Contains(recorder.Body.String(), "internal-service-token") || strings.Contains(recorder.Body.String(), "10.0.0.7") {
				t.Fatalf("upstream details leaked: %q", recorder.Body.String())
			}
			if body := strings.TrimSpace(recorder.Body.String()); body != tt.wantBody {
				t.Fatalf("body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestRejectUpstreamErrorAllowsSuccess(t *testing.T) {
	recorder := httptest.NewRecorder()
	if rejectUpstreamError(recorder, &http.Response{StatusCode: http.StatusOK}) {
		t.Fatal("successful upstream response was rejected")
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("unexpected response: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

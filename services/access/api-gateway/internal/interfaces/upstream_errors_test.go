package interfaces

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectUpstreamErrorPreservesRefusalReasonButSanitizesFailures(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		wantStatus int
		wantBody   string
		wantRetry  string
	}{
		{name: "bad request", status: http.StatusBadRequest, body: "invalid protocol", wantStatus: http.StatusBadRequest, wantBody: "invalid protocol"},
		{name: "unauthorized", status: http.StatusUnauthorized, body: "invalid credentials", wantStatus: http.StatusUnauthorized, wantBody: "invalid credentials"},
		{name: "forbidden", status: http.StatusForbidden, body: "forbidden: this session is not yours to read", wantStatus: http.StatusForbidden, wantBody: "forbidden: this session is not yours to read"},
		{name: "not found", status: http.StatusNotFound, body: "session not found", wantStatus: http.StatusNotFound, wantBody: "session not found"},
		{name: "conflict", status: http.StatusConflict, body: "account is not pinned", wantStatus: http.StatusConflict, wantBody: "account is not pinned"},
		{name: "rate limited", status: http.StatusTooManyRequests, body: "quota exceeded", wantStatus: http.StatusTooManyRequests, wantBody: "quota exceeded"},
		{name: "rate limited with retry metadata", status: http.StatusTooManyRequests, body: "try later", retryAfter: "30", wantStatus: http.StatusTooManyRequests, wantBody: "try later", wantRetry: "30"},
		{name: "internal error", status: http.StatusInternalServerError, body: "boom", wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
		{name: "service unavailable", status: http.StatusServiceUnavailable, body: "database password=secret", wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
		{name: "bad gateway", status: http.StatusBadGateway, body: "dial tcp 10.0.0.7:8080", wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
		{name: "redirect", status: http.StatusFound, body: "internal redirect", wantStatus: http.StatusServiceUnavailable, wantBody: "upstream unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			header := make(http.Header)
			header.Set("Content-Type", "text/plain")
			if tt.retryAfter != "" {
				header.Set("Retry-After", tt.retryAfter)
			}
			upstream := &http.Response{
				StatusCode: tt.status,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(tt.body)),
			}
			if !rejectUpstreamError(recorder, upstream) {
				t.Fatal("expected upstream error to be handled")
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if body := strings.TrimSpace(recorder.Body.String()); body != tt.wantBody {
				t.Fatalf("body = %q, want %q", body, tt.wantBody)
			}
			if got := recorder.Header().Get("Retry-After"); got != tt.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", got, tt.wantRetry)
			}
			if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
				t.Fatalf("Content-Type = %q, want text/plain", got)
			}
			if tt.status >= http.StatusInternalServerError && (strings.Contains(recorder.Body.String(), "secret") || strings.Contains(recorder.Body.String(), "10.0.0.7")) {
				t.Fatalf("upstream details leaked: %q", recorder.Body.String())
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

package interfaces

import (
	"log"
	"net/http"
)

// rejectUpstreamError prevents an upstream error body from crossing the public
// Gateway boundary (ADR-0043). Refusals retain their HTTP status but expose only
// a stable generic reason; upstream failures are normalized to 503. Never log
// the upstream body: it may contain credentials, internal URLs, or host details.
func rejectUpstreamError(w http.ResponseWriter, resp *http.Response) bool {
	if resp == nil || (resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return false
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		log.Printf("api-gateway: upstream returned failure status %d", resp.StatusCode)
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		return true
	}

	message := "request rejected"
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		message = "invalid request"
	case http.StatusUnauthorized:
		message = "authentication failed"
	case http.StatusForbidden:
		message = "access denied"
	case http.StatusNotFound:
		message = "not found"
	case http.StatusConflict:
		message = "request conflict"
	case http.StatusTooManyRequests:
		message = "too many requests"
	}
	http.Error(w, message, resp.StatusCode)
	return true
}

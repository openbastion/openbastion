package interfaces

import (
	"io"
	"log"
	"net/http"
)

// rejectUpstreamError keeps the Gateway's public error contract (ADR-0043):
// explicit 4xx refusals retain their service-defined reason and retry metadata;
// upstream 5xx responses never cross the boundary and become a generic 503.
// Transport failures are handled by the caller as 502. Only the small set of
// public response headers is copied; hop-by-hop and internal headers are not.
func rejectUpstreamError(w http.ResponseWriter, resp *http.Response) bool {
	if resp == nil || (resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return false
	}

	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode < http.StatusBadRequest {
		log.Printf("api-gateway: upstream returned failure status %d", resp.StatusCode)
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		return true
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" && resp.StatusCode == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
	}
	return true
}

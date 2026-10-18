package infrastructure_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func establish(t *testing.T, status int, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"proxy_endpoint":"127.0.0.1:2222","connection_ticket":"ticket_x"}`))
			return
		}
		http.Error(w, body, status)
	}))
	defer srv.Close()
	_, _, err := (&infrastructure.ProxyClientHTTPClient{BaseURL: srv.URL}).EstablishSession(context.Background(), "s", "h", "u", "scope", time.Minute)
	return err
}

// The proxy's recording policy refusing a session (ADR-0008) is reported as such;
// every other failure — including a 503 from something else — is not.
func TestProxyClient_RecognisesARecordingRefusal(t *testing.T) {
	if err := establish(t, http.StatusOK, ""); err != nil {
		t.Fatalf("a successful establish returned %v", err)
	}
	if err := establish(t, http.StatusServiceUnavailable, "recording unavailable: the session was not started"); !errors.Is(err, domain.ErrRecordingUnavailable) {
		t.Fatalf("the proxy's recording refusal was not recognised: %v", err)
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"a bare 503 (a load balancer with no backend)": {http.StatusServiceUnavailable, "no healthy upstream"},
		"a 500 that mentions recording":                {http.StatusInternalServerError, "recording unavailable"},
		"a 403":                                        {http.StatusForbidden, "denied"},
	} {
		if err := establish(t, c.status, c.body); err == nil || errors.Is(err, domain.ErrRecordingUnavailable) {
			t.Errorf("%s: got %v, want a plain failure", name, err)
		}
	}
}

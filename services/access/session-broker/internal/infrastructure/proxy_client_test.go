package infrastructure_test

import (
	"context"
	"encoding/json"
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
	_, _, err := (&infrastructure.ProxyClientHTTPClient{BaseURL: srv.URL}).EstablishSession(context.Background(), "s", "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{})
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

// The Broker's authorisation reaches the proxy as `break_glass`, in the request
// body — absent or false means no waiver, so a proxy never has to guess.
func TestProxyClient_SendsTheBreakGlassAuthorisation(t *testing.T) {
	for _, want := range []bool{true, false} {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`{"proxy_endpoint":"127.0.0.1:2222","connection_ticket":"ticket_x"}`))
		}))
		_, _, err := (&infrastructure.ProxyClientHTTPClient{BaseURL: srv.URL}).EstablishSession(context.Background(), "s", "ssh", "h", "u", "scope", time.Minute, want, domain.ClipboardRights{})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := got["break_glass"].(bool); !ok || v != want {
			t.Fatalf("break_glass = %v (%v), want %v; body %v", got["break_glass"], ok, want, got)
		}
		if got["protocol"] != "ssh" {
			t.Fatalf("protocol=%v, want ssh", got["protocol"])
		}
	}
}

// Each clipboard direction the Broker granted reaches the proxy on its own
// field (ADR-0096 §4): a proxy that read one for the other would open the
// wrong direction.
func TestProxyClient_SendsEachClipboardDirection(t *testing.T) {
	for _, want := range []domain.ClipboardRights{{}, {ToTarget: true}, {FromTarget: true}, {ToTarget: true, FromTarget: true}} {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`{"proxy_endpoint":"127.0.0.1:3389","connection_ticket":"ticket_x"}`))
		}))
		_, _, err := (&infrastructure.ProxyClientHTTPClient{BaseURL: srv.URL}).EstablishSession(context.Background(), "s", "rdp", "h", "u", "scope", time.Minute, false, want)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		to, okTo := got["clipboard_to_target"].(bool)
		from, okFrom := got["clipboard_from_target"].(bool)
		if !okTo || !okFrom || to != want.ToTarget || from != want.FromTarget {
			t.Fatalf("rights %+v reached the proxy as to=%v(%v) from=%v(%v)", want, got["clipboard_to_target"], okTo, got["clipboard_from_target"], okFrom)
		}
	}
}

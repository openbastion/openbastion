package infrastructure_test

// The Broker's call to the proxy's revoke-session (ADR-0018): what it sends, and that only a
// 200 is a revocation — anything else, including a proxy that does not know the route, means
// the session may still be open and the Broker must not say it was ended.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

type seenRevoke struct {
	method, path, contentType string
	body                      map[string]any
}

// revokeServer answers every call with `status` and remembers the last one it saw.
func revokeServer(t *testing.T, status int) (*infrastructure.ProxyClientHTTPClient, func() seenRevoke) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen seenRevoke
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = seenRevoke{method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type")}
		_ = json.Unmarshal(raw, &seen.body)
		mu.Unlock()
		if status != http.StatusOK {
			http.Error(w, "dial tcp 10.9.8.7:8082: refused", status)
			return
		}
		_, _ = w.Write([]byte(`{"tickets_revoked":1,"connections_cut":2}`))
	}))
	t.Cleanup(srv.Close)
	return &infrastructure.ProxyClientHTTPClient{BaseURL: srv.URL}, func() seenRevoke {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

func TestProxyClient_RevokeSessionSendsTheSessionAndTheTimeToRemember(t *testing.T) {
	client, seen := revokeServer(t, http.StatusOK)
	if err := client.RevokeSession(context.Background(), "session_abc", 90*time.Second+500*time.Millisecond); err != nil {
		t.Fatalf("a 200 returned %v", err)
	}
	got := seen()
	if got.method != http.MethodPost || got.path != "/internal/v1/revoke-session" || got.contentType != "application/json" {
		t.Fatalf("sent %+v", got)
	}
	if got.body["session_id"] != "session_abc" {
		t.Fatalf("session_id = %v", got.body["session_id"])
	}
	if secs, _ := got.body["ttl_seconds"].(float64); secs != 91 {
		t.Fatalf("ttl_seconds = %v, want 91 for 90.5s asked (rounded up, never less than asked)", got.body["ttl_seconds"])
	}
}

func TestProxyClient_RevokeSessionNeverAsksForANonPositiveMemory(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Minute, 200 * time.Millisecond} {
		client, seen := revokeServer(t, http.StatusOK)
		if err := client.RevokeSession(context.Background(), "s", d); err != nil {
			t.Fatalf("%v: %v", d, err)
		}
		if secs, _ := seen().body["ttl_seconds"].(float64); secs < 1 {
			t.Fatalf("a remaining time of %v was sent as %v seconds: the proxy refuses anything below 1", d, secs)
		}
	}
}

func TestProxyClient_OnlyA200IsARevocation(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest, http.StatusNotFound /* a proxy that does not know the route */, http.StatusConflict,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable /* connections still closing */, http.StatusNoContent,
	} {
		client, _ := revokeServer(t, status)
		err := client.RevokeSession(context.Background(), "s", time.Minute)
		if err == nil {
			t.Fatalf("status %d was taken for a revocation", status)
		}
	}
}

func TestProxyClient_RevokeSessionToAProxyThatIsNotThere_IsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	if err := (&infrastructure.ProxyClientHTTPClient{BaseURL: url}).RevokeSession(context.Background(), "s", time.Minute); err == nil {
		t.Fatal("a proxy that cannot be reached was taken for a revocation")
	}
}

func TestProxyClient_RevokeSessionHonoursItsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(func() { close(release); srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := (&infrastructure.ProxyClientHTTPClient{BaseURL: srv.URL}).RevokeSession(ctx, "s", time.Minute); err == nil {
		t.Fatal("a proxy that never answers was taken for a revocation")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the call took %v for a context of 100ms", time.Since(start))
	}
}

// The proxy's own message names an address; the error the Broker builds from it must not carry
// the body (it ends up in a log line, and the response to the client never has it).
func TestProxyClient_RevokeSessionErrorDoesNotCarryTheProxysBody(t *testing.T) {
	client, _ := revokeServer(t, http.StatusServiceUnavailable)
	err := client.RevokeSession(context.Background(), "s", time.Minute)
	if err == nil {
		t.Fatal("want an error")
	}
	if got := err.Error(); got != "revoke-session: status 503" {
		t.Fatalf("error = %q, want only the status: the body of a proxy is not the Broker's to repeat", got)
	}
}

package transit_test

// ADR-0056: a token replaced on disk is taken once Transit accepts it; otherwise the token in use
// stays. Neither token is ever written.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/transit"
)

const newToken = "s.the-new-token-0123456789"

type acceptingServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	ok   map[string]bool
	seen []string
}

func newAccepting(t *testing.T, tokens ...string) *acceptingServer {
	t.Helper()
	a := &acceptingServer{ok: map[string]bool{}}
	for _, tk := range tokens {
		a.ok[tk] = true
	}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk := r.Header.Get("X-Vault-Token")
		a.mu.Lock()
		a.seen = append(a.seen, tk)
		ok := a.ok[tk]
		a.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied for " + tk}})
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/lookup-self"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "renewable": true}})
		case strings.Contains(r.URL.Path, "/encrypt/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:xx"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *acceptingServer) last() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seen[len(a.seen)-1]
}

func rewrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestReloadToken_ANewTokenAcceptedByTransitIsTaken_ElseTheOldStays(t *testing.T) {
	srv := newAccepting(t, token, newToken)
	file := tokenFile(t, token+"\n", 0o600)
	c, err := transit.New(transit.Config{Addr: srv.srv.URL, Key: "k1", TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if changed, err := c.ReloadToken(ctx); changed || err != nil {
		t.Fatalf("the same file: %v, %v; want nothing", changed, err)
	}

	for name, f := range map[string]func(){
		"a token Transit refuses": func() { rewrite(t, file, "s.refused-token\n", 0o600) },
		"a file others can read":  func() { rewrite(t, file, newToken+"\n", 0o644) },
		"an empty file":           func() { rewrite(t, file, "\n", 0o600) },
		"two tokens on one line":  func() { rewrite(t, file, newToken+" "+token+"\n", 0o600) },
	} {
		f()
		changed, err := c.ReloadToken(ctx)
		if changed || err == nil {
			t.Fatalf("%s: changed=%v err=%v; want the old token kept, and why", name, changed, err)
		}
		if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), newToken) || strings.Contains(err.Error(), "s.refused-token") {
			t.Fatalf("%s: the error holds a token: %v", name, err)
		}
		if _, err := c.Encrypt(ctx, []byte("x"), []byte("a")); err != nil || srv.last() != token {
			t.Fatalf("%s: the old token is no longer the one used (%v, %q)", name, err, srv.last())
		}
	}

	rewrite(t, file, newToken+"\n", 0o600)
	if changed, err := c.ReloadToken(ctx); !changed || err != nil {
		t.Fatalf("a new token Transit accepts: %v, %v; want it taken", changed, err)
	}
	if _, err := c.Encrypt(ctx, []byte("x"), []byte("a")); err != nil || srv.last() != newToken {
		t.Fatalf("after the change: %v, the server saw %q; want the new token", err, srv.last())
	}
}

func TestWatchTokenFile_TakesTheChange_AndSaysAFailureOnce(t *testing.T) {
	srv := newAccepting(t, token, newToken)
	file := tokenFile(t, token+"\n", 0o600)
	c, _ := transit.New(transit.Config{Addr: srv.srv.URL, Key: "k1", TokenFile: file})
	l := &logBook{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.WatchTokenFile(ctx, 20*time.Millisecond, l.logf)

	rewrite(t, file, newToken+"\n", 0o644) // too open: refused, said once however often it is read
	time.Sleep(200 * time.Millisecond)
	if n := strings.Count(l.all(), "cannot be taken"); n != 1 {
		t.Fatalf("the same failure was said %d times:\n%s", n, l.all())
	}
	rewrite(t, file, newToken+"\n", 0o600)
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(l.all(), "the token file changed") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := c.Encrypt(ctx, []byte("x"), []byte("a")); err != nil || srv.last() != newToken {
		t.Fatalf("the watched change was not taken: %v, %q\n%s", err, srv.last(), l.all())
	}
	if strings.Contains(l.all(), token) || strings.Contains(l.all(), newToken) {
		t.Fatalf("a token is in the log:\n%s", l.all())
	}
}

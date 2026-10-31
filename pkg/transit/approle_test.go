package transit_test

// ADR-0058: the service logs in by AppRole, renews the token it gets, logs in again once that token
// has reached its maximum life, and never writes the role_id, the secret_id or a token.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/transit"
)

const (
	roleID   = "role-0f1e2d3c-4b5a"
	secretID = "secret-9a8b7c6d-5e4f-3a2b"
)

// appRoleServer is OpenBao as far as AppRole goes: a login against the right pair gives a token
// that lives ttl and may be renewed up to max after its login; encrypt answers a live token only.
type appRoleServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	ttl, max time.Duration
	secret   string // the secret_id it accepts
	issued   int
	tokens   map[string][2]time.Time // token → {ends, max}
	logins   []time.Time
	renews   int
	lastSeen string // the last token an encrypt call carried
}

func newAppRoleServer(t *testing.T, ttl, max time.Duration) *appRoleServer {
	t.Helper()
	s := &appRoleServer{ttl: ttl, max: max, secret: secretID, tokens: map[string][2]time.Time{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		now := time.Now()
		tk := r.Header.Get("X-Vault-Token")
		life, live := s.tokens[tk]
		live = live && now.Before(life[0])
		secs := func(d time.Duration) int64 { return int64((d + time.Second - 1) / time.Second) }
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if tk != "" || in["role_id"] != roleID || in["secret_id"] != s.secret {
				w.WriteHeader(http.StatusBadRequest) // the answer echoes what it was given, to test that it is scrubbed
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid role_id " + in["role_id"] + " or secret_id " + in["secret_id"]}})
				return
			}
			s.issued++
			tok := fmt.Sprintf("s.approle-token-%d", s.issued)
			s.tokens[tok] = [2]time.Time{now.Add(s.ttl), now.Add(s.max)}
			s.logins = append(s.logins, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": secs(s.ttl), "renewable": true}})
		case "/v1/auth/token/lookup-self":
			if !live {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": secs(life[0].Sub(now)), "renewable": true}})
		case "/v1/auth/token/renew-self":
			if !live {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			s.renews++
			ends := now.Add(s.ttl)
			if ends.After(life[1]) {
				ends = life[1]
			}
			s.tokens[tk] = [2]time.Time{ends, life[1]}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"lease_duration": secs(ends.Sub(now)), "renewable": true}})
		case "/v1/transit/encrypt/k1", "/v1/transit/decrypt/k1":
			if !live {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			s.lastSeen = tk
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if strings.HasSuffix(r.URL.Path, "encrypt/k1") {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:" + in["plaintext"]}})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": strings.TrimPrefix(in["ciphertext"], "vault:v1:")}})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *appRoleServer) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.logins)
}

func secretFile(t *testing.T, name, value string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(value+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFromEnv_AppRoleIsOneWayToLogIn_AndItsHalvesAndBothWaysAreRefused(t *testing.T) {
	role, secret := secretFile(t, "role", roleID, 0o600), secretFile(t, "secret", secretID, 0o600)
	tok := secretFile(t, "token", token, 0o600)
	base := map[string]string{"TRANSIT_ADDR": "http://127.0.0.1:8200", "TRANSIT_KEY": "k1"}
	with := func(extra map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return base[k]
		}
	}
	refused := map[string]struct {
		env  map[string]string
		says string
	}{
		"both ways":                   {map[string]string{"TRANSIT_TOKEN_FILE": tok, "TRANSIT_ROLE_ID_FILE": role, "TRANSIT_SECRET_ID_FILE": secret}, "give one"},
		"the token and a mount":       {map[string]string{"TRANSIT_TOKEN_FILE": tok, "TRANSIT_APPROLE_MOUNT": "approle"}, "give one"},
		"the role without the secret": {map[string]string{"TRANSIT_ROLE_ID_FILE": role}, "missing: TRANSIT_SECRET_ID_FILE"},
		"the secret without the role": {map[string]string{"TRANSIT_SECRET_ID_FILE": secret}, "missing: TRANSIT_ROLE_ID_FILE"},
		"a mount alone":               {map[string]string{"TRANSIT_APPROLE_MOUNT": "approle"}, "missing: TRANSIT_ROLE_ID_FILE, TRANSIT_SECRET_ID_FILE"},
		"no way at all":               {map[string]string{}, "missing: TRANSIT_TOKEN_FILE"},
		"a secret others can read":    {map[string]string{"TRANSIT_ROLE_ID_FILE": role, "TRANSIT_SECRET_ID_FILE": secretFile(t, "open", secretID, 0o644)}, "TRANSIT_SECRET_ID_FILE is readable by its group or by others"},
		"a role others can read":      {map[string]string{"TRANSIT_ROLE_ID_FILE": secretFile(t, "openrole", roleID, 0o640), "TRANSIT_SECRET_ID_FILE": secret}, "TRANSIT_ROLE_ID_FILE is readable by its group or by others"},
		"two values in the secret":    {map[string]string{"TRANSIT_ROLE_ID_FILE": role, "TRANSIT_SECRET_ID_FILE": secretFile(t, "two", secretID+" "+secretID, 0o600)}, "one secret_id on one line"},
		"a secret file missing":       {map[string]string{"TRANSIT_ROLE_ID_FILE": role, "TRANSIT_SECRET_ID_FILE": "/nonexistent/secret"}, "TRANSIT_SECRET_ID_FILE cannot be read"},
		"a mount that is not a path":  {map[string]string{"TRANSIT_ROLE_ID_FILE": role, "TRANSIT_SECRET_ID_FILE": secret, "TRANSIT_APPROLE_MOUNT": "../sys"}, "TRANSIT_APPROLE_MOUNT"},
	}
	for name, c := range refused {
		_, configured, err := transit.FromEnv(with(c.env))
		if !configured || err == nil || !strings.Contains(err.Error(), c.says) {
			t.Fatalf("%s: configured %v, %v; want a refusal saying %q", name, configured, err, c.says)
		}
		if strings.Contains(err.Error(), secretID) || strings.Contains(err.Error(), roleID) || strings.Contains(err.Error(), token) {
			t.Fatalf("%s: the refusal repeats a value: %v", name, err)
		}
	}
	if c, configured, err := transit.FromEnv(with(map[string]string{"TRANSIT_ROLE_ID_FILE": role, "TRANSIT_SECRET_ID_FILE": secret})); err != nil || !configured || c == nil {
		t.Fatalf("AppRole whole: %v, %v", configured, err)
	}
}

func TestAppRole_TheProbeLogsInFirst_AndTheTokenItGetsIsUsed_AndARefusalSaysNoValue(t *testing.T) {
	s := newAppRoleServer(t, time.Hour, time.Hour)
	role, secret := secretFile(t, "role", roleID, 0o600), secretFile(t, "secret", secretID, 0o600)
	c, err := transit.New(transit.Config{Addr: s.srv.URL, Key: "k1", RoleIDFile: role, SecretIDFile: secret})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if s.loginCount() != 1 || s.lastSeen != "s.approle-token-1" {
		t.Fatalf("logins %d, token used %q", s.loginCount(), s.lastSeen)
	}

	// A secret_id the server no longer accepts: the error names neither value, and the token in use stays.
	s.mu.Lock()
	s.secret = "another-secret"
	s.mu.Unlock()
	_, err = c.Login(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 400: invalid role_id [role_id] or secret_id [secret_id]") {
		t.Fatalf("a refused login must say why, the values masked: %v", err)
	}
	if strings.Contains(err.Error(), secretID) || strings.Contains(err.Error(), roleID) {
		t.Fatalf("the error repeats the role_id or the secret_id: %v", err)
	}
	if _, err := c.Encrypt(context.Background(), []byte("x"), []byte("a")); err != nil || s.lastSeen != "s.approle-token-1" {
		t.Fatalf("after a refused login the token in use must stay: %v, %q", err, s.lastSeen)
	}

	// The secret_id replaced on disk is read at the next login.
	if err := os.WriteFile(secret, []byte("another-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background()); err != nil {
		t.Fatalf("a login with the secret_id replaced on disk: %v", err)
	}
	if _, err := c.Encrypt(context.Background(), []byte("x"), []byte("a")); err != nil || s.lastSeen != "s.approle-token-2" {
		t.Fatalf("the new token is not used: %v, %q", err, s.lastSeen)
	}
}

func TestAppRole_ATokenAtItsMaximumIsReplacedByANewLogin_AndTheKeysStayUsable(t *testing.T) {
	// Each token lives 2 s and may not outlive 3 s: without a new login, the keys go after 3 s.
	s := newAppRoleServer(t, 2*time.Second, 3*time.Second)
	role, secret := secretFile(t, "role", roleID, 0o600), secretFile(t, "secret", secretID, 0o600)
	c, err := transit.New(transit.Config{Addr: s.srv.URL, Key: "k1", RoleIDFile: role, SecretIDFile: secret})
	if err != nil {
		t.Fatal(err)
	}
	c.WithRenewFloor(50 * time.Millisecond)
	if err := c.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &logBook{}
	go c.KeepAlive(ctx, l.logf)
	// Calls all along: the new token is logged in before the old one ends, so not one call fails.
	for end := time.Now().Add(7 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if _, err := c.Encrypt(context.Background(), []byte("x"), []byte("a")); err != nil {
			t.Fatalf("a call failed with tokens of at most 3 s: %v\n%s", err, l.all())
		}
	}
	s.mu.Lock()
	logins, renews := len(s.logins), s.renews
	s.mu.Unlock()
	if logins < 3 || renews < 2 {
		t.Fatalf("%d logins and %d renewals in 7 s, want the token renewed, then a new one logged in at its maximum\n%s", logins, renews, l.all())
	}
	out := l.all()
	if !strings.Contains(out, "a new token is logged in") || !strings.Contains(out, "renewed at half its life") {
		t.Fatalf("the log does not say what is done:\n%s", out)
	}
	if strings.Contains(out, secretID) || strings.Contains(out, roleID) || strings.Contains(out, "s.approle-token") {
		t.Fatalf("the log holds a value:\n%s", out)
	}
}

func TestAppRole_ALoginThatFailsIsTriedAgain_AndSaid_AndTheTokenFileIsNotWatched(t *testing.T) {
	s := newAppRoleServer(t, 2*time.Second, 2*time.Second)
	role, secret := secretFile(t, "role", roleID, 0o600), secretFile(t, "secret", secretID, 0o600)
	c, err := transit.New(transit.Config{Addr: s.srv.URL, Key: "k1", RoleIDFile: role, SecretIDFile: secret})
	if err != nil {
		t.Fatal(err)
	}
	c.WithRenewFloor(50 * time.Millisecond)
	if err := c.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.secret = "not-yet" // every login is refused until the secret_id on disk is the one the server takes
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &logBook{}
	go c.KeepAlive(ctx, l.logf)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(l.all(), "no new token") {
		if time.Now().After(deadline) {
			t.Fatalf("a refused login is not said:\n%s", l.all())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(l.all(), secretID) || strings.Contains(l.all(), roleID) {
		t.Fatalf("the log holds a value:\n%s", l.all())
	}
	if err := os.WriteFile(secret, []byte("not-yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(l.all(), "a new token is logged in") {
		if time.Now().After(deadline.Add(5 * time.Second)) {
			t.Fatalf("the login is not tried again:\n%s", l.all())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := c.Encrypt(context.Background(), []byte("x"), []byte("a")); err != nil {
		t.Fatalf("after the new login: %v", err)
	}

	w := &logBook{}
	c.WatchTokenFile(ctx, time.Millisecond, w.logf) // returns at once: there is no token file
	if !strings.Contains(w.all(), "AppRole") {
		t.Fatalf("WatchTokenFile with AppRole: %q", w.all())
	}
	if _, err := c.ReloadToken(ctx); err == nil {
		t.Fatal("ReloadToken with AppRole must say there is no token file")
	}
}

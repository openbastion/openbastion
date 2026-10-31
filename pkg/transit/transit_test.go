package transit_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/pkg/transit"
)

const token = "s.test-token-0123456789"

// fakeTransit encrypts for real (AES-GCM under its own key, aad as GCM additional data), as
// Transit does, and keeps what it was asked.
type fakeTransit struct {
	srv    *httptest.Server
	gcm    cipher.AEAD
	mu     sync.Mutex
	paths  []string
	tokens []string
	status int // when set, every call answers it, with an error that echoes the token
}

func newFake(t *testing.T) *fakeTransit {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	f := &fakeTransit{gcm: gcm}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths, f.tokens = append(f.paths, r.URL.Path), append(f.tokens, r.Header.Get("X-Vault-Token"))
		status := f.status
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied for token " + r.Header.Get("X-Vault-Token")}})
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		aad, _ := base64.StdEncoding.DecodeString(in["associated_data"])
		switch {
		case strings.HasSuffix(r.URL.Path, "/encrypt/k1"):
			p, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			nonce := make([]byte, gcm.NonceSize())
			_, _ = rand.Read(nonce)
			ct := "vault:v1:" + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, p, aad))
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": ct}})
		case strings.HasSuffix(r.URL.Path, "/decrypt/k1"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(in["ciphertext"], "vault:v1:"))
			if len(raw) < gcm.NonceSize() {
				w.WriteHeader(400)
				return
			}
			p, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
			if err != nil {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"cipher: message authentication failed"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(p)}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func tokenFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func client(t *testing.T, addr string) *transit.Client {
	t.Helper()
	c, err := transit.New(transit.Config{Addr: addr, Key: "k1", TokenFile: tokenFile(t, token+"\n", 0o600)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFromEnv_NothingSetIsNotConfigured_SomeSetIsAnError(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, configured, err := transit.FromEnv(env(nil)); c != nil || configured || err != nil {
		t.Fatalf("nothing set: %v %v %v", c, configured, err)
	}
	f := tokenFile(t, token, 0o600)
	for _, m := range []map[string]string{
		{"TRANSIT_ADDR": "https://bao.example:8200"},
		{"TRANSIT_ADDR": "https://bao.example:8200", "TRANSIT_KEY": "k1"},
		{"TRANSIT_KEY": "k1", "TRANSIT_TOKEN_FILE": f},
		{"TRANSIT_MOUNT": "transit"},
	} {
		_, configured, err := transit.FromEnv(env(m))
		if !configured || err == nil || !strings.Contains(err.Error(), "go together") {
			t.Fatalf("%v: configured=%v err=%v, want a refusal", m, configured, err)
		}
	}
	c, configured, err := transit.FromEnv(env(map[string]string{"TRANSIT_ADDR": "https://bao.example:8200", "TRANSIT_KEY": "k1", "TRANSIT_TOKEN_FILE": f}))
	if err != nil || !configured || c.KeyID() != "transit:transit/k1" {
		t.Fatalf("%v %v %v", c, configured, err)
	}
}

func TestNew_RefusesWhatCannotBeTrusted_WithoutRepeatingTheToken(t *testing.T) {
	good := tokenFile(t, token, 0o600)
	for name, cfg := range map[string]transit.Config{
		"http to another host":       {Addr: "http://bao.example:8200", Key: "k1", TokenFile: good},
		"another scheme":             {Addr: "ftp://bao.example", Key: "k1", TokenFile: good},
		"credentials in the URL":     {Addr: "https://u:p@bao.example", Key: "k1", TokenFile: good},
		"a path":                     {Addr: "https://bao.example/v1", Key: "k1", TokenFile: good},
		"a key name with a slash":    {Addr: "https://bao.example", Key: "k/1", TokenFile: good},
		"a mount with ..":            {Addr: "https://bao.example", Mount: "../sys", Key: "k1", TokenFile: good},
		"a token others can read":    {Addr: "https://bao.example", Key: "k1", TokenFile: tokenFile(t, token, 0o644)},
		"a token the group can read": {Addr: "https://bao.example", Key: "k1", TokenFile: tokenFile(t, token, 0o640)},
		"an empty token":             {Addr: "https://bao.example", Key: "k1", TokenFile: tokenFile(t, "\n", 0o600)},
		"two tokens":                 {Addr: "https://bao.example", Key: "k1", TokenFile: tokenFile(t, token+" other", 0o600)},
		"no token file":              {Addr: "https://bao.example", Key: "k1", TokenFile: filepath.Join(t.TempDir(), "none")},
		"an unreadable CA file":      {Addr: "https://bao.example", Key: "k1", TokenFile: good, CAFile: filepath.Join(t.TempDir(), "none")},
		"a CA file without PEM":      {Addr: "https://bao.example", Key: "k1", TokenFile: good, CAFile: tokenFile(t, "not pem", 0o600)},
	} {
		_, err := transit.New(cfg)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("%s: the error holds the token: %v", name, err)
		}
	}
}

func TestEncryptDecrypt_ARoundTrip_BoundToItsAssociatedData(t *testing.T) {
	f := newFake(t)
	c := client(t, f.srv.URL)
	ctx := context.Background()
	ct, err := c.Encrypt(ctx, []byte("a data key"), []byte("session-1"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ct, base64.StdEncoding.EncodeToString([]byte("a data key"))) {
		t.Fatal("the ciphertext carries the plaintext")
	}
	got, err := c.Decrypt(ctx, ct, []byte("session-1"))
	if err != nil || string(got) != "a data key" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	// The attack: a wrapped key moved to another row (another session) does not unwrap.
	if _, err := c.Decrypt(ctx, ct, []byte("session-2")); err == nil {
		t.Fatal("a ciphertext unwrapped under other associated data")
	}
	for _, aad := range [][]byte{nil, {}} {
		if _, err := c.Encrypt(ctx, []byte("x"), aad); err == nil {
			t.Fatal("Encrypt without associated data")
		}
		if _, err := c.Decrypt(ctx, ct, aad); err == nil {
			t.Fatal("Decrypt without associated data")
		}
	}
	if _, err := c.Decrypt(ctx, "not-transit", []byte("session-1")); err == nil {
		t.Fatal("a value that is not a Transit ciphertext was sent to be decrypted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, p := range f.paths {
		if p != "/v1/transit/encrypt/k1" && p != "/v1/transit/decrypt/k1" {
			t.Fatalf("call %d to %s", i, p)
		}
		if f.tokens[i] != token {
			t.Fatalf("call %d carried token %q", i, f.tokens[i])
		}
	}
}

func TestErrors_NeverCarryTheToken_EvenWhenTheServerEchoesIt(t *testing.T) {
	f := newFake(t)
	f.status = http.StatusForbidden
	c := client(t, f.srv.URL)
	_, err := c.Encrypt(context.Background(), []byte("x"), []byte("a"))
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
	if err := c.Probe(context.Background()); err == nil {
		t.Fatal("the probe passed against a server that refuses")
	}
}

func TestProbe_PassesWhenTheKeyWorksBothWays(t *testing.T) {
	if err := client(t, newFake(t).srv.URL).Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestARedirectIsNotFollowed_TheTokenGoesNowhereElse(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Vault-Token") != "" }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if _, err := client(t, srv.URL).Encrypt(context.Background(), []byte("x"), []byte("a")); err == nil {
		t.Fatal("a redirect was taken as an answer")
	}
	if leaked {
		t.Fatal("the token followed the redirect")
	}
}

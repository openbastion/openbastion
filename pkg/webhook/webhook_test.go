package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/webhook"
)

const secret = "0123456789abcdef0123456789abcdef"

func TestNew_AcceptsOnlyAURLItCanTrust_AndNeverRepeatsIt(t *testing.T) {
	for _, ok := range []string{"https://hooks.example/T/B/x", "http://127.0.0.1:9/x", "http://localhost:9/x", "http://[::1]:9/x"} {
		if _, err := webhook.New(ok); err != nil {
			t.Fatalf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://hooks.example/s3cr3t", "ftp://hooks.example/s3cr3t", "https://user:s3cr3t@hooks.example/",
		"https:///s3cr3t", "://s3cr3t", "hooks.example/s3cr3t", "http://10.0.0.1/s3cr3t"} {
		_, err := webhook.New(bad)
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Fatalf("%q: the error repeats the URL: %v", bad, err)
		}
	}
}

func TestEndpoint_WhereIsSchemeAndHostOnly(t *testing.T) {
	e, _ := webhook.New("https://hooks.example:8443/services/T/B/s3cr3t?token=x")
	if e.Where() != "https://hooks.example:8443" {
		t.Fatalf("Where() = %q", e.Where())
	}
}

func TestEndpoint_AShortSecretIsRefused_WithoutBeingRepeated(t *testing.T) {
	e, _ := webhook.New("https://hooks.example/x")
	short := strings.Repeat("k", webhook.MinSecretBytes-1)
	if _, err := e.WithSecret(short); err == nil || strings.Contains(err.Error(), short) {
		t.Fatalf("err = %v", err)
	}
	if e.Signed() {
		t.Fatal("a refused secret signs")
	}
	if _, err := e.WithSecret(secret); err != nil || !e.Signed() {
		t.Fatalf("a %d-byte secret: %v", len(secret), err)
	}
}

func TestPost_SignsTheExactBody_StampedWhenSent(t *testing.T) {
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, body = r.Header.Clone(), mustRead(r)
		w.WriteHeader(202)
	}))
	defer srv.Close()
	e, _ := webhook.New(srv.URL)
	_, _ = e.WithSecret(secret)
	e.WithClock(func() time.Time { return time.Unix(1700000000, 0) })
	status, err := e.Post(context.Background(), "ua-test", []byte(`{"a":1}`))
	if err != nil || status != 202 {
		t.Fatalf("status %d, err %v", status, err)
	}
	if got.Get(webhook.TimestampHeader) != "1700000000" || got.Get("User-Agent") != "ua-test" || got.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", got)
	}
	// The reference value, computed here with crypto/hmac rather than by the code under test.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(`1700000000.{"a":1}`))
	want := "v1=" + hex.EncodeToString(mac.Sum(nil))
	if sig := got.Get(webhook.SignatureHeader); sig != want || string(body) != `{"a":1}` {
		t.Fatalf("signature %q over %q, want %q", sig, body, want)
	}
	if webhook.Signature([]byte(secret), "1700000000", body) != want {
		t.Fatal("Signature does not compute what a receiver computes")
	}
}

func TestPost_WithoutASecretNothingIsSigned(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	e, _ := webhook.New(srv.URL)
	if _, err := e.Post(context.Background(), "ua", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if got.Get(webhook.SignatureHeader) != "" || got.Get(webhook.TimestampHeader) != "" {
		t.Fatalf("an unsigned endpoint signed: %v", got)
	}
}

func TestPost_ARedirectIsAnAnswer_NotFollowed(t *testing.T) {
	followed := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	e, _ := webhook.New(srv.URL)
	status, err := e.Post(context.Background(), "ua", []byte("{}"))
	if err != nil || status != http.StatusTemporaryRedirect || followed {
		t.Fatalf("status %d, err %v, followed %v", status, err, followed)
	}
}

func TestPost_ATransportErrorDoesNotCarryTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/services/T/B/s3cr3t-path"
	srv.Close()
	e, _ := webhook.New(url)
	_, err := e.Post(context.Background(), "ua", []byte("{}"))
	if err == nil || strings.Contains(err.Error(), "s3cr3t-path") {
		t.Fatalf("err = %v", err)
	}
}

func TestPost_ASilentEndpointIsCutAtTheTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	e, _ := webhook.New(srv.URL)
	e.WithTimeout(50 * time.Millisecond)
	start := time.Now()
	if _, err := e.Post(context.Background(), "ua", []byte("{}")); err == nil {
		t.Fatal("a silent endpoint answered")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Post waited %s", d)
	}
}

func TestSafeText_KeepsAnIdentifier_AndDisarmsTheRest(t *testing.T) {
	if got := webhook.SafeText("acc_db-01.prod:x"); got != "acc_db-01.prod:x" {
		t.Fatalf("an identifier was changed: %q", got)
	}
	if got := webhook.SafeText("a<@U1>\n*b*"); got != "a??U1???b?" {
		t.Fatalf("SafeText = %q", got)
	}
	if got := webhook.SafeText(strings.Repeat("x", 100)); len(got) != 64 {
		t.Fatalf("not bounded: %d", len(got))
	}
}

func mustRead(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	return b
}

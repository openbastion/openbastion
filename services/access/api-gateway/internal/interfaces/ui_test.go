package interfaces_test

// The Admin UI served by the Gateway under /ui/ (ADR-0036): same origin as the API, a strict
// policy on every answer, the page itself for every route of the interface, nothing outside
// its directory.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

func uiDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<!doctype html><script type="module" src="/ui/assets/app.js"></script>`), 0o644))
	must(os.MkdirAll(filepath.Join(dir, "assets"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte(`console.log("ui")`), 0o644))
	must(os.WriteFile(filepath.Join(filepath.Dir(dir), "secret.txt"), []byte("outside"), 0o644))
	return dir
}

const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func TestUI_EveryAnswerCarriesTheStrictPolicy_AndTheRoutesGetThePage(t *testing.T) {
	h, err := interfaces.NewUIHandler(uiDir(t))
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	for _, c := range []struct {
		path, body, cache string
		status            int
	}{
		{"/ui/", "<!doctype html>", "no-store", 200},
		{"/ui/index.html", "<!doctype html>", "no-store", 200},
		{"/ui/oidc/callback", "<!doctype html>", "no-store", 200}, // the OIDC return page is the app
		{"/ui/accounts", "<!doctype html>", "no-store", 200},
		{"/ui/assets/app.js", `console.log("ui")`, "", 200},
		{"/ui/assets/missing.js", "", "", 404},
	} {
		rec := get(c.path)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.body) {
			t.Fatalf("%s: %d %q", c.path, rec.Code, rec.Body.String())
		}
		for k, want := range map[string]string{"Content-Security-Policy": wantCSP, "X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"} {
			if got := rec.Header().Get(k); got != want {
				t.Fatalf("%s: %s = %q, want %q", c.path, k, got, want)
			}
		}
		if c.cache != "" && rec.Header().Get("Cache-Control") != c.cache {
			t.Fatalf("%s: Cache-Control %q, want %q", c.path, rec.Header().Get("Cache-Control"), c.cache)
		}
	}
}

func TestUI_NothingOutsideItsDirectory_AndOnlyReads(t *testing.T) {
	h, _ := interfaces.NewUIHandler(uiDir(t))
	for _, path := range []string{"/ui/../secret.txt", "/ui/%2e%2e/secret.txt", "/ui/assets/../../secret.txt", "/ui/..%2fsecret.txt"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		req.URL.Path, req.URL.RawPath = path, ""
		h.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), "outside") {
			t.Fatalf("%s served a file outside the UI directory", path)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ui/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /ui/: %d, want 405", rec.Code)
	}
}

func TestNewUIHandler_RefusesADirectoryThatCannotBeTheUI(t *testing.T) {
	empty := t.TempDir()
	for _, dir := range []string{"", "web/admin-ui/dist", "/nonexistent-dir-for-openbastion", empty} {
		if _, err := interfaces.NewUIHandler(dir); err == nil {
			t.Fatalf("%q accepted", dir)
		}
	}
}

// Without the UI the Gateway serves nothing under /ui/.
func TestGateway_ServesTheUIOnlyWhenGivenOne(t *testing.T) {
	g := interfaces.NewGatewayServer(nil, nil, nil, "", "", "", "", "")
	rec := httptest.NewRecorder()
	g.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no UI configured: %d, want 404", rec.Code)
	}
	h, _ := interfaces.NewUIHandler(uiDir(t))
	rec = httptest.NewRecorder()
	g.WithUI(h).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Security-Policy") != wantCSP {
		t.Fatalf("UI configured: %d %q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
}

package interfaces

// The Admin UI, served by the Gateway under /ui/ (ADR-0036): of the same origin as the API, so
// that nothing has to be opened to another origin, and under a policy that lets the page run
// nothing but its own files.

import (
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// uiPolicy lets the page load its own scripts, styles and images, and talk to its own origin
// — nothing inline, nothing from elsewhere, never framed.
const uiPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

type uiHandler struct {
	dir   string
	files http.Handler
}

// NewUIHandler serves the built UI in dir: an absolute path to a directory with index.html.
func NewUIHandler(dir string) (http.Handler, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("the UI directory must be an absolute path")
	}
	if info, err := os.Stat(filepath.Join(dir, "index.html")); err != nil || info.IsDir() {
		return nil, errors.New("the UI directory has no index.html (build it: npm run build in web/admin-ui)")
	}
	return &uiHandler{dir: dir, files: http.StripPrefix("/ui", http.FileServer(http.Dir(dir)))}, nil
}

func (u *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", uiPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer") // the OIDC code in the return URL never leaves by Referer
	h.Set("X-Frame-Options", "DENY")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/ui")), "/")
	if strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	// A route of the interface (no extension) is the page itself; a file is a file.
	if rel == "" || rel == "index.html" || path.Ext(rel) == "" {
		h.Set("Cache-Control", "no-store")
		f, err := os.Open(filepath.Join(u.dir, "index.html"))
		if err != nil {
			http.Error(w, "the UI is not available", http.StatusServiceUnavailable)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			http.Error(w, "the UI is not available", http.StatusServiceUnavailable)
			return
		}
		// ServeContent, not ServeFile: ServeFile redirects .../index.html to .../.
		http.ServeContent(w, r, "index.html", info.ModTime(), f)
		return
	}
	u.files.ServeHTTP(w, r)
}

package infrastructure_test

// The Vault's refusals are read by their stable code, never their text (ADR-0042).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func TestVaultClient_ReadsTheRefusalCode_NotTheText(t *testing.T) {
	answer := func(status int, body string) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control=%q", r.Header.Get("Cache-Control"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		_, _, err := (&infrastructure.VaultAuthorizationHTTPClient{BaseURL: srv.URL}).AuthorizeScope(context.Background(), "s", "acc", "ssh-proxy", time.Minute)
		return err
	}
	if err := answer(http.StatusConflict, `{"code":"no_pinned_host_key","error":"the account has no pinned host key at 10.1.2.3"}`); !errors.Is(err, domain.ErrAccountNotPinned) {
		t.Fatalf("no_pinned_host_key: %v", err)
	}
	if err := answer(http.StatusConflict, `{"code":"no_pinned_tls_pin","error":"the graphical account has no pinned TLS certificate and target domain"}`); !errors.Is(err, domain.ErrAccountTLSNotPinned) {
		t.Fatalf("no_pinned_tls_pin: %v", err)
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"another 409 code":               {http.StatusConflict, `{"code":"something_else","error":"x"}`},
		"a 403 with the code":            {http.StatusForbidden, `{"code":"no_pinned_host_key","error":"x"}`},
		"a 409 TLS code on wrong status": {http.StatusForbidden, `{"code":"no_pinned_tls_pin","error":"x"}`},
		"a text body":                    {http.StatusConflict, "the account has no pinned host key"},
		"a refusal whose text leaks":     {http.StatusForbidden, `{"code":"refused","error":"dial tcp 10.1.2.3:5432"}`},
	} {
		err := answer(c.status, c.body)
		if err == nil || errors.Is(err, domain.ErrAccountNotPinned) || strings.Contains(err.Error(), "10.1.2.3") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

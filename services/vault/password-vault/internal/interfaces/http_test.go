package interfaces_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/interfaces"
)

type allowAll struct{}

func (allowAll) CheckAccess(context.Context, []string, string, string) (bool, string, error) {
	return true, "", nil
}

// vaultWithScope returns a server and a scope token authorized for ssh-proxy.
func vaultWithScope(t *testing.T, fromCert bool) (*interfaces.HTTPServer, string) {
	t.Helper()
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatal(err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, allowAll{})
	ctx := context.Background()
	if err := svc.OnboardAccount(ctx, []string{"vault-admin"}, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret")); err != nil {
		t.Fatal(err)
	}
	token, _, err := svc.AuthorizeScope(ctx, "sess1", "acc1", "ssh-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	srv := interfaces.NewHTTPServer(svc)
	srv.CallerFromCertificate = fromCert
	return srv, token
}

func fetch(srv *interfaces.HTTPServer, caller, token, claimed string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"scope_token": token, "calling_proxy_id": claimed})
	req := httptest.NewRequest(http.MethodPost, "/vault/v1/fetch-credential", bytes.NewReader(body))
	if caller != "" {
		req = req.WithContext(mtls.WithCaller(req.Context(), caller))
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestFetchCredential_WithCertificates_TheCallerIsTheCertificateNotTheClaim(t *testing.T) {
	t.Run("the proxy the scope was issued to redeems it, claiming nothing", func(t *testing.T) {
		srv, token := vaultWithScope(t, true)
		if rec := fetch(srv, "ssh-proxy", token, ""); rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})
	t.Run("and may state the same identity", func(t *testing.T) {
		srv, token := vaultWithScope(t, true)
		if rec := fetch(srv, "ssh-proxy", token, "ssh-proxy"); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("a stolen scope token is useless to another service, whatever it claims", func(t *testing.T) {
		srv, token := vaultWithScope(t, true)
		// The Broker holds scope tokens. It claims to be the proxy.
		if rec := fetch(srv, "session-broker", token, "ssh-proxy"); rec.Code != http.StatusForbidden {
			t.Fatalf("a forged identity was accepted: %d", rec.Code)
		}
		// Claiming nothing, it is itself — which the scope was not issued to.
		if rec := fetch(srv, "session-broker", token, ""); rec.Code != http.StatusForbidden {
			t.Fatalf("another service redeemed the scope: %d", rec.Code)
		}
		// Neither attempt burnt the token: the rightful proxy can still use it.
		if rec := fetch(srv, "ssh-proxy", token, ""); rec.Code != http.StatusOK {
			t.Fatalf("a refused attempt consumed the scope: %d", rec.Code)
		}
	})
	t.Run("no authenticated caller at all is refused", func(t *testing.T) {
		srv, token := vaultWithScope(t, true)
		if rec := fetch(srv, "", token, "ssh-proxy"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("the credential itself is what comes back", func(t *testing.T) {
		srv, token := vaultWithScope(t, true)
		rec := fetch(srv, "ssh-proxy", token, "")
		var out struct {
			CredentialMaterial []byte `json:"credential_material"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if string(out.CredentialMaterial) != "s3cret" {
			t.Fatalf("material %q", out.CredentialMaterial)
		}
	})
}

func TestFetchCredential_WithoutCertificates_TheClaimIsAllThereIs(t *testing.T) {
	// INTERNAL_TLS=disabled: development, where nothing authenticates anyone.
	srv, token := vaultWithScope(t, false)
	if rec := fetch(srv, "", token, "someone-else"); rec.Code != http.StatusForbidden {
		t.Fatalf("a wrong claim: %d", rec.Code)
	}
	if rec := fetch(srv, "", token, "ssh-proxy"); rec.Code != http.StatusOK {
		t.Fatalf("the right claim: %d", rec.Code)
	}
}

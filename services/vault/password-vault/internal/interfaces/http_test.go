package interfaces_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	if err := svc.OnboardPinned(ctx, []string{"vault-admin"}, application.OnboardInput{ID: "acc1", Name: "target", Username: "root", TargetHost: "10.0.0.1:22",
		Protocol: "ssh", Policy: domain.RotationManual, InitialSecret: []byte("s3cret"), HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4DoGHWLAW6lDc2nUPEk0OinOIhont/UMnJzJUQCiKK"}); err != nil {
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

// ADR-0039 over HTTP: fetch-credential hands the proxy the target with the secret; an
// unpinned account is a 409 at authorize-scope and fetch-credential; PUT host-key pins it.
func TestHostKey_OverHTTP(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4DoGHWLAW6lDc2nUPEk0OinOIhont/UMnJzJUQCiKK"
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, allowAll{}).WithRotation(noTarget{}, &okAudit{})
	ctx := context.Background()
	if err := svc.OnboardPinned(ctx, []string{"vault-admin"}, application.OnboardInput{ID: "rec", Name: "rec", Username: "root", TargetHost: "10.0.0.1:22",
		Protocol: "ssh", Policy: domain.RotationManual, InitialSecret: []byte("r"), HostKey: key}); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnboardPinned(ctx, []string{"vault-admin"}, application.OnboardInput{ID: "acc1", Name: "target", Username: "app", TargetHost: "10.0.0.1:22",
		Protocol: "ssh", Policy: domain.RotationManual, InitialSecret: []byte("s3cret"), ReconciliationAccountID: "rec", HostKey: key}); err != nil {
		t.Fatal(err)
	}
	srv := interfaces.NewHTTPServer(svc)
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	scope := func() (*httptest.ResponseRecorder, string) {
		rec := call(http.MethodPost, "/vault/v1/authorize-scope", map[string]any{"session_id": "s", "privileged_account_id": "acc1", "proxy_service_id": "ssh-proxy", "ttl_seconds": 60})
		var out struct {
			Token string `json:"scope_token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out.Token
	}

	_, token := scope()
	rec := fetch(srv, "", token, "ssh-proxy")
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["target_host"] != "10.0.0.1:22" || got["host_key"] != key {
		t.Fatalf("fetch-credential: %d %v", rec.Code, got)
	}

	_, token = scope()
	_ = store.SetHostKey(ctx, "acc1", "") // as an account onboarded before ADR-0039
	if rec, _ := scope(); rec.Code != http.StatusConflict {
		t.Fatalf("authorize-scope of an unpinned account: %d", rec.Code)
	}
	if rec := fetch(srv, "", token, "ssh-proxy"); rec.Code != http.StatusConflict || bytes.Contains(rec.Body.Bytes(), []byte("s3cret")) {
		t.Fatalf("fetch-credential of an unpinned account: %d %s", rec.Code, rec.Body)
	}
	if rec := call(http.MethodPost, "/vault/v1/rotate", map[string]any{"accountId": "acc1", "actorRoles": []string{"vault-admin"}}); rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("no pinned host key")) {
		t.Fatalf("rotate of an unpinned account: %d %s", rec.Code, rec.Body)
	}

	if rec := call(http.MethodPut, "/vault/v1/accounts/acc1/host-key", map[string]any{"hostKey": "nonsense", "actorId": "u", "actorRoles": []string{"vault-admin"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a key that does not read: %d", rec.Code)
	}
	rec = call(http.MethodPut, "/vault/v1/accounts/acc1/host-key", map[string]any{"hostKey": "10.0.0.1 " + key, "actorId": "u", "actorRoles": []string{"vault-admin"}})
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("SHA256:")) {
		t.Fatalf("PUT host-key: %d %s", rec.Code, rec.Body)
	}
	rec = call(http.MethodGet, "/vault/v1/accounts/acc1", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["hostKey"] != key || got["hostKeyFingerprint"] == "" {
		t.Fatalf("GET after the pin: %v", got)
	}
	if rec, _ := scope(); rec.Code != http.StatusOK {
		t.Fatalf("authorize-scope after the pin: %d", rec.Code)
	}
}

type okAudit struct{}

func (okAudit) EmitEvent(context.Context, string, string, string, string, bool) error { return nil }

// noTarget is a target that is never reached: every use is a failure of the test.
type noTarget struct{}

func (noTarget) SetPassword(context.Context, string, string, string, []byte, string, []byte) error {
	panic("the target was reached")
}

func (noTarget) Verify(context.Context, string, string, string, []byte) error {
	panic("the target was reached")
}

// ADR-0040 over HTTP: the schedule is checked at onboarding, and an account says its cadence
// and its next rotation; an account no schedule runs says neither.
func TestSchedule_OverHTTP(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4DoGHWLAW6lDc2nUPEk0OinOIhont/UMnJzJUQCiKK"
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	srv := interfaces.NewHTTPServer(application.NewVaultService(store, store, store, kms, allowAll{}))
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, httptest.NewRequest(method, path, bytes.NewReader(b)))
		return rec
	}
	onboard := func(id, policy string, days int, rec string) int {
		return call(http.MethodPost, "/vault/v1/onboard-account", map[string]any{"id": id, "name": id, "username": "root", "targetHost": "10.0.0.1:22",
			"protocol": "ssh", "rotationPolicy": policy, "rotationIntervalDays": days, "reconciliationAccountId": rec,
			"initialSecret": []byte("pw"), "hostKey": key, "actorRoles": []string{"vault-admin"}}).Code
	}
	if s := onboard("rec", "manual", 0, ""); s != http.StatusCreated {
		t.Fatalf("rec: %d", s)
	}
	if s := onboard("bad", "scheduled", 0, "rec"); s != http.StatusBadRequest {
		t.Fatalf("scheduled without an interval: %d", s)
	}
	if s := onboard("bad", "manual", 7, ""); s != http.StatusBadRequest {
		t.Fatalf("manual with an interval: %d", s)
	}
	if s := onboard("bad", "scheduled", 7, ""); s != http.StatusConflict {
		t.Fatalf("scheduled without a reconciliation account: %d", s)
	}
	if s := onboard("acc", "scheduled", 30, "rec"); s != http.StatusCreated {
		t.Fatalf("scheduled: %d", s)
	}
	var got map[string]any
	_ = json.Unmarshal(call(http.MethodGet, "/vault/v1/accounts/acc", nil).Body.Bytes(), &got)
	next, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(got["nextRotationAt"]))
	if got["rotationIntervalDays"] != float64(30) || time.Until(next) < 29*24*time.Hour || time.Until(next) > 30*24*time.Hour {
		t.Fatalf("scheduled account: %v", got)
	}
	got = nil
	_ = json.Unmarshal(call(http.MethodGet, "/vault/v1/accounts/rec", nil).Body.Bytes(), &got)
	if _, has := got["rotationIntervalDays"]; has {
		t.Fatalf("a manual account says an interval: %v", got)
	}
	if _, has := got["nextRotationAt"]; has {
		t.Fatalf("a manual account says a next rotation: %v", got)
	}
	if _, has := got["rotationFailures"]; has {
		t.Fatalf("an account with no failure says some: %v", got)
	}

	// ADR-0041: failures in a row are said.
	for i := 0; i < 2; i++ {
		_, _ = store.RecordRotationFailure(context.Background(), "acc")
	}
	got = nil
	_ = json.Unmarshal(call(http.MethodGet, "/vault/v1/accounts/acc", nil).Body.Bytes(), &got)
	if got["rotationFailures"] != float64(2) {
		t.Fatalf("failures not said: %v", got)
	}
}

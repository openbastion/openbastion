package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// ADR-0100: an RDP account's realm and KDCs are set by an administrator of the account, written to
// the audit before they change (nothing changes without it), normalized, refused on any other
// protocol and on an account pinned to an IP address; nil removes them. The proxy receives them
// with the secret, and an account re-pinned to an IP address afterwards gets no secret.
func TestSetKerberos_OnlyAnAdministrator_AuditedFirst_RDPOnly_DeliveredWithTheSecret(t *testing.T) {
	svc, store, authz, audit := pinnedService(t)
	ctx := context.Background()
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "desk", Name: "d", Username: "operator", TargetHost: "10.0.0.5:3389",
		Protocol: "rdp", Policy: domain.RotationManual, InitialSecret: []byte("pw")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "screen", Name: "v", Username: "operator", TargetHost: "10.0.0.6:5900",
		Protocol: "vnc", Policy: domain.RotationManual, InitialSecret: []byte("pw")}); err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("a", 64)
	if _, _, err := svc.SetTLSPin(ctx, "admin", adminRoles, "desk", pin, "desk.corp.example.com"); err != nil {
		t.Fatal(err)
	}
	kerberos := func() *domain.KerberosSettings { a, _ := store.Get(ctx, "desk"); return a.Kerberos }
	if kerberos() != nil {
		t.Fatal("an account has no Kerberos settings unless they are set")
	}
	corp := &domain.KerberosSettings{Realm: "corp.example.com", KDCs: []string{"DC1.corp.example.com"}}
	audit.events = nil

	authz.allowed = false
	audit.down = true
	if _, err := svc.SetKerberos(ctx, "user_op", []string{"dba"}, "desk", corp); !errors.Is(err, application.ErrAuditUnavailable) || kerberos() != nil {
		t.Fatalf("the refusal was not fail-closed when audit was down: %v, %+v", err, kerberos())
	}
	audit.down = false
	if _, err := svc.SetKerberos(ctx, "user_op", []string{"dba"}, "desk", corp); !errors.Is(err, application.ErrAccessDenied) || kerberos() != nil {
		t.Fatalf("a refused caller changed the settings: %v, %+v", err, kerberos())
	}
	if authz.lastResource != "vault:account-admin:desk" || authz.lastAction != "vault:account:kerberos" {
		t.Fatalf("checked %s %s", authz.lastResource, authz.lastAction)
	}
	authz.allowed = true

	if _, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "desk", &domain.KerberosSettings{Realm: "CORP"}); !errors.Is(err, domain.ErrInvalidKerberos) || kerberos() != nil {
		t.Fatalf("invalid settings were stored: %v, %+v", err, kerberos())
	}
	if _, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "screen", corp); !errors.Is(err, application.ErrKerberosNotRDP) {
		t.Fatalf("a VNC account took Kerberos settings: %v", err)
	}
	audit.down = true
	if _, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "desk", corp); !errors.Is(err, application.ErrAuditUnavailable) || kerberos() != nil {
		t.Fatalf("changed without the audit: %v, %+v", err, kerberos())
	}
	audit.down = false

	stored, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "desk", corp)
	if err != nil || stored == nil || stored.Realm != "CORP.EXAMPLE.COM" || strings.Join(stored.KDCs, ",") != "dc1.corp.example.com:88" {
		t.Fatalf("set: %+v, %v", stored, err)
	}
	if k := kerberos(); k == nil || k.Realm != "CORP.EXAMPLE.COM" {
		t.Fatalf("stored: %+v", k)
	}

	// The proxy receives the settings with the secret.
	scope, _, err := svc.AuthorizeScope(ctx, "session-kerberos", "desk", "rdp-vnc-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := svc.FetchCredential(ctx, scope, "rdp-vnc-proxy")
	if err != nil || delivered.Kerberos == nil || delivered.Kerberos.Realm != "CORP.EXAMPLE.COM" || delivered.Kerberos.KDCs[0] != "dc1.corp.example.com:88" {
		t.Fatalf("delivered: %+v, %v", delivered.Kerberos, err)
	}

	// A ticket names a host: the account cannot be re-pinned to an IP address through the API,
	// and an IP name written behind the API's back delivers no secret.
	if _, _, err := svc.SetTLSPin(ctx, "admin", adminRoles, "desk", pin, "10.0.0.5"); !errors.Is(err, application.ErrKerberosNeedsName) {
		t.Fatalf("re-pinned to an IP address: %v", err)
	}
	if err := store.SetTLSPin(ctx, "desk", pin, "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	scope, _, err = svc.AuthorizeScope(ctx, "session-ip", "desk", "rdp-vnc-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := svc.FetchCredential(ctx, scope, "rdp-vnc-proxy"); !errors.Is(err, application.ErrKerberosNeedsName) || d.Material != nil {
		t.Fatalf("a secret for a ticket without a host name: %v", err)
	}
	if _, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "desk", corp); !errors.Is(err, application.ErrKerberosNeedsName) {
		t.Fatalf("Kerberos on an account pinned to an IP address: %v", err)
	}

	// nil removes the settings, even on an account pinned to an IP address: back to NTLMv2.
	if stored, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "desk", nil); err != nil || stored != nil || kerberos() != nil {
		t.Fatalf("removed: %+v, %v, %+v", stored, err, kerberos())
	}
	if got := strings.Join(audit.events, ","); got != "user_op|vault.kerberos_set|desk|false,user_admin|vault.kerberos_set|desk|true,user_admin|vault.kerberos_set|desk|true" {
		t.Fatalf("audit: %s", got)
	}

	if err := svc.DisableAccount(ctx, adminRoles, "desk"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetKerberos(ctx, "user_admin", adminRoles, "desk", corp); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a disabled account was changed: %v", err)
	}
}

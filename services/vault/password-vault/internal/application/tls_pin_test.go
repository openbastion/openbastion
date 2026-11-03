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

func TestNormalizeTLSPinAndTargetDomain(t *testing.T) {
	pin := strings.Repeat("A", 64)
	gotPin, gotDomain, err := application.NormalizeTLSPin(pin, "TARGET.Example.")
	if err != nil || gotPin != strings.ToLower(pin) || gotDomain != "target.example" {
		t.Fatalf("normalize: pin=%q domain=%q err=%v", gotPin, gotDomain, err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", 64)} {
		if _, _, err := application.NormalizeTLSPin(bad, "target.example"); !errors.Is(err, application.ErrBadTLSPin) {
			t.Fatalf("pin %q: %v", bad, err)
		}
	}
	for _, bad := range []string{"", "*.example.com", "https://target.example", "target.example:5900", "bad label.example", "-bad.example", "bad..example"} {
		if _, err := application.NormalizeTargetDomain(bad); !errors.Is(err, application.ErrBadTargetDomain) {
			t.Fatalf("domain %q accepted: %v", bad, err)
		}
	}
	if got, err := application.NormalizeTargetDomain("2001:0db8::1"); err != nil || got != "2001:db8::1" {
		t.Fatalf("IPv6 normalization: %q, %v", got, err)
	}
}

func TestVNCAccountNeedsAuditedTLSPinBeforeScopeAndCredentialDelivery(t *testing.T) {
	svc, store, authz, audit := pinnedService(t)
	ctx := context.Background()
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "vnc-account", Name: "desktop", Username: "operator", TargetHost: "desktop.internal:5900", Protocol: "vnc", Policy: domain.RotationManual, InitialSecret: []byte("vnc-password")}); err != nil {
		t.Fatalf("onboard VNC account: %v", err)
	}
	if _, _, err := svc.AuthorizeScope(ctx, "session-before-pin", "vnc-account", "rdp-vnc-proxy", time.Minute); !errors.Is(err, application.ErrNoTLSPin) {
		t.Fatalf("scope without pin = %v", err)
	}
	if _, _, err := svc.AuthorizeScope(ctx, "session-wrong-proxy", "vnc-account", "ssh-proxy", time.Minute); !errors.Is(err, application.ErrProxyProtocolMismatch) {
		t.Fatalf("VNC account scope for SSH proxy = %v", err)
	}
	if _, err := svc.SetHostKey(ctx, "admin", adminRoles, "vnc-account", testHostKey); !errors.Is(err, application.ErrUnsupportedProtocol) {
		t.Fatalf("SSH host key must not be set on a VNC account: %v", err)
	}

	pin := strings.Repeat("a", 64)
	authz.allowed = false
	if _, _, err := svc.SetTLSPin(ctx, "operator", []string{"dba"}, "vnc-account", pin, "desktop.internal"); !errors.Is(err, application.ErrAccessDenied) {
		t.Fatalf("non-admin pin = %v", err)
	}
	authz.allowed = true
	if _, _, err := svc.SetTLSPin(ctx, "admin", adminRoles, "vnc-account", "bad-pin", "desktop.internal"); !errors.Is(err, application.ErrBadTLSPin) {
		t.Fatalf("bad pin = %v", err)
	}
	audit.down = true
	if _, _, err := svc.SetTLSPin(ctx, "admin", adminRoles, "vnc-account", pin, "desktop.internal"); !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("pin without audit = %v", err)
	}
	if a, _ := store.Get(ctx, "vnc-account"); a.TLSCertificateSHA256 != "" || a.TargetDomain != "" {
		t.Fatal("TLS pin changed without a successful audit")
	}
	audit.down = false
	gotPin, gotDomain, err := svc.SetTLSPin(ctx, "admin", adminRoles, "vnc-account", strings.ToUpper(pin), "DESKTOP.INTERNAL.")
	if err != nil || gotPin != pin || gotDomain != "desktop.internal" {
		t.Fatalf("set pin: %q %q %v", gotPin, gotDomain, err)
	}
	if authz.lastAction != "vault:account:pin" {
		t.Fatalf("authorization action = %q", authz.lastAction)
	}
	if got := strings.Join(audit.events, ","); got != "admin|vault.tls_pin_set|vnc-account|true" {
		t.Fatalf("audit = %q", got)
	}

	scope, _, err := svc.AuthorizeScope(ctx, "session-after-pin", "vnc-account", "rdp-vnc-proxy", time.Minute)
	if err != nil {
		t.Fatalf("scope after pin: %v", err)
	}
	delivered, err := svc.FetchCredential(ctx, scope, "rdp-vnc-proxy")
	if err != nil {
		t.Fatalf("fetch after pin: %v", err)
	}
	if string(delivered.Material) != "vnc-password" || delivered.TargetHost != "desktop.internal:5900" || delivered.TargetUser != "operator" || delivered.TLSCertificateSHA256 != pin || delivered.TargetDomain != "desktop.internal" {
		t.Fatalf("credential target metadata mismatch: type=%q host=%q user=%q pin=%q domain=%q", delivered.Type, delivered.TargetHost, delivered.TargetUser, delivered.TLSCertificateSHA256, delivered.TargetDomain)
	}
	if err := svc.Rotate(ctx, adminRoles, "vnc-account", []byte("new-password")); !errors.Is(err, application.ErrUnsupportedProtocol) {
		t.Fatalf("VNC password rotation must fail closed: %v", err)
	}
	// A pin removed after scope issuance is rechecked at redemption; no secret escapes.
	scope, _, err = svc.AuthorizeScope(ctx, "session-pin-removed", "vnc-account", "rdp-vnc-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTLSPin(ctx, "vnc-account", "", ""); err != nil {
		t.Fatal(err)
	}
	missing, err := svc.FetchCredential(ctx, scope, "rdp-vnc-proxy")
	if !errors.Is(err, application.ErrNoTLSPin) || missing.Material != nil {
		t.Fatalf("credential after pin removal: err=%v material=%d", err, len(missing.Material))
	}
}

func TestVNCProtocolRejectsSSHHostKeyAndScheduledRotation(t *testing.T) {
	svc, store, _, _ := pinnedService(t)
	ctx := context.Background()
	in := application.OnboardInput{ID: "vnc-bad", Name: "desktop", Username: "operator", TargetHost: "desktop.internal:5900", Protocol: "vnc", Policy: domain.RotationManual, InitialSecret: []byte("pw"), HostKey: testHostKey}
	if err := svc.OnboardPinned(ctx, adminRoles, in); !errors.Is(err, application.ErrBadHostKey) {
		t.Fatalf("VNC with SSH host key = %v", err)
	}
	in.ID, in.HostKey, in.Policy = "vnc-scheduled", "", domain.RotationScheduled
	in.RotationIntervalDays = 30
	if err := svc.OnboardPinned(ctx, adminRoles, in); !errors.Is(err, application.ErrUnsupportedProtocol) {
		t.Fatalf("scheduled VNC rotation = %v", err)
	}
	if _, err := store.Get(ctx, "vnc-bad"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rejected VNC account was persisted: %v", err)
	}
}

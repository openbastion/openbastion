package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// ADR-0132: an RDP account's screen profile is set by an administrator of the account, written
// to the audit before it changes (nothing changes without it), validated, and refused on any
// other protocol; nil removes it.
func TestSetScreenProfile_OnlyAnAdministrator_AuditedFirst_RDPOnly(t *testing.T) {
	svc, store, authz, audit := pinnedService(t)
	ctx := context.Background()
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "desk", Name: "d", Username: "operator", TargetHost: "10.0.0.5:3389",
		Protocol: "rdp", Policy: domain.RotationManual, InitialSecret: []byte("pw")}); err != nil {
		t.Fatal(err)
	}
	if err := onboardTest(svc, ctx, adminRoles, "shell", "s", "root", host, "ssh", domain.RotationManual, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	profile := func() *domain.ScreenProfile { a, _ := store.Get(ctx, "desk"); return a.ScreenProfile }
	if profile() != nil {
		t.Fatal("an account has no profile unless one is set")
	}
	bitmap16 := &domain.ScreenProfile{Channels: []string{"bitmap"}, DefaultChannel: "bitmap", ColorDepths: []int{16}, DefaultColorDepth: 16}
	audit.events = nil

	authz.allowed = false
	audit.down = true
	if err := svc.SetScreenProfile(ctx, "user_op", []string{"dba"}, "desk", bitmap16); !errors.Is(err, application.ErrAuditUnavailable) || profile() != nil {
		t.Fatalf("the refusal was not fail-closed when audit was down: %v, %+v", err, profile())
	}
	audit.down = false
	if err := svc.SetScreenProfile(ctx, "user_op", []string{"dba"}, "desk", bitmap16); !errors.Is(err, application.ErrAccessDenied) || profile() != nil {
		t.Fatalf("a refused caller changed the profile: %v, %+v", err, profile())
	}
	if authz.lastResource != "vault:account-admin:desk" || authz.lastAction != "vault:account:screen-profile" {
		t.Fatalf("checked %s %s", authz.lastResource, authz.lastAction)
	}
	authz.allowed = true

	invalid := &domain.ScreenProfile{Channels: []string{"bitmap"}, DefaultChannel: "graphics", ColorDepths: []int{16}, DefaultColorDepth: 16}
	if err := svc.SetScreenProfile(ctx, "user_admin", adminRoles, "desk", invalid); !errors.Is(err, domain.ErrInvalidScreenProfile) || profile() != nil {
		t.Fatalf("an invalid profile was stored: %v, %+v", err, profile())
	}
	if err := svc.SetScreenProfile(ctx, "user_admin", adminRoles, "shell", bitmap16); !errors.Is(err, application.ErrNotRDP) {
		t.Fatalf("an SSH account took a screen profile: %v", err)
	}

	audit.down = true
	if err := svc.SetScreenProfile(ctx, "user_admin", adminRoles, "desk", bitmap16); !errors.Is(err, application.ErrAuditUnavailable) || profile() != nil {
		t.Fatalf("changed without the audit: %v, %+v", err, profile())
	}
	audit.down = false

	if err := svc.SetScreenProfile(ctx, "user_admin", adminRoles, "desk", bitmap16); err != nil || profile() == nil || profile().DefaultChannel != "bitmap" || profile().DefaultColorDepth != 16 {
		t.Fatalf("set: %v, %+v", err, profile())
	}
	if err := svc.SetScreenProfile(ctx, "user_admin", adminRoles, "desk", nil); err != nil || profile() != nil {
		t.Fatalf("removed: %v, %+v", err, profile())
	}
	if got := strings.Join(audit.events, ","); got != "user_op|vault.screen_profile_set|desk|false,user_admin|vault.screen_profile_set|desk|true,user_admin|vault.screen_profile_set|desk|true" {
		t.Fatalf("audit: %s", got)
	}

	if err := svc.DisableAccount(ctx, adminRoles, "desk"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetScreenProfile(ctx, "user_admin", adminRoles, "desk", bitmap16); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a disabled account was changed: %v", err)
	}
}

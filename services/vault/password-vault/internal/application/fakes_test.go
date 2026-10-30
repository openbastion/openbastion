package application_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"sync"
)

// fakeTarget is the targets: for each host and user, the password it takes.
type fakeTarget struct {
	mu        sync.Mutex
	passwords map[string]string // host|user -> password
	setFails  bool              // the target refuses the change
	verifyBad bool              // the change is made, the new password does not open the target
	sets      int
}

func newFakeTarget() *fakeTarget { return &fakeTarget{passwords: map[string]string{}} }

func (f *fakeTarget) SetPassword(_ context.Context, host, hostKey, admin string, adminSecret []byte, user string, newSecret []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if hostKey != testHostKey {
		return errors.New("the target is not the one pinned")
	}
	if f.setFails {
		return errors.New("chpasswd: permission denied")
	}
	if p, ok := f.passwords[host+"|"+admin]; ok && p != string(adminSecret) {
		return fmt.Errorf("the reconciliation account cannot log in")
	}
	f.sets++
	f.passwords[host+"|"+user] = string(newSecret)
	return nil
}

func (f *fakeTarget) Verify(_ context.Context, host, hostKey, user string, secret []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if hostKey != testHostKey {
		return errors.New("the target is not the one pinned")
	}
	if f.verifyBad {
		return errors.New("permission denied")
	}
	if p, ok := f.passwords[host+"|"+user]; !ok || p != string(secret) {
		return errors.New("permission denied")
	}
	return nil
}

func (f *fakeTarget) has(host, user string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passwords[host+"|"+user]
}

// fakeAudit records the events; down refuses them.
type fakeAudit struct {
	mu     sync.Mutex
	events []string
	down   bool
}

func (a *fakeAudit) EmitEvent(_ context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down {
		return errors.New("audit unreachable")
	}
	a.events = append(a.events, fmt.Sprintf("%s|%s|%s|%v", actorID, action, resourceID, success))
	return nil
}

// testHostKey is the pinned host key of every test target (ADR-0039).
const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4DoGHWLAW6lDc2nUPEk0OinOIhont/UMnJzJUQCiKK"

// onboardTest onboards an account with its target's host key pinned (ADR-0039).
func onboardTest(svc *application.VaultService, ctx context.Context, roles []string, id, name, user, host, proto string, policy domain.RotationPolicy, secret []byte) error {
	return svc.OnboardPinned(ctx, roles, application.OnboardInput{ID: id, Name: name, Username: user, TargetHost: host, Protocol: proto,
		Policy: policy, InitialSecret: secret, HostKey: testHostKey})
}

// fetchMaterial is the secret FetchCredential delivers.
func fetchMaterial(svc *application.VaultService, ctx context.Context, token, proxy string) ([]byte, error) {
	d, err := svc.FetchCredential(ctx, token, proxy)
	return d.Material, err
}

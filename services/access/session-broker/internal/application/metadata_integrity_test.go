package application_test

// ADR-0116 §8 in the service: a session whose row nobody attested is shown, read-only, and never
// acted on; one whose MAC failed is not even shown.

import (
	"context"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

// integrityStore reads every session as the store would have found its row.
type integrityStore struct {
	*infrastructure.InMemoryStore
	integrity domain.MetadataIntegrity
	broken    bool
}

func (s *integrityStore) Get(ctx context.Context, id string) (*domain.Session, error) {
	if s.broken {
		return nil, domain.ErrMetadataIntegrity
	}
	sess, err := s.InMemoryStore.Get(ctx, id)
	if err == nil && s.integrity != "" {
		sess.Integrity = s.integrity
	}
	return sess, err
}

func TestMetadataIntegrity_ALegacySessionIsReadOnly(t *testing.T) {
	store := &integrityStore{InMemoryStore: infrastructure.NewInMemoryStore()}
	f := newTerminateFixtureOn(store)
	sess := f.open(t)
	store.integrity = domain.IntegrityLegacyUnverified
	ctx := context.Background()
	proxyCalls := f.proxy.calls

	if got, err := f.broker.GetSession(ctx, sess.ID, requester, []string{"sre"}); err != nil || got.ID != sess.ID {
		t.Fatalf("reading a legacy session: %v %v", got, err)
	}
	if _, err := f.end(sess.ID, requester); !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("terminating a legacy session: %v", err)
	}
	if _, _, _, _, err := f.broker.ConnectDetails(ctx, sess.ID, requester, domain.ScreenChoice{}); !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("connecting to a legacy session: %v", err)
	}
	if _, err := f.broker.ApproveBreakGlass(ctx, sess.ID, "lead", []string{"sre"}); !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("deciding on a legacy session: %v", err)
	}
	if _, err := f.broker.StartSecretActionStepUp(ctx, requester, []string{"sre"}, sess.ID, "secret:inject"); !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("a secret into a legacy session: %v", err)
	}
	if n := f.proxy.calls - proxyCalls; n != 0 {
		t.Fatalf("the proxy was asked %d time(s) about a legacy session", n)
	}
}

func TestMetadataIntegrity_AForgedSessionIsNotEvenShown(t *testing.T) {
	store := &integrityStore{InMemoryStore: infrastructure.NewInMemoryStore()}
	f := newTerminateFixtureOn(store)
	sess := f.open(t)
	store.broken = true
	ctx := context.Background()
	if _, err := f.broker.GetSession(ctx, sess.ID, requester, []string{"sre"}); !errors.Is(err, domain.ErrMetadataIntegrity) {
		t.Fatalf("reading a forged session: %v", err)
	}
	if _, err := f.end(sess.ID, requester); !errors.Is(err, domain.ErrMetadataIntegrity) {
		t.Fatalf("terminating a forged session: %v", err)
	}
	if _, _, _, _, err := f.broker.ConnectDetails(ctx, sess.ID, requester, domain.ScreenChoice{}); !errors.Is(err, domain.ErrMetadataIntegrity) {
		t.Fatalf("connecting to a forged session: %v", err)
	}
}

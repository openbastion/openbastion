package infrastructure_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

type actionGrantStore interface {
	domain.UserRepository
	domain.MFAActionRepository
}

func actionGrantStores(t *testing.T) map[string]func(*testing.T) actionGrantStore {
	return map[string]func(*testing.T) actionGrantStore{
		"memory":   func(*testing.T) actionGrantStore { return infrastructure.NewInMemoryStore() },
		"postgres": func(t *testing.T) actionGrantStore { return infrastructure.NewPostgresStore(testDB(t)) },
	}
}

func newActionGrant(t *testing.T, userID string, expires time.Time) domain.MFAActionGrant {
	t.Helper()
	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		t.Fatal(err)
	}
	return domain.MFAActionGrant{
		Hash: hash, UserID: userID, SessionID: "session-01", AccountID: "account-01",
		Protocol: "ssh", Action: "secret:inject", ExpiresAt: expires,
	}
}

func actionGrantBinding(grant domain.MFAActionGrant) domain.MFAActionGrantBinding {
	return domain.MFAActionGrantBinding{
		UserID: grant.UserID, SessionID: grant.SessionID, AccountID: grant.AccountID,
		Protocol: grant.Protocol, Action: grant.Action,
	}
}

func TestMFAActionGrant_BindsEveryFieldExpiresAndCanBeConsumedOnce(t *testing.T) {
	for name, open := range actionGrantStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := open(t)
			userID := fmt.Sprintf("user_action_grant_%d", time.Now().UnixNano())
			if err := store.Create(ctx, &domain.User{ID: userID, Username: userID, DisplayName: userID, PasswordHash: "x"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			grant := newActionGrant(t, userID, now.Add(time.Minute))
			if err := store.SaveActionGrant(ctx, grant); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveActionGrant(ctx, grant); !errors.Is(err, domain.ErrMFAActionGrantExists) {
				t.Fatalf("duplicate grant hash: %v", err)
			}

			// A mismatch must not burn a valid grant: an attacker cannot move it to
			// another user/session/account/protocol/action.
			mutations := []struct {
				name string
				edit func(*domain.MFAActionGrantBinding)
			}{
				{"user", func(g *domain.MFAActionGrantBinding) { g.UserID = "another-user" }},
				{"session", func(g *domain.MFAActionGrantBinding) { g.SessionID = "another-session" }},
				{"account", func(g *domain.MFAActionGrantBinding) { g.AccountID = "another-account" }},
				{"protocol", func(g *domain.MFAActionGrantBinding) { g.Protocol = "rdp" }},
				{"action", func(g *domain.MFAActionGrantBinding) { g.Action = "secret:paste" }},
			}
			for _, mutation := range mutations {
				expected := actionGrantBinding(grant)
				mutation.edit(&expected)
				if ok, err := store.ConsumeActionGrant(ctx, grant.Hash, expected, now); err != nil || ok {
					t.Fatalf("%s binding mismatch consumed grant: ok=%v err=%v", mutation.name, ok, err)
				}
			}
			if ok, err := store.ConsumeActionGrant(ctx, grant.Hash, actionGrantBinding(grant), now); err != nil || !ok {
				t.Fatalf("valid grant not consumed: ok=%v err=%v", ok, err)
			}
			if ok, err := store.ConsumeActionGrant(ctx, grant.Hash, actionGrantBinding(grant), now); err != nil || ok {
				t.Fatalf("replayed grant accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestMFAActionGrant_ExpiredGrantIsRefused(t *testing.T) {
	for name, open := range actionGrantStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := open(t)
			userID := fmt.Sprintf("user_action_expired_%d", time.Now().UnixNano())
			if err := store.Create(ctx, &domain.User{ID: userID, Username: userID, DisplayName: userID, PasswordHash: "x"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			grant := newActionGrant(t, userID, now)
			if err := store.SaveActionGrant(ctx, grant); err != nil {
				t.Fatal(err)
			}
			if ok, err := store.ConsumeActionGrant(ctx, grant.Hash, actionGrantBinding(grant), now); err != nil || ok {
				t.Fatalf("expired grant accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestMFAActionGrant_ConcurrentConsumptionHasOneWinner(t *testing.T) {
	for name, open := range actionGrantStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := open(t)
			userID := fmt.Sprintf("user_action_race_%d", time.Now().UnixNano())
			if err := store.Create(ctx, &domain.User{ID: userID, Username: userID, DisplayName: userID, PasswordHash: "x"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			grant := newActionGrant(t, userID, now.Add(time.Minute))
			if err := store.SaveActionGrant(ctx, grant); err != nil {
				t.Fatal(err)
			}

			var winners atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ok, err := store.ConsumeActionGrant(ctx, grant.Hash, actionGrantBinding(grant), now)
					if err != nil {
						t.Errorf("consume: %v", err)
						return
					}
					if ok {
						winners.Add(1)
					}
				}()
			}
			wg.Wait()
			if got := winners.Load(); got != 1 {
				t.Fatalf("successful consumers = %d, want exactly one", got)
			}
		})
	}
}

func TestMFAActionChallenge_ConcurrentConsumptionHasOneWinner(t *testing.T) {
	for name, open := range actionGrantStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := open(t)
			userID := fmt.Sprintf("user_action_challenge_%d", time.Now().UnixNano())
			if err := store.Create(ctx, &domain.User{ID: userID, Username: userID, DisplayName: userID, PasswordHash: "x"}); err != nil {
				t.Fatal(err)
			}
			hash := make([]byte, 32)
			if _, err := rand.Read(hash); err != nil {
				t.Fatal(err)
			}
			challenge := domain.MFAActionChallenge{
				Hash:    hash,
				Binding: domain.MFAActionGrantBinding{UserID: userID, SessionID: "s-1", AccountID: "a-1", Protocol: "ssh", Action: "secret:inject"},
				Factors: []string{"totp"}, ExpiresAt: time.Now().UTC().Add(time.Minute),
			}
			if err := store.SaveActionChallenge(ctx, challenge); err != nil {
				t.Fatal(err)
			}
			var winners atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ok, err := store.ConsumeActionChallenge(ctx, hash, time.Now().UTC())
					if err != nil {
						t.Errorf("consume challenge: %v", err)
						return
					}
					if ok {
						winners.Add(1)
					}
				}()
			}
			wg.Wait()
			if got := winners.Load(); got != 1 {
				t.Fatalf("successful challenge consumers = %d, want exactly one", got)
			}
		})
	}
}

func TestMFAActionChallenge_ExpiryAndAttemptLimit(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	ctx := context.Background()
	userID := "user_action_attempts"
	if err := store.Create(ctx, &domain.User{ID: userID, Username: userID, DisplayName: userID, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		t.Fatal(err)
	}
	challenge := domain.MFAActionChallenge{
		Hash:    hash,
		Binding: domain.MFAActionGrantBinding{UserID: userID, SessionID: "s-1", AccountID: "a-1", Protocol: "ssh", Action: "secret:inject"},
		Factors: []string{"totp"}, ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	if err := store.SaveActionChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if gone, err := store.FailActionChallenge(ctx, hash, 5); err != nil || gone {
			t.Fatalf("attempt %d: gone=%v err=%v", i+1, gone, err)
		}
	}
	if gone, err := store.FailActionChallenge(ctx, hash, 5); err != nil || !gone {
		t.Fatalf("fifth attempt: gone=%v err=%v", gone, err)
	}
	if _, err := store.GetActionChallenge(ctx, hash); !errors.Is(err, domain.ErrChallengeNotFound) {
		t.Fatalf("exhausted challenge remains: %v", err)
	}

	expiredHash := make([]byte, 32)
	if _, err := rand.Read(expiredHash); err != nil {
		t.Fatal(err)
	}
	expired := domain.MFAActionChallenge{
		Hash:    expiredHash,
		Binding: domain.MFAActionGrantBinding{UserID: userID, SessionID: "s-expired", AccountID: "a-1", Protocol: "ssh", Action: "secret:inject"},
		Factors: []string{"totp"}, ExpiresAt: time.Now().UTC().Add(-time.Second),
	}
	if err := store.SaveActionChallenge(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.ConsumeActionChallenge(ctx, expiredHash, time.Now().UTC()); err != nil || ok {
		t.Fatalf("expired challenge consumed: ok=%v err=%v", ok, err)
	}
	if _, err := store.GetActionChallenge(ctx, expiredHash); !errors.Is(err, domain.ErrChallengeNotFound) {
		t.Fatalf("expired challenge remains: %v", err)
	}
}

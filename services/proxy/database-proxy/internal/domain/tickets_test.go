package domain

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTicketStoreConsumesOnceAndStoresOnlyDigest(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	store, err := NewTicketStore(8, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := store.Register(PendingSession{SessionID: "s1", ActorID: "u1", ScopeToken: []byte("vault-scope"), ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.pending) != 1 {
		t.Fatalf("pending count = %d", len(store.pending))
	}
	for digest := range store.pending {
		if string(digest[:]) == ticket {
			t.Fatal("plaintext ticket was stored as the map key")
		}
	}
	got, err := store.Consume(ticket)
	if err != nil || got.SessionID != "s1" || string(got.ScopeToken) != "vault-scope" {
		t.Fatalf("Consume = %#v, %v", got, err)
	}
	if _, err := store.Consume(ticket); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestTicketStoreExpiresAndRevokesTickets(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	store, err := NewTicketStore(8, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.Register(PendingSession{SessionID: "expired", ScopeToken: []byte("scope"), ExpiresAt: now.Add(-time.Second)})
	if err == nil || expired != "" {
		t.Fatalf("expired ticket registration = %q, %v", expired, err)
	}
	ticket, err := store.Register(PendingSession{SessionID: "s1", ScopeToken: []byte("scope"), ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if n := store.RevokeSession("s1", now.Add(time.Hour)); n != 1 {
		t.Fatalf("revoked tickets = %d", n)
	}
	if !store.IsRevoked("s1") {
		t.Fatal("session revocation was not retained")
	}
	if _, err := store.Consume(ticket); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("revoked ticket error = %v", err)
	}
}

func TestTicketStoreBoundsPendingTickets(t *testing.T) {
	now := time.Now().UTC()
	store, err := NewTicketStore(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(PendingSession{SessionID: "s1", ScopeToken: []byte("one"), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(PendingSession{SessionID: "s2", ScopeToken: []byte("two"), ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, ErrTicketCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestTicketStoreConcurrentConsumeHasOneWinner(t *testing.T) {
	now := time.Now().UTC()
	store, err := NewTicketStore(8, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := store.Register(PendingSession{SessionID: "s1", ScopeToken: []byte("scope"), ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Consume(ticket); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("successful consumes = %d, want 1", winners)
	}
}

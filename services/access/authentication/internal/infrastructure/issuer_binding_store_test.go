package infrastructure_test

// ADR-0078, in PostgreSQL: a binding is created once, held while it is decided on, changed only when
// asked, and a refusal leaves every row as it was — the new ones included.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

// keep decides nothing: it returns what is bound.
func keep(into map[string]domain.IssuerBinding) func(map[string]domain.IssuerBinding) (map[string]string, error) {
	return func(b map[string]domain.IssuerBinding) (map[string]string, error) {
		for k, v := range b {
			into[k] = v
		}
		return nil, nil
	}
}

func TestPostgresStore_BindIssuers_CreatedOnce_ChangedWhenAsked_RefusedLeavesNothing(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()
	p, q := uniqueUsername("corp"), uniqueUsername("other")

	got := map[string]domain.IssuerBinding{}
	if err := store.BindIssuers(ctx, map[string]string{p: "https://a.example"}, keep(got)); err != nil {
		t.Fatal(err)
	}
	if !got[p].Created || got[p].Issuer != "https://a.example" {
		t.Fatalf("first: %+v, want created with A", got[p])
	}
	got = map[string]domain.IssuerBinding{}
	_ = store.BindIssuers(ctx, map[string]string{p: "https://b.example"}, keep(got))
	if got[p].Created || got[p].Issuer != "https://a.example" {
		t.Fatalf("second, configured with B: %+v, want A, not created", got[p])
	}

	refused := errors.New("refused")
	err := store.BindIssuers(ctx, map[string]string{p: "https://b.example", q: "https://q.example"}, func(map[string]domain.IssuerBinding) (map[string]string, error) {
		return nil, refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("%v, want the refusal", err)
	}
	got = map[string]domain.IssuerBinding{}
	_ = store.BindIssuers(ctx, map[string]string{q: "https://later.example"}, keep(got))
	if got[q].Issuer != "https://later.example" {
		t.Fatalf("%s after a refused start: %+v — the refusal kept a row it created", q, got[q])
	}

	if err := store.BindIssuers(ctx, map[string]string{p: "https://b.example"}, func(map[string]domain.IssuerBinding) (map[string]string, error) {
		return map[string]string{p: "https://b.example"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	got = map[string]domain.IssuerBinding{}
	_ = store.BindIssuers(ctx, map[string]string{p: "https://c.example"}, keep(got))
	if got[p].Issuer != "https://b.example" {
		t.Fatalf("after the change: %+v, want B", got[p])
	}
	if err := store.BindIssuers(ctx, map[string]string{p: "x"}, func(map[string]domain.IssuerBinding) (map[string]string, error) {
		return map[string]string{"not-held": "x"}, nil
	}); err == nil {
		t.Fatal("a row not held was changed")
	}
}

// Two replicas start together with two issuers for one new provider: one issuer is kept, and the
// other replica sees it — never each its own.
func TestPostgresStore_BindIssuers_TwoStartsTogether_SeeOneIssuer(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	for round := 0; round < 10; round++ {
		p := uniqueUsername("race")
		start := make(chan struct{})
		var wg sync.WaitGroup
		seen := make([]domain.IssuerBinding, 2)
		errs := make([]error, 2)
		for i, issuer := range []string{"https://a.example", "https://b.example"} {
			wg.Add(1)
			go func(i int, issuer string) {
				defer wg.Done()
				<-start
				errs[i] = store.BindIssuers(context.Background(), map[string]string{p: issuer}, func(b map[string]domain.IssuerBinding) (map[string]string, error) {
					seen[i] = b[p]
					time.Sleep(20 * time.Millisecond) // hold the row: the other one must wait
					return nil, nil
				})
			}(i, issuer)
		}
		close(start)
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("round %d: %v %v", round, errs[0], errs[1])
		}
		if seen[0].Issuer != seen[1].Issuer || seen[0].Created == seen[1].Created {
			t.Fatalf("round %d: %+v and %+v — want one created, and both seeing its issuer", round, seen[0], seen[1])
		}
	}
}

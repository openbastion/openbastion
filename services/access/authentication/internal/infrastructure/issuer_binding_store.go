package infrastructure

// The issuer of each OIDC provider (ADR-0078), in PostgreSQL and in memory.

import (
	"context"
	"fmt"
	"sort"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

func sortedProviders(want map[string]string) []string {
	providers := make([]string, 0, len(want))
	for p := range want {
		providers = append(providers, p)
	}
	// Always in the same order: two replicas never wait on each other's rows crosswise.
	sort.Strings(providers)
	return providers
}

// BindIssuers is domain.IssuerBindingRepository.BindIssuers. Under READ COMMITTED, the INSERT of a
// replica that starts at the same time waits for the first one's transaction, then inserts nothing:
// its SELECT … FOR UPDATE reads the row the first one committed.
func (s *PostgresStore) BindIssuers(ctx context.Context, want map[string]string, decide func(map[string]domain.IssuerBinding) (map[string]string, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	bound := map[string]domain.IssuerBinding{}
	for _, p := range sortedProviders(want) {
		res, err := tx.ExecContext(ctx, `INSERT INTO identity_provider_bindings (provider, issuer) VALUES ($1, $2) ON CONFLICT (provider) DO NOTHING`, p, want[p])
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		var issuer string
		if err := tx.QueryRowContext(ctx, `SELECT issuer FROM identity_provider_bindings WHERE provider = $1 FOR UPDATE`, p).Scan(&issuer); err != nil {
			return err
		}
		bound[p] = domain.IssuerBinding{Provider: p, Issuer: issuer, Created: n == 1}
	}
	replace, err := decide(bound)
	if err != nil {
		return err
	}
	for _, p := range sortedProviders(replace) {
		if _, held := bound[p]; !held {
			return fmt.Errorf("the issuer of provider %q is not held: it cannot be changed", p)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE identity_provider_bindings SET issuer = $2, bound_at = now() WHERE provider = $1`, p, replace[p]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// BindIssuers is domain.IssuerBindingRepository.BindIssuers, for one process.
func (s *InMemoryStore) BindIssuers(ctx context.Context, want map[string]string, decide func(map[string]domain.IssuerBinding) (map[string]string, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issuers == nil {
		s.issuers = map[string]string{}
	}
	bound := map[string]domain.IssuerBinding{}
	for _, p := range sortedProviders(want) {
		issuer, ok := s.issuers[p]
		if !ok {
			issuer = want[p]
		}
		bound[p] = domain.IssuerBinding{Provider: p, Issuer: issuer, Created: !ok}
	}
	replace, err := decide(bound)
	if err != nil {
		return err
	}
	for p := range replace {
		if _, held := bound[p]; !held {
			return fmt.Errorf("the issuer of provider %q is not held: it cannot be changed", p)
		}
	}
	for p, b := range bound {
		s.issuers[p] = b.Issuer
	}
	for p, issuer := range replace {
		s.issuers[p] = issuer
	}
	return nil
}

// IssuerOf is the issuer provider is bound to in memory, "" if none; for tests.
func (s *InMemoryStore) IssuerOf(provider string) string {
	return s.issuers[provider]
}

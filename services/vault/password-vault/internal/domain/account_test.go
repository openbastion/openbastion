package domain_test

import (
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// A scheduled account is due its interval after its last rotation — after its creation if it
// never rotated (ADR-0040); an account no schedule runs is never due.
func TestRotationDueAt(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rotated := created.Add(10 * 24 * time.Hour)
	a := &domain.PrivilegedAccount{RotationPolicy: domain.RotationScheduled, RotationIntervalDays: 7, CreatedAt: created}
	if due := a.RotationDueAt(); due == nil || !due.Equal(created.Add(7*24*time.Hour)) {
		t.Fatalf("never rotated: %v", due)
	}
	a.LastRotatedAt = &rotated
	if due := a.RotationDueAt(); due == nil || !due.Equal(rotated.Add(7*24*time.Hour)) {
		t.Fatalf("rotated on day 10: %v", due)
	}
	for _, other := range []*domain.PrivilegedAccount{
		{RotationPolicy: domain.RotationManual, RotationIntervalDays: 7, CreatedAt: created},
		{RotationPolicy: domain.RotationPostUse, CreatedAt: created},
		{RotationPolicy: domain.RotationScheduled, RotationIntervalDays: 0, CreatedAt: created},
	} {
		if due := other.RotationDueAt(); due != nil {
			t.Fatalf("%s/%d is due at %v", other.RotationPolicy, other.RotationIntervalDays, due)
		}
	}
}

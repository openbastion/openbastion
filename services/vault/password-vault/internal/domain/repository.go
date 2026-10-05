package domain

import (
	"context"
	"errors"
)

// ErrNotFound is returned by any repository when the requested entity does
// not exist. Concrete infrastructure implementations map their own
// not-found conditions onto this sentinel so application/ never depends
// on a specific storage engine's error type.
var ErrNotFound = errors.New("not found")

type AccountRepository interface {
	Get(ctx context.Context, id string) (*PrivilegedAccount, error)
	Create(ctx context.Context, a *PrivilegedAccount) error
}

type SecretRepository interface {
	CurrentVersion(ctx context.Context, accountID string) (*SecretVersion, error)
	AddVersion(ctx context.Context, s *SecretVersion) error
	SupersedeCurrent(ctx context.Context, accountID string) error
}

type ScopeRepository interface {
	Save(ctx context.Context, g *ScopeGrant) error
	// ConsumeIfValid atomically checks and marks a scope token consumed —
	// it must reject an unknown, expired, already-consumed, or wrong-proxy
	// token in a single operation, so there is no window for a race
	// between "check" and "consume" (ADR-0003).
	ConsumeIfValid(ctx context.Context, token, callingProxyID string) (*ScopeGrant, error)
}

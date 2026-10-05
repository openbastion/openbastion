package domain

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("session not found")

type SessionRepository interface {
	Save(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
}

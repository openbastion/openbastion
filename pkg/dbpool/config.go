// Package dbpool owns the strict, shared contract for per-process PostgreSQL pool limits.
package dbpool

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

const (
	DefaultMaxOpenConns = 10
	MaxOpenConns        = 1000
	DefaultMaxIdleConns = 10
)

// Config bounds one process. Idle connections are a subset of open connections.
type Config struct {
	MaxOpenConns int
	MaxIdleConns int
}

// Defaults preserves the pool limits used by every service before ADR-0135.
func Defaults() Config {
	return Config{MaxOpenConns: DefaultMaxOpenConns, MaxIdleConns: DefaultMaxIdleConns}
}

// ParseEnv reads the two pool settings. An explicitly empty variable is invalid;
// only an absent variable selects its default.
func ParseEnv(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("dbpool: environment lookup is nil")
	}

	cfg := Defaults()
	if raw, ok := lookup("DB_POOL_MAX_OPEN_CONNS"); ok {
		value, err := parseDecimal("DB_POOL_MAX_OPEN_CONNS", raw, 1, MaxOpenConns)
		if err != nil {
			return Config{}, err
		}
		cfg.MaxOpenConns = value
	}
	if cfg.MaxIdleConns > cfg.MaxOpenConns {
		cfg.MaxIdleConns = cfg.MaxOpenConns
	}
	if raw, ok := lookup("DB_POOL_MAX_IDLE_CONNS"); ok {
		value, err := parseDecimal("DB_POOL_MAX_IDLE_CONNS", raw, 0, cfg.MaxOpenConns)
		if err != nil {
			return Config{}, err
		}
		cfg.MaxIdleConns = value
	}
	return cfg, nil
}

// Validate rejects configurations that database/sql would interpret as unbounded.
func (c Config) Validate() error {
	if c.MaxOpenConns < 1 || c.MaxOpenConns > MaxOpenConns {
		return fmt.Errorf("dbpool: max open connections must be between 1 and %d", MaxOpenConns)
	}
	if c.MaxIdleConns < 0 || c.MaxIdleConns > c.MaxOpenConns {
		return fmt.Errorf("dbpool: max idle connections must be between 0 and max open connections (%d)", c.MaxOpenConns)
	}
	return nil
}

// Configure applies the validated per-process ceilings to a database/sql pool.
func Configure(db *sql.DB, config Config) error {
	if db == nil {
		return errors.New("dbpool: database handle is nil")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	return nil
}

func parseDecimal(name, raw string, min, max int) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("dbpool: %s must be a decimal integer between %d and %d", name, min, max)
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("dbpool: %s must be a decimal integer between %d and %d", name, min, max)
		}
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("dbpool: %s must be a decimal integer between %d and %d", name, min, max)
	}
	return value, nil
}

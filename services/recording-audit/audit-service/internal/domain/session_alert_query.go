package domain

import "time"

// SessionAlertFilter is a bounded keyset query over the operator projection.
type SessionAlertFilter struct {
	Status           string
	Severity         string
	SessionID        string
	Since            *time.Time
	Until            *time.Time
	BeforeDetectedAt *time.Time
	BeforeID         string
	Limit            int
}

// SessionAlertCounts is one database snapshot of all unacknowledged occurrences.
type SessionAlertCounts struct {
	UnacknowledgedCount int64
	BySeverity          map[AlertSeverity]int64
	AsOf                time.Time
}

package domain

import (
	"errors"
	"time"
)

var ErrAlertDetectionAlreadyProcessed = errors.New("session alert detection already processed")

const (
	AlertStatusUnacknowledged = "unacknowledged"
	AlertStatusAcknowledged   = "acknowledged"
)

type AlertSeverity string

const (
	AlertInfo     AlertSeverity = "info"
	AlertLow      AlertSeverity = "low"
	AlertMedium   AlertSeverity = "medium"
	AlertHigh     AlertSeverity = "high"
	AlertCritical AlertSeverity = "critical"
)

// SessionAlert is an operational projection. The source event remains the audit proof.
type SessionAlert struct {
	ID                     string
	RuleID                 string
	RuleVersion            string
	SourceEventID          string
	SessionID              string
	Severity               AlertSeverity
	Status                 string
	Summary                string
	DetectedAt             time.Time
	CreatedAt              time.Time
	Revision               int64
	AcknowledgedAt         *time.Time
	AcknowledgedBy         string
	AcknowledgementEventID string
}

// AlertDetectionItem carries only an event reference and the catalogue version, never its body.
type AlertDetectionItem struct {
	SourceEventID  string
	CatalogVersion string
	Attempts       int
	NextAttemptAt  time.Time
}

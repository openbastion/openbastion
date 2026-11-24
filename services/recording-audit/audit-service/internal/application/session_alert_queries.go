package application

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

var (
	ErrSessionAlertReadUnavailable            = errors.New("session alert read unavailable")
	ErrSessionAlertNotFound                   = errors.New("session alert not found")
	ErrInvalidSessionAlertQuery               = errors.New("invalid session alert query")
	ErrSessionAlertAcknowledgementUnavailable = errors.New("session alert acknowledgement unavailable")
	ErrInvalidSessionAlertAcknowledgement     = errors.New("invalid session alert acknowledgement")
)

const (
	DefaultSessionAlertLimit = 50
	MaxSessionAlertLimit     = 100
)

// SessionAlertReadStore is the read side of the Audit Service's alert projection.
type SessionAlertReadStore interface {
	ListSessionAlerts(context.Context, domain.SessionAlertFilter) ([]domain.SessionAlert, error)
	GetSessionAlert(context.Context, string) (*domain.SessionAlert, error)
	SessionAlertCounts(context.Context) (domain.SessionAlertCounts, error)
	SessionAlertsDurable() bool
}

type SessionAlertListQuery struct {
	Status    string
	Severity  string
	SessionID string
	Since     *time.Time
	Until     *time.Time
	Cursor    string
	Limit     int
}

type SessionAlertPage struct {
	Alerts     []domain.SessionAlert `json:"alerts"`
	NextCursor string                `json:"next_cursor,omitempty"`
	HasMore    bool                  `json:"has_more"`
}

type SessionAlertSummary struct {
	UnacknowledgedCount int64            `json:"unacknowledged_count"`
	BySeverity          map[string]int64 `json:"by_severity"`
	AsOf                time.Time        `json:"as_of"`
	Durable             bool             `json:"durable"`
}

func (s *AuditService) ListSessionAlerts(ctx context.Context, query SessionAlertListQuery) (SessionAlertPage, error) {
	store, ok := s.store.(SessionAlertReadStore)
	if !ok {
		return SessionAlertPage{}, ErrSessionAlertReadUnavailable
	}
	filter, err := normalizeSessionAlertQuery(query)
	if err != nil {
		return SessionAlertPage{}, err
	}
	alerts, err := store.ListSessionAlerts(ctx, filter)
	if err != nil {
		return SessionAlertPage{}, fmt.Errorf("list session alerts: %w", err)
	}
	pageLimit := filter.Limit - 1
	page := SessionAlertPage{Alerts: alerts, HasMore: len(alerts) > pageLimit}
	if page.HasMore {
		page.Alerts = page.Alerts[:pageLimit]
		last := page.Alerts[len(page.Alerts)-1]
		page.NextCursor = encodeSessionAlertCursor(last.DetectedAt, last.ID)
	}
	if page.Alerts == nil {
		page.Alerts = []domain.SessionAlert{}
	}
	return page, nil
}

func (s *AuditService) GetSessionAlert(ctx context.Context, id string) (*domain.SessionAlert, error) {
	if !validSessionAlertID(id) {
		return nil, ErrInvalidSessionAlertQuery
	}
	store, ok := s.store.(SessionAlertReadStore)
	if !ok {
		return nil, ErrSessionAlertReadUnavailable
	}
	alert, err := store.GetSessionAlert(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get session alert: %w", err)
	}
	if alert == nil {
		return nil, ErrSessionAlertNotFound
	}
	return alert, nil
}

func (s *AuditService) SessionAlertSummary(ctx context.Context) (SessionAlertSummary, error) {
	store, ok := s.store.(SessionAlertReadStore)
	if !ok {
		return SessionAlertSummary{}, ErrSessionAlertReadUnavailable
	}
	counts, err := store.SessionAlertCounts(ctx)
	if err != nil {
		return SessionAlertSummary{}, fmt.Errorf("count session alerts: %w", err)
	}
	bySeverity := make(map[string]int64, 5)
	for _, severity := range []domain.AlertSeverity{domain.AlertInfo, domain.AlertLow, domain.AlertMedium, domain.AlertHigh, domain.AlertCritical} {
		bySeverity[string(severity)] = counts.BySeverity[severity]
	}
	return SessionAlertSummary{
		UnacknowledgedCount: counts.UnacknowledgedCount,
		BySeverity:          bySeverity,
		AsOf:                counts.AsOf.UTC(),
		Durable:             store.SessionAlertsDurable(),
	}, nil
}

func normalizeSessionAlertQuery(query SessionAlertListQuery) (domain.SessionAlertFilter, error) {
	limit := query.Limit
	if limit == 0 {
		limit = DefaultSessionAlertLimit
	}
	if limit < 1 || limit > MaxSessionAlertLimit {
		return domain.SessionAlertFilter{}, ErrInvalidSessionAlertQuery
	}
	if query.Status != "" && query.Status != domain.AlertStatusUnacknowledged && query.Status != domain.AlertStatusAcknowledged {
		return domain.SessionAlertFilter{}, ErrInvalidSessionAlertQuery
	}
	if query.Severity != "" && !validSeverity(query.Severity) {
		return domain.SessionAlertFilter{}, ErrInvalidSessionAlertQuery
	}
	if query.SessionID != "" && !validSessionIDFilter(query.SessionID) {
		return domain.SessionAlertFilter{}, ErrInvalidSessionAlertQuery
	}
	if query.Since != nil && query.Until != nil && query.Since.After(*query.Until) {
		return domain.SessionAlertFilter{}, ErrInvalidSessionAlertQuery
	}
	filter := domain.SessionAlertFilter{Status: query.Status, Severity: query.Severity, SessionID: query.SessionID, Since: query.Since, Until: query.Until, Limit: limit + 1}
	if query.Cursor != "" {
		at, id, err := decodeSessionAlertCursor(query.Cursor)
		if err != nil {
			return domain.SessionAlertFilter{}, ErrInvalidSessionAlertQuery
		}
		filter.BeforeDetectedAt, filter.BeforeID = &at, id
	}
	return filter, nil
}

func validSessionIDFilter(id string) bool {
	if len(id) > MaxIDBytes || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validSeverity(v string) bool {
	switch domain.AlertSeverity(v) {
	case domain.AlertInfo, domain.AlertLow, domain.AlertMedium, domain.AlertHigh, domain.AlertCritical:
		return true
	default:
		return false
	}
}

func validSessionAlertID(id string) bool {
	if len(id) != len("alert_")+32 || !strings.HasPrefix(id, "alert_") {
		return false
	}
	for _, c := range id[len("alert_"):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func encodeSessionAlertCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeSessionAlertCursor(cursor string) (time.Time, string, error) {
	if len(cursor) > 256 {
		return time.Time{}, "", ErrInvalidSessionAlertQuery
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 2 || !validSessionAlertID(parts[1]) {
		return time.Time{}, "", ErrInvalidSessionAlertQuery
	}
	at, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", err
	}
	return at.UTC(), parts[1], nil
}

// SessionAlertAcknowledger appends the signed audit event and updates the projection atomically.
type SessionAlertAcknowledger interface {
	AcknowledgeSessionAlert(context.Context, string, int64, string, *domain.Event) (domain.SessionAlert, bool, error)
}

// AcknowledgeSessionAlert records a human acknowledgement in the audit chain and projection.
// The returned bool is true when the occurrence had already been acknowledged (idempotent retry).
func (s *AuditService) AcknowledgeSessionAlert(ctx context.Context, emitter, actorID, id string, expectedRevision int64) (domain.SessionAlert, bool, error) {
	if !validSessionAlertID(id) || expectedRevision < 1 || checkID("actor_id", actorID, true) != nil || checkEmitter(emitter) != nil {
		return domain.SessionAlert{}, false, ErrInvalidSessionAlertAcknowledgement
	}
	readStore, readOK := s.store.(SessionAlertReadStore)
	ackStore, ackOK := s.store.(SessionAlertAcknowledger)
	if !readOK || !ackOK {
		return domain.SessionAlert{}, false, ErrSessionAlertAcknowledgementUnavailable
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	alert, err := readStore.GetSessionAlert(ctx, id)
	if err != nil {
		return domain.SessionAlert{}, false, fmt.Errorf("read session alert before acknowledgement: %w", err)
	}
	if alert == nil {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertNotFound
	}
	if alert.Status == domain.AlertStatusAcknowledged {
		return *alert, true, nil
	}
	if alert.Status != domain.AlertStatusUnacknowledged || alert.Revision != expectedRevision || alert.Revision >= domain.MaxSessionAlertRevision {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertRevisionConflict
	}

	details := map[string]string{
		"alert_id":   id,
		"session_id": alert.SessionID,
		"rule_id":    alert.RuleID,
		"severity":   string(alert.Severity),
		"revision":   strconv.FormatInt(alert.Revision, 10),
	}
	if err := validate(actorID, "session.alert.acknowledged", "session_alert", id); err != nil {
		return domain.SessionAlert{}, false, ErrInvalidSessionAlertAcknowledgement
	}
	if err := validateDetails(details); err != nil {
		return domain.SessionAlert{}, false, ErrInvalidSessionAlertAcknowledgement
	}
	event, err := s.nextEvent(ctx, emitter, actorID, "session.alert.acknowledged", "session_alert", id, details, true)
	if err != nil {
		return domain.SessionAlert{}, false, fmt.Errorf("prepare session alert acknowledgement event: %w", err)
	}
	acknowledged, changed, err := ackStore.AcknowledgeSessionAlert(ctx, id, expectedRevision, actorID, event)
	if err != nil {
		return domain.SessionAlert{}, false, fmt.Errorf("commit session alert acknowledgement: %w", err)
	}
	if changed {
		tip := *event
		s.tip = &tip
	}
	return acknowledged, !changed, nil
}

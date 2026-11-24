package infrastructure

import (
	"context"
	"sort"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

func (s *InMemoryStore) ListSessionAlerts(_ context.Context, filter domain.SessionAlertFilter) ([]domain.SessionAlert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alerts := make([]domain.SessionAlert, 0, len(s.sessionAlerts))
	for _, alert := range s.sessionAlerts {
		if filter.Status != "" && alert.Status != filter.Status || filter.Severity != "" && string(alert.Severity) != filter.Severity || filter.SessionID != "" && alert.SessionID != filter.SessionID {
			continue
		}
		if filter.Since != nil && alert.DetectedAt.Before(*filter.Since) || filter.Until != nil && alert.DetectedAt.After(*filter.Until) {
			continue
		}
		if filter.BeforeDetectedAt != nil && !alert.DetectedAt.Before(*filter.BeforeDetectedAt) && !(alert.DetectedAt.Equal(*filter.BeforeDetectedAt) && alert.ID < filter.BeforeID) {
			continue
		}
		alerts = append(alerts, cloneSessionAlert(alert))
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].DetectedAt.Equal(alerts[j].DetectedAt) {
			return alerts[i].ID > alerts[j].ID
		}
		return alerts[i].DetectedAt.After(alerts[j].DetectedAt)
	})
	if len(alerts) > filter.Limit {
		alerts = alerts[:filter.Limit]
	}
	return alerts, nil
}

func (s *InMemoryStore) GetSessionAlert(_ context.Context, id string) (*domain.SessionAlert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert, ok := s.sessionAlerts[id]
	if !ok {
		return nil, nil
	}
	copy := cloneSessionAlert(alert)
	return &copy, nil
}

func (s *InMemoryStore) SessionAlertCounts(_ context.Context) (domain.SessionAlertCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := domain.SessionAlertCounts{BySeverity: map[domain.AlertSeverity]int64{}, AsOf: time.Now().UTC()}
	for _, alert := range s.sessionAlerts {
		if alert.Status != domain.AlertStatusUnacknowledged {
			continue
		}
		counts.UnacknowledgedCount++
		counts.BySeverity[alert.Severity]++
	}
	return counts, nil
}

func (s *InMemoryStore) SessionAlertsDurable() bool { return false }

func cloneSessionAlert(alert domain.SessionAlert) domain.SessionAlert {
	if alert.AcknowledgedAt != nil {
		at := *alert.AcknowledgedAt
		alert.AcknowledgedAt = &at
	}
	return alert
}

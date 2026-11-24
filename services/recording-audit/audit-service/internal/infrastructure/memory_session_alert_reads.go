package infrastructure

import (
	"bytes"
	"context"
	"fmt"
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

// AcknowledgeSessionAlert appends the event and changes the projection under the same lock.
func (s *InMemoryStore) AcknowledgeSessionAlert(_ context.Context, id string, expectedRevision int64, actorID string, event *domain.Event) (domain.SessionAlert, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert, ok := s.sessionAlerts[id]
	if !ok {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertNotFound
	}
	if alert.Status == domain.AlertStatusAcknowledged {
		return cloneSessionAlert(alert), false, nil
	}
	if alert.Status != domain.AlertStatusUnacknowledged || alert.Revision != expectedRevision || alert.Revision >= domain.MaxSessionAlertRevision {
		return domain.SessionAlert{}, false, domain.ErrSessionAlertRevisionConflict
	}
	if event == nil || event.ActorID != actorID || event.ResourceID != id || event.Action != "session.alert.acknowledged" {
		return domain.SessionAlert{}, false, fmt.Errorf("invalid session alert acknowledgement event")
	}
	var lastHash []byte
	if len(s.events) > 0 {
		lastHash = s.events[len(s.events)-1].Hash
	}
	if !bytes.Equal(lastHash, event.PrevHash) {
		return domain.SessionAlert{}, false, fmt.Errorf("audit chain head moved during session alert acknowledgement")
	}
	at := event.Timestamp.UTC()
	alert.Status = domain.AlertStatusAcknowledged
	alert.AcknowledgedAt = &at
	alert.AcknowledgedBy = actorID
	alert.AcknowledgementEventID = event.ID
	alert.Revision++
	s.events = append(s.events, event)
	s.sessionAlerts[id] = alert
	return cloneSessionAlert(alert), true, nil
}

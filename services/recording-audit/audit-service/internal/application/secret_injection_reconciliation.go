package application

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

const (
	secretInjectionStarted                = "session.secret_injection_started"
	secretInjectionDone                   = "session.secret_injected"
	secretInjectionFailed                 = "session.secret_injection_failed"
	defaultInjectionLimit                 = 100
	MaxSecretInjectionReconciliationLimit = 500
)

// SecretInjectionOutcome is a read-only projection of immutable audit evidence. It never
// claims that the target received the complete secret: completed means only that the proxy
// recorded a successful terminal result. Unknown outcomes must be verified at the target.
type SecretInjectionOutcome struct {
	InjectionID string     `json:"injection_id"`
	SessionID   string     `json:"session_id"`
	AccountID   string     `json:"account_id"`
	Protocol    string     `json:"protocol"`
	Emitter     string     `json:"emitter,omitempty"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	StartEvent  string     `json:"start_event_id,omitempty"`
	ResultEvent string     `json:"result_event_id,omitempty"`
}

// SecretInjectionReconciliation is explicit about its coverage. Archived months are included
// only after every referenced archive, checkpoint, event hash and covered anchor is verified.
type SecretInjectionReconciliation struct {
	Outcomes                []SecretInjectionOutcome `json:"outcomes"`
	Coverage                string                   `json:"coverage"`
	ArchivedHistoryExcluded bool                     `json:"archived_history_excluded"`
	ScannedEvents           int                      `json:"scanned_events"`
	ArchivedEvents          int                      `json:"archived_events"`
	HasMore                 bool                     `json:"has_more"`
	NextBefore              string                   `json:"next_before,omitempty"`
}

var (
	ErrInvalidReconciliationCursor  = errors.New("invalid secret-injection reconciliation cursor")
	ErrReconciliationCursorNotFound = errors.New("secret-injection reconciliation cursor not found")
)

type injectionEvidence struct {
	outcome SecretInjectionOutcome
	starts  []*domain.Event
	results []*domain.Event
}

// ReconcileSecretInjections derives outcomes from the retained chain and every verified archive.
// It performs no writes, never repairs history and never retries an injection.
func (s *AuditService) ReconcileSecretInjections(ctx context.Context, limit int, before string) (*SecretInjectionReconciliation, error) {
	if limit <= 0 {
		limit = defaultInjectionLimit
	}
	if limit > MaxSecretInjectionReconciliationLimit {
		return nil, fmt.Errorf("limit must not exceed %d", MaxSecretInjectionReconciliationLimit)
	}
	if err := s.VerifyChain(ctx); err != nil {
		return nil, fmt.Errorf("verify audit chain before reconciliation: %w", err)
	}
	events, err := s.store.All(ctx)
	if err != nil {
		return nil, err
	}
	var archivedEvents []*domain.Event
	var archivedEventCount int
	if s.anchors != nil {
		checkpoints, err := s.anchors.Checkpoints(ctx)
		if err != nil {
			return nil, fmt.Errorf("read audit archive checkpoints: %w", err)
		}
		anchors, err := s.anchors.All(ctx)
		if err != nil {
			return nil, fmt.Errorf("read audit anchors: %w", err)
		}
		archivedEvents, archivedEventCount, err = s.readVerifiedArchives(ctx, checkpoints, anchors)
		if err != nil {
			return nil, err
		}
	} else if s.archive != nil {
		return nil, fmt.Errorf("archive reader is configured without an anchor/checkpoint source")
	}
	allEvents := make([]*domain.Event, 0, len(archivedEvents)+len(events))
	allEvents = append(allEvents, archivedEvents...)
	allEvents = append(allEvents, events...)

	byID := make(map[string]*injectionEvidence)
	for _, event := range allEvents {
		if event.ResourceType != "session" || (event.Action != secretInjectionStarted && event.Action != secretInjectionDone && event.Action != secretInjectionFailed) {
			continue
		}
		id := event.Details["injection_id"]
		if !validInjectionID(id) {
			continue
		}
		evidence := byID[id]
		if evidence == nil {
			evidence = &injectionEvidence{outcome: SecretInjectionOutcome{InjectionID: id, Status: "outcome_unknown"}}
			byID[id] = evidence
		}
		switch event.Action {
		case secretInjectionStarted:
			evidence.starts = append(evidence.starts, event)
		case secretInjectionDone, secretInjectionFailed:
			evidence.results = append(evidence.results, event)
		}
	}

	outcomes := make([]SecretInjectionOutcome, 0, len(byID))
	for _, evidence := range byID {
		outcome := evidence.outcome
		switch {
		case len(evidence.starts) == 0:
			outcome.Reason = "missing_start_event"
		case len(evidence.starts) != 1:
			outcome.Reason = "duplicate_start_event"
		default:
			start := evidence.starts[0]
			outcome.SessionID = start.ResourceID
			outcome.AccountID = start.Details["account_id"]
			outcome.Protocol = start.Details["protocol"]
			outcome.Emitter = start.Emitter
			started := start.Timestamp
			outcome.StartedAt = &started
			outcome.StartEvent = start.ID
			if !start.Success || outcome.AccountID == "" || (outcome.Protocol != "ssh" && outcome.Protocol != "rdp" && outcome.Protocol != "vnc") {
				outcome.Reason = "invalid_start_evidence"
			} else if len(evidence.results) == 0 {
				outcome.Reason = "missing_terminal_event"
			} else if len(evidence.results) != 1 {
				outcome.Reason = "multiple_terminal_events"
			} else {
				result := evidence.results[0]
				finished := result.Timestamp
				outcome.FinishedAt = &finished
				outcome.ResultEvent = result.ID
				if result.ResourceID != start.ResourceID || result.Emitter != start.Emitter ||
					result.Details["account_id"] != outcome.AccountID || result.Details["protocol"] != outcome.Protocol ||
					result.Timestamp.Before(start.Timestamp) {
					outcome.Reason = "evidence_mismatch"
				} else if result.Action == secretInjectionDone && result.Success {
					outcome.Status = "completed"
				} else if result.Action == secretInjectionFailed && !result.Success {
					outcome.Status = "failed"
					outcome.Reason = "proxy_reported_input_failure_may_be_partial"
				} else {
					outcome.Reason = "invalid_terminal_evidence"
				}
			}
		}
		outcomes = append(outcomes, outcome)
	}

	sort.Slice(outcomes, func(i, j int) bool {
		if outcomes[i].StartedAt == nil && outcomes[j].StartedAt == nil {
			return outcomes[i].InjectionID > outcomes[j].InjectionID
		}
		if outcomes[i].StartedAt == nil {
			return false
		}
		if outcomes[j].StartedAt == nil {
			return true
		}
		if outcomes[i].StartedAt.Equal(*outcomes[j].StartedAt) {
			return outcomes[i].InjectionID > outcomes[j].InjectionID
		}
		return outcomes[i].StartedAt.After(*outcomes[j].StartedAt)
	})
	if before != "" {
		if !validInjectionID(before) {
			return nil, ErrInvalidReconciliationCursor
		}
		cursor := -1
		for i := range outcomes {
			if outcomes[i].InjectionID == before {
				cursor = i
				break
			}
		}
		if cursor < 0 {
			return nil, ErrReconciliationCursorNotFound
		}
		outcomes = outcomes[cursor+1:]
	}
	hasMore := len(outcomes) > limit
	if hasMore {
		outcomes = outcomes[:limit]
	}
	coverage := "retained_audit_chain"
	if len(archivedEvents) > 0 {
		coverage = "verified_archives_and_retained_chain"
	}
	result := &SecretInjectionReconciliation{
		Outcomes: outcomes, Coverage: coverage,
		ArchivedHistoryExcluded: false, ScannedEvents: len(events) + archivedEventCount, ArchivedEvents: archivedEventCount, HasMore: hasMore,
	}
	if hasMore && len(outcomes) > 0 {
		result.NextBefore = outcomes[len(outcomes)-1].InjectionID
	}
	return result, nil
}

func validInjectionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id
}

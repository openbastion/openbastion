package application

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

const (
	VideoEventSecretInjectionStarted = "secret_injection_started"
	VideoEventSourceVault            = "vault"
	DefaultVideoEventPageSize        = 50
	MaxVideoEventPageSize            = 100
	maxVideoEventCursorBytes         = 1024
)

type VideoEventPage struct {
	Events     []domain.VideoRecordingEvent
	NextCursor string
}

type videoEventCursor struct {
	SessionID  string    `json:"s"`
	OccurredAt time.Time `json:"t"`
	EventID    string    `json:"i"`
}

// RecordVideoEvent durably writes a metadata-only event. The repository assigns the timestamp.
func (s *RecorderService) RecordVideoEvent(ctx context.Context, event domain.VideoRecordingEvent) (domain.VideoRecordingEvent, error) {
	if !usableSessionID(event.SessionID) || !usableOpaqueID(event.EventID, 128) ||
		!usableOpaqueID(event.AccountID, 256) || event.EventType != VideoEventSecretInjectionStarted ||
		(event.Protocol != "vnc" && event.Protocol != "rdp") || event.Source != VideoEventSourceVault {
		return domain.VideoRecordingEvent{}, domain.ErrInvalidSegment
	}
	depCtx, cancel := dependencyContext(ctx)
	defer cancel()
	return s.repo.RecordVideoEvent(depCtx, event)
}

// ReadVideoEvents authorizes and audits every page before reading it, including an empty page.
func (s *RecorderService) ReadVideoEvents(ctx context.Context, actorID string, roles []string, sessionID, cursor string, limit int) (VideoEventPage, error) {
	if !usableSessionID(sessionID) || !usableSessionID(actorID) || len(roles) > maxActorRoles {
		return VideoEventPage{}, domain.ErrForbidden
	}
	for _, role := range roles {
		if !usableActorRole(role) {
			return VideoEventPage{}, domain.ErrForbidden
		}
	}
	if limit == 0 {
		limit = DefaultVideoEventPageSize
	}
	if limit < 1 || limit > MaxVideoEventPageSize {
		return VideoEventPage{}, domain.ErrInvalidSegment
	}
	after, err := decodeVideoEventCursor(sessionID, cursor)
	if err != nil {
		return VideoEventPage{}, domain.ErrInvalidSegment
	}

	depCtx, cancel := dependencyContext(ctx)
	allowed, _, err := s.authz.CheckAccess(depCtx, roles, RecordingResource+sessionID, ActionRead)
	cancel()
	if err != nil {
		return VideoEventPage{}, fmt.Errorf("%w: asking authorization: %v", domain.ErrUnavailable, err)
	}
	if !allowed {
		s.auditRefusedRead(ctx, actorID, sessionID)
		return VideoEventPage{}, domain.ErrForbidden
	}

	depCtx, cancel = dependencyContext(ctx)
	err = s.audit.EmitEvent(depCtx, actorID, AuditActionRead, "session", sessionID, true, map[string]string{
		"recording_kind": "video_events", "page_limit": fmt.Sprint(limit),
	})
	cancel()
	if err != nil {
		return VideoEventPage{}, fmt.Errorf("%w: recording video event read: %v", domain.ErrUnavailable, err)
	}

	depCtx, cancel = dependencyContext(ctx)
	defer cancel()
	events, err := s.repo.GetVideoEvents(depCtx, sessionID, after, limit+1)
	if err != nil {
		return VideoEventPage{}, err
	}
	page := VideoEventPage{Events: events}
	if len(events) > limit {
		page.Events = events[:limit]
		last := page.Events[len(page.Events)-1]
		page.NextCursor = encodeVideoEventCursor(sessionID, last)
	}
	return page, nil
}

func encodeVideoEventCursor(sessionID string, event domain.VideoRecordingEvent) string {
	value, _ := json.Marshal(videoEventCursor{SessionID: sessionID, OccurredAt: event.OccurredAt.UTC(), EventID: event.EventID})
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeVideoEventCursor(sessionID, cursor string) (domain.EventCursor, error) {
	if cursor == "" {
		return domain.EventCursor{}, nil
	}
	if len(cursor) > maxVideoEventCursorBytes {
		return domain.EventCursor{}, domain.ErrInvalidSegment
	}
	for _, character := range cursor {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return domain.EventCursor{}, domain.ErrInvalidSegment
		}
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return domain.EventCursor{}, domain.ErrInvalidSegment
	}
	var value videoEventCursor
	if err := json.Unmarshal(data, &value); err != nil || value.SessionID != sessionID || value.OccurredAt.IsZero() || !usableOpaqueID(value.EventID, 128) {
		return domain.EventCursor{}, domain.ErrInvalidSegment
	}
	return domain.EventCursor{OccurredAt: value.OccurredAt.UTC(), EventID: value.EventID}, nil
}

func usableOpaqueID(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

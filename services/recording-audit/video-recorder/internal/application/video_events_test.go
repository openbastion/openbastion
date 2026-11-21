package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

func TestVideoRecordingEventsAreIdempotentAndIndependentOfFrameSequence(t *testing.T) {
	authz := &authorization{allowed: true}
	audit := &auditEmitter{}
	svc := newRecorder(t, authz, audit, newObjectStore())
	input := domain.VideoRecordingEvent{EventID: "evt-1", SessionID: "session-events", EventType: application.VideoEventSecretInjectionStarted, Protocol: "vnc", Source: "vault", AccountID: "account-1"}
	first, err := svc.RecordVideoEvent(context.Background(), input)
	if err != nil {
		t.Fatalf("record event before first frame: %v", err)
	}
	second, err := svc.RecordVideoEvent(context.Background(), input)
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if first.OccurredAt.IsZero() || !first.OccurredAt.Equal(second.OccurredAt) {
		t.Fatalf("retry changed server timestamp: first=%v second=%v", first.OccurredAt, second.OccurredAt)
	}
	conflicting := input
	conflicting.AccountID = "different-account"
	if _, err := svc.RecordVideoEvent(context.Background(), conflicting); !errors.Is(err, domain.ErrEventConflict) {
		t.Fatalf("conflicting idempotency key returned %v", err)
	}

	writer, err := svc.BeginRecording(context.Background(), "session-events")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.RecordSegment(context.Background(), oneFrameSegment("session-events", 1)); err != nil {
		t.Fatalf("event changed image sequence: %v", err)
	}
	if err := writer.Complete(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
}

func TestReadVideoEventsAuditsEveryPageIncludingEmptyPageAndUsesStableCursor(t *testing.T) {
	authz := &authorization{allowed: true}
	audit := &auditEmitter{}
	svc := newRecorder(t, authz, audit, newObjectStore())
	writer, err := svc.BeginRecording(context.Background(), "session-pages")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, id := range []string{"evt-a", "evt-b"} {
		if _, err := svc.RecordVideoEvent(context.Background(), domain.VideoRecordingEvent{EventID: id, SessionID: "session-pages", EventType: application.VideoEventSecretInjectionStarted, Protocol: "rdp", Source: "vault", AccountID: "account-1"}); err != nil {
			t.Fatal(err)
		}
	}

	page, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "session-pages", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.NextCursor == "" {
		t.Fatalf("first page = %+v", page)
	}
	second, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "session-pages", page.NextCursor, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != 1 || second.NextCursor != "" || second.Events[0].EventID == page.Events[0].EventID {
		t.Fatalf("second page = %+v", second)
	}

	empty, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "session-empty", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Events) != 0 {
		t.Fatalf("expected empty page, got %+v", empty)
	}
	if len(audit.events) != 3 {
		t.Fatalf("audit events = %d, want one per page including empty", len(audit.events))
	}
	for i, event := range audit.events {
		wantSession := "session-pages"
		if i == 2 {
			wantSession = "session-empty"
		}
		if event.action != application.AuditActionRead || event.actor != "user-1" || event.resourceID != wantSession || !event.success {
			t.Errorf("audit event %d = %+v", i, event)
		}
		if audit.details[i]["recording_kind"] != "video_events" {
			t.Errorf("audit details %d = %+v", i, audit.details[i])
		}
	}
	if authz.resource != "recording:session:session-empty" || authz.action != "recording:session:read" {
		t.Fatalf("authorization scope = %s %s", authz.resource, authz.action)
	}
}

func TestReadVideoEventsFailsClosedWhenAuditUnavailable(t *testing.T) {
	audit := &auditEmitter{err: errors.New("audit offline")}
	svc := newRecorder(t, &authorization{allowed: true}, audit, newObjectStore())
	writer, err := svc.BeginRecording(context.Background(), "session-audit")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "session-audit", "", 10); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("read without audit returned %v", err)
	}
}

func TestReadVideoEventsRejectsMalformedAndCrossSessionCursors(t *testing.T) {
	svc := newRecorder(t, &authorization{allowed: true}, &auditEmitter{}, newObjectStore())
	for _, sessionID := range []string{"cursor-a", "cursor-b"} {
		writer, err := svc.BeginRecording(context.Background(), sessionID)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if _, err := svc.RecordVideoEvent(context.Background(), domain.VideoRecordingEvent{EventID: "evt-" + sessionID, SessionID: sessionID, EventType: application.VideoEventSecretInjectionStarted, Protocol: "vnc", Source: "vault", AccountID: "account-1"}); err != nil {
			t.Fatal(err)
		}
		if sessionID == "cursor-a" {
			if _, err := svc.RecordVideoEvent(context.Background(), domain.VideoRecordingEvent{EventID: "evt-cursor-a-2", SessionID: sessionID, EventType: application.VideoEventSecretInjectionStarted, Protocol: "vnc", Source: "vault", AccountID: "account-1"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	page, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "cursor-a", "", 1)
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	if _, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "cursor-b", page.NextCursor, 1); !errors.Is(err, domain.ErrInvalidSegment) {
		t.Fatalf("cross-session cursor returned %v, want invalid cursor", err)
	}
	if _, err := svc.ReadVideoEvents(context.Background(), "user-1", []string{"auditor"}, "cursor-a", "not a cursor", 1); !errors.Is(err, domain.ErrInvalidSegment) {
		t.Fatalf("malformed cursor returned %v, want invalid cursor", err)
	}
}

func TestReadVideoEventsAuthorizationDenialIsAuditedAndFailsClosed(t *testing.T) {
	audit := &auditEmitter{}
	svc := newRecorder(t, &authorization{allowed: false}, audit, newObjectStore())
	writer, err := svc.BeginRecording(context.Background(), "session-denied")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := svc.ReadVideoEvents(context.Background(), "user-denied", []string{"viewer"}, "session-denied", "", 10); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("unauthorized event read returned %v", err)
	}
	if len(audit.events) != 1 || audit.events[0].success || audit.events[0].actor != "user-denied" {
		t.Fatalf("authorization refusal audit = %+v", audit.events)
	}
}

// ADR-0133: what a marker may be, a Vault secret's or an operator's password's, never its text.
func TestValidVideoEvent_AVaultSecretOrAnOperatorsPassword(t *testing.T) {
	vault := domain.VideoRecordingEvent{EventID: "e1", SessionID: "s1", EventType: application.VideoEventSecretInjectionStarted, Protocol: "rdp", Source: application.VideoEventSourceVault, AccountID: "a1"}
	paste := domain.VideoRecordingEvent{EventID: "e2", SessionID: "s1", EventType: application.VideoEventSecretPasteStarted, Protocol: "vnc", Source: application.VideoEventSourceOperator, AccountID: "a1",
		PasteBytes: 9, PasteSalt: strings.Repeat("0", 32), PasteSHA256: strings.Repeat("f", 64)}
	if !application.ValidVideoEvent(vault) || !application.ValidVideoEvent(paste) {
		t.Fatal("a valid marker refused")
	}
	for name, mutate := range map[string]func(*domain.VideoRecordingEvent){
		"a Vault marker with a size":      func(e *domain.VideoRecordingEvent) { *e = vault; e.PasteBytes = 1 },
		"a Vault marker with a salt":      func(e *domain.VideoRecordingEvent) { *e = vault; e.PasteSalt = strings.Repeat("0", 32) },
		"an operator marker of the Vault": func(e *domain.VideoRecordingEvent) { e.Source = application.VideoEventSourceVault },
		"no size":                         func(e *domain.VideoRecordingEvent) { e.PasteBytes = 0 },
		"513 bytes":                       func(e *domain.VideoRecordingEvent) { e.PasteBytes = 513 },
		"a short salt":                    func(e *domain.VideoRecordingEvent) { e.PasteSalt = strings.Repeat("0", 30) },
		"an upper-case fingerprint":       func(e *domain.VideoRecordingEvent) { e.PasteSHA256 = strings.Repeat("F", 64) },
		"the text as fingerprint":         func(e *domain.VideoRecordingEvent) { e.PasteSHA256 = "hunter22" },
		"another protocol":                func(e *domain.VideoRecordingEvent) { e.Protocol = "ssh" },
	} {
		event := paste
		mutate(&event)
		if application.ValidVideoEvent(event) {
			t.Errorf("%s accepted", name)
		}
	}
}

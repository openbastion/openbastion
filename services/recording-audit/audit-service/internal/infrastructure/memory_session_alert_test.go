package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

func TestInMemoryStore_AppendWithDetectionIsAtomicAndBounded(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStore()
	e := &domain.Event{ID: "evt_atomic", Action: "session.breakglass_requested"}
	if err := s.AppendWithDetection(ctx, e, "v1", 4096); err != nil {
		t.Fatal(err)
	}
	if len(s.events) != 1 || s.detectionOutbox[e.ID].CatalogVersion != "v1" {
		t.Fatalf("event/outbox not committed together: events=%d outbox=%v", len(s.events), s.detectionOutbox)
	}
	if err := s.DeleteThrough(ctx, e.ID, 1); err == nil {
		t.Fatal("archiving removed a source event whose detection is still pending")
	}
	if err := s.AppendWithDetection(ctx, e, "v1", 4096); err != nil {
		t.Fatal(err)
	}
	if len(s.events) != 1 {
		t.Fatalf("duplicate event appended %d times", len(s.events))
	}

	full := NewInMemoryStore()
	full.detectionOutbox = make(map[string]domain.AlertDetectionItem)
	for i := 0; i < 4096; i++ {
		id := fmt.Sprintf("evt_%d", i)
		full.detectionOutbox[id] = domain.AlertDetectionItem{SourceEventID: id, CatalogVersion: "v1"}
	}
	blocked := &domain.Event{ID: "evt_overflow"}
	if err := full.AppendWithDetection(ctx, blocked, "v1", 4096); !errors.Is(err, domain.ErrSessionAlertOutboxFull) {
		t.Fatalf("full outbox error = %v", err)
	}
	if len(full.events) != 0 {
		t.Fatalf("event was appended despite full outbox: %d", len(full.events))
	}
}

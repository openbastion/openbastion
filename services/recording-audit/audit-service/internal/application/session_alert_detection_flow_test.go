package application_test

import (
	"context"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

type detectionRecordingStore struct {
	*infrastructure.InMemoryStore
	catalogVersion string
	calls          int
}

func (s *detectionRecordingStore) AppendWithDetection(ctx context.Context, event *domain.Event, catalogVersion string) error {
	s.catalogVersion = catalogVersion
	s.calls++
	return s.InMemoryStore.AppendWithDetection(ctx, event, catalogVersion)
}

func TestEmitEvent_EnqueuesOnlyARecognizedAuthenticatedSource(t *testing.T) {
	store := &detectionRecordingStore{InMemoryStore: infrastructure.NewInMemoryStore()}
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEventAs(context.Background(), "session-broker", "operator-1", "session.breakglass_requested", "session", "session-1", true); err != nil {
		t.Fatal(err)
	}
	if store.catalogVersion != application.SessionAlertCatalogVersion {
		t.Fatalf("catalog version %q, want %q", store.catalogVersion, application.SessionAlertCatalogVersion)
	}
	if _, err := svc.EmitEventAs(context.Background(), "api-gateway", "operator-1", "session.breakglass_requested", "session", "session-2", true); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 {
		t.Fatalf("detection store called %d times, want exactly once for the recognized event", store.calls)
	}
}

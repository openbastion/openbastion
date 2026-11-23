package application_test

import (
	"context"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func TestSessionAlertRules_OnlyDeclaredAuthenticatedSignalsMatch(t *testing.T) {
	cases := []struct {
		name  string
		event domain.Event
		want  bool
	}{
		{"breakglass requested", domain.Event{Emitter: mtls.SessionBroker, Action: "session.breakglass_requested", ResourceType: "session", Success: false}, true},
		{"ssh injection failed", domain.Event{Emitter: mtls.SSHProxy, Action: "session.secret_injection_failed", ResourceType: "session", Success: false}, true},
		{"rdp vnc injection failed", domain.Event{Emitter: mtls.RDPVNCProxy, Action: "session.secret_injection_failed", ResourceType: "session", Success: false}, true},
		{"wrong emitter", domain.Event{Emitter: mtls.SessionBroker, Action: "session.secret_injection_failed", ResourceType: "session", Success: false}, false},
		{"successful injection", domain.Event{Emitter: mtls.SSHProxy, Action: "session.secret_injection_failed", ResourceType: "session", Success: true}, false},
		{"wrong resource", domain.Event{Emitter: mtls.SessionBroker, Action: "session.breakglass_requested", ResourceType: "account"}, false},
		{"unnamed emitter", domain.Event{Action: "session.breakglass_requested", ResourceType: "session"}, false},
		{"failed session read is not a unit alert", domain.Event{Emitter: mtls.SessionBroker, Action: "session.read", ResourceType: "session", Success: false}, false},
		{"unknown action", domain.Event{Emitter: mtls.SessionBroker, Action: "session.other", ResourceType: "session"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := application.MatchSessionAlert(&tc.event)
			if got != tc.want {
				t.Fatalf("match=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestSessionAlertDetection_EmitsProjectionAndSignedDetectionEvent(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEventAsWithDetails(ctx, mtls.SSHProxy, "operator-1", "session.secret_injection_failed", "session", "session-123", map[string]string{"protocol": "ssh"}, false); err != nil {
		t.Fatal(err)
	}
	if got := len(store.SessionAlerts()); got != 0 {
		t.Fatalf("alert visible before worker: %d", got)
	}
	processed, err := svc.ProcessSessionAlertDetections(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if processed != 1 {
		t.Fatalf("processed=%d, want 1", processed)
	}
	alerts := store.SessionAlerts()
	if len(alerts) != 1 {
		t.Fatalf("alerts=%d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.SessionID != "session-123" || a.Severity != domain.AlertHigh || a.Status != domain.AlertStatusUnacknowledged || a.Revision != 1 || a.SourceEventID == "" || a.RuleID == "" {
		t.Fatalf("unexpected alert projection: %+v", a)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("detection event must be in the signed chain: %v", err)
	}
	all, err := store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range all {
		if event.Action == "session.alert.detected" && event.Emitter == "audit-service" {
			found = true
			if event.Details["protocol"] != "" || len(event.Details) != 5 {
				t.Fatalf("detection event copied source details: %+v", event.Details)
			}
		}
	}
	if !found {
		t.Fatal("session.alert.detected not appended")
	}
	processed, err = svc.ProcessSessionAlertDetections(ctx, 10)
	if err != nil || processed != 0 || len(store.SessionAlerts()) != 1 {
		t.Fatalf("replay duplicated work: processed=%d err=%v alerts=%d", processed, err, len(store.SessionAlerts()))
	}
}

func TestSessionAlertDetection_OutboxFullRefusesSourceEventAtomically(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	first := &domain.Event{ID: "one"}
	if err := store.AppendWithDetection(context.Background(), first, application.SessionAlertCatalogVersion, 1); err != nil {
		t.Fatal(err)
	}
	before, _ := store.All(context.Background())
	if err := store.AppendWithDetection(context.Background(), &domain.Event{ID: "two"}, application.SessionAlertCatalogVersion, 1); err == nil {
		t.Fatal("full outbox accepted another source event")
	}
	after, _ := store.All(context.Background())
	if len(after) != len(before) || after[0].ID != "one" {
		t.Fatalf("source event appended despite full outbox: before=%d after=%d", len(before), len(after))
	}
}

func TestSessionAlertDetection_TwoWorkersCannotCreateDuplicateOccurrence(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	keys := application.RandomChainKeys()
	producer := application.NewAuditService(store).WithChainKeys(keys)
	if _, err := producer.EmitEventAs(ctx, mtls.SessionBroker, "operator-1", "session.breakglass_requested", "session", "session-race", false); err != nil {
		t.Fatal(err)
	}
	workers := []*application.AuditService{application.NewAuditService(store).WithChainKeys(keys), application.NewAuditService(store).WithChainKeys(keys)}
	var wg sync.WaitGroup
	errs := make(chan error, len(workers))
	for _, worker := range workers {
		wg.Add(1)
		go func(svc *application.AuditService) {
			defer wg.Done()
			_, err := svc.ProcessSessionAlertDetections(ctx, 10)
			errs <- err
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(store.SessionAlerts()); got != 1 {
		t.Fatalf("alerts=%d, want exactly one", got)
	}
	all, err := store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range all {
		if event.Action == "session.alert.detected" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("detection events=%d, want exactly one", count)
	}
}

func TestSessionAlertDetection_TamperedSourceIsNotProjected(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEventAs(ctx, mtls.SSHProxy, "operator-1", "session.secret_injection_failed", "session", "session-tampered", false); err != nil {
		t.Fatal(err)
	}
	events, err := store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	events[0].Action = "session.breakglass_requested" // mutate a signed source event
	processed, err := svc.ProcessSessionAlertDetections(ctx, 10)
	if err == nil || processed != 0 {
		t.Fatalf("tampered source processed=%d err=%v, want refusal", processed, err)
	}
	if got := len(store.SessionAlerts()); got != 0 {
		t.Fatalf("tampered source created %d alert(s)", got)
	}
}

func TestSessionAlertRules_CatalogueVersionIsPinned(t *testing.T) {
	event := &domain.Event{Emitter: mtls.SSHProxy, Action: "session.secret_injection_failed", ResourceType: "session", Success: false}
	rule, matched, err := application.MatchSessionAlertForVersion(event, "1")
	if err != nil || !matched || rule.Version != "1" {
		t.Fatalf("v1 match=%+v matched=%v err=%v", rule, matched, err)
	}
	if _, matched, err := application.MatchSessionAlertForVersion(event, "999"); err == nil || matched {
		t.Fatalf("unknown catalogue version matched=%v err=%v", matched, err)
	}
}

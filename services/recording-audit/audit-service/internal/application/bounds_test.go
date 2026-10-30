package application_test

// What the trail takes is bounded (ADR-0025): every event an emitter writes is taken, and
// what none can mean is refused before the chain is touched.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func TestEmitEvent_TakesWhatTheEmittersWrite_UpToTheBounds(t *testing.T) {
	svc := application.NewAuditService(infrastructure.NewInMemoryStore())
	for _, c := range []struct{ actor, action, typ, id string }{
		{"user_3f9a1c2b7d4e5f60", "session.breakglass_requested", "session", "session_0123456789abcdef"},
		{"", "session.recording_lost", "session", "s1"}, // a system action has no actor
		{"u_carol", "recording.read", "session", strings.Repeat("x", application.MaxIDBytes)},
		{strings.Repeat("a", application.MaxIDBytes), strings.Repeat("a", application.MaxNameBytes), strings.Repeat("t", application.MaxNameBytes), "é-ü"},
	} {
		if _, err := svc.EmitEvent(context.Background(), c.actor, c.action, c.typ, c.id, true); err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
	}
}

func TestEmitEvent_RefusesWhatNoEmitterCanMean_AndTheChainIsUntouched(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEvent(ctx, "u_1", "session.read", "session", "s1", true); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string][4]string{
		"resource id too long":     {"u_1", "session.read", "session", strings.Repeat("x", application.MaxIDBytes+1)},
		"actor too long":           {strings.Repeat("a", application.MaxIDBytes+1), "session.read", "session", "s1"},
		"no resource id":           {"u_1", "session.read", "session", ""},
		"newline in the id":        {"u_1", "session.read", "session", "s1\nforged"},
		"control byte in actor":    {"u_\x1b1", "session.read", "session", "s1"},
		"DEL in the id":            {"u_1", "session.read", "session", "s\x7f1"},
		"invalid UTF-8":            {"u_1", "session.read", "session", "s\xff1"},
		"no action":                {"u_1", "", "session", "s1"},
		"action too long":          {"u_1", strings.Repeat("a", application.MaxNameBytes+1), "session", "s1"},
		"action with a capital":    {"u_1", "Session.read", "session", "s1"},
		"action with a space":      {"u_1", "session read", "session", "s1"},
		"action with a dash":       {"u_1", "session-read", "session", "s1"},
		"no resource type":         {"u_1", "session.read", "", "s1"},
		"resource type with a dot": {"u_1", "session.read", "ses.sion", "s1"},
		"resource type too long":   {"u_1", "session.read", strings.Repeat("t", application.MaxNameBytes+1), "s1"},
	} {
		_, err := svc.EmitEvent(ctx, c[0], c[1], c[2], c[3], true)
		if !errors.Is(err, domain.ErrInvalidEvent) {
			t.Fatalf("%s: want ErrInvalidEvent, got %v", name, err)
		}
		for _, v := range []string{c[0], c[3]} {
			quoted := strings.Trim(strconv.Quote(v), `"`)
			if len(v) > 3 && (strings.Contains(err.Error(), v) || strings.Contains(err.Error(), quoted)) {
				t.Fatalf("%s: the error repeats the value: %v", name, err)
			}
		}
	}
	all, _ := store.All(ctx)
	if len(all) != 1 {
		t.Fatalf("%d event(s) in the chain, want the 1 valid one", len(all))
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatal(err)
	}
}

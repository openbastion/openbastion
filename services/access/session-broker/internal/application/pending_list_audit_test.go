package application_test

// Each request served in a listing of the requests that wait is on the record before it
// is served, and a listing that cannot be recorded is not served (ADR-0023).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// listedEvents is what the audit was told of requests served in a listing.
func (a *journalAudit) listedEvents() []auditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []auditRecord
	for _, e := range a.events {
		if e.action == application.AuditActionListed {
			out = append(out, e)
		}
	}
	return out
}

func (a *journalAudit) listedTypes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for i, e := range a.events {
		if e.action == application.AuditActionListed {
			out = append(out, a.types[i])
		}
	}
	return out
}

func TestListPendingAudit_EachRequestOnThePageServedIsAnEvent_AndOnlyThose(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.broker.WithMaxPendingPerRequester(100)
	var all []string
	for i := 0; i < 3; i++ {
		f.clock.advance(time.Second)
		all = append(all, f.request(t).ID)
	}

	items, total, _ := f.list(t, approver, 1, 2)
	if len(items) != 2 || total != 3 {
		t.Fatalf("page 1 of size 2: %v total %d", ids(items), total)
	}
	got := f.audit.listedEvents()
	want := []auditRecord{
		{action: "session.listed", success: true, actor: approver, resource: all[0]},
		{action: "session.listed", success: true, actor: approver, resource: all[1]},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("events %+v, want %+v — the third request, counted but not served, is not one", got, want)
	}
	for _, typ := range f.audit.listedTypes() {
		if typ != "session" {
			t.Fatalf("an event is about a %q, want a session", typ)
		}
	}
}

func TestListPendingAudit_EveryListingWritesAgain_ThereIsNoBudget(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.request(t)
	for i := 0; i < 25; i++ {
		if items, _, _ := f.list(t, approver, 1, 20); len(items) != 1 {
			t.Fatalf("listing %d: %v", i, ids(items))
		}
	}
	if n := len(f.audit.listedEvents()); n != 25 {
		t.Fatalf("%d event(s) for 25 listings of one request, want 25", n)
	}
}

// What discloses nothing writes nothing: no authority, a page past the end, the
// platform granting no break-glass.
func TestListPendingAudit_AnEmptyPageWritesNothing(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.request(t)

	none := newApprovalFixture(30, sessionRes, breakGlassRes) // nobody may approve
	none.request(t)
	if items, _, _ := none.list(t, approver, 1, 20); len(items) != 0 {
		t.Fatalf("no authority: %v", ids(items))
	}
	if items, _, _ := f.list(t, approver, 2, 20); len(items) != 0 {
		t.Fatalf("past the end: %v", ids(items))
	}
	off := newApprovalFixture(0, everything...)
	if items, _, _ := off.list(t, approver, 1, 20); len(items) != 0 {
		t.Fatalf("break-glass off: %v", ids(items))
	}
	for name, a := range map[string]*journalAudit{"no authority": none.audit, "past the end": f.audit, "break-glass off": off.audit} {
		if n := len(a.listedEvents()); n != 0 {
			t.Fatalf("%s: %d event(s) for an empty page", name, n)
		}
	}
}

func TestListPendingAudit_IsNotServedWithoutTheAudit_AndIsOnceItIsBack(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	f.audit.failOn = application.AuditActionListed

	items, total, truncated, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20)
	if !errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrForbidden) || items != nil || total != 0 || truncated {
		t.Fatalf("with the audit down: %v total=%d truncated=%v err=%v, want nothing served and unavailable", ids(items), total, truncated, err)
	}

	f.audit.stopFailing()
	if items, _, _ := f.list(t, approver, 1, 20); len(items) != 1 || items[0].ID != sess.ID {
		t.Fatalf("with the audit back: %v", ids(items))
	}
	if n := len(f.audit.listedEvents()); n != 1 {
		t.Fatalf("%d event(s): the listing that was not served must have left none", n)
	}
}

func TestListPendingAudit_AListingThatWasNotDecidedWritesNothing(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.request(t)
	f.authz.failOn = approveRes
	if _, _, _, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	if _, _, _, err := f.broker.ListPendingApprovals(context.Background(), "", []string{"lead"}, 1, 20); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: want forbidden, got %v", err)
	}
	if n := len(f.audit.listedEvents()); n != 0 {
		t.Fatalf("%d event(s) for listings that were not served", n)
	}
}

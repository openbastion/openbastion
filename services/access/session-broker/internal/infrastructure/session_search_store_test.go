package infrastructure_test

// ADR-0080: the search of sessions in each store. The text is a substring without case and
// without wildcards (% and _ are themselves); the window, the filters, the order (created_at, id)
// descending and the cursor hold — in memory and under PostgreSQL alike.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func runSessionSearchContract(t *testing.T, repo domain.SessionRepository) {
	t.Helper()
	ctx := context.Background()
	// A window of its own, far from what other tests write.
	base := time.Date(2001, 2, 3, 4, 0, 0, 0, time.UTC).Add(time.Duration(time.Now().UnixNano()%1_000_000) * time.Minute)
	run := fmt.Sprint(time.Now().UnixNano())
	save := func(id, justification, ticket, protocol string, breakGlass bool, at time.Time) {
		s := &domain.Session{ID: id + "-" + run, Status: domain.StatusTerminated, Protocol: protocol, RequestedBy: "u_" + run,
			PrivilegedAccountID: "acct-" + run, Justification: justification, Ticket: ticket, BreakGlass: breakGlass,
			CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
		if err := repo.Save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	save("pct", "disk at 100% on DB1", "", "ssh", false, base.Add(-1*time.Minute))
	save("plain", "disk at 1000 on db1", "", "vnc", true, base.Add(-2*time.Minute))
	save("ticket", "routine", "CHG-77", "ssh", false, base.Add(-3*time.Minute))
	save("same-a", "tie", "", "ssh", false, base.Add(-4*time.Minute))
	save("same-b", "tie", "", "ssh", false, base.Add(-4*time.Minute))
	save("outside", "disk at 100% on db1", "", "ssh", false, base.Add(-48*time.Hour))
	find := func(q domain.SessionSearch, limit int) []string {
		t.Helper()
		q.From, q.To = base.Add(-time.Hour), base
		got, err := repo.SearchSessions(ctx, q, limit)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range got {
			out = append(out, s.ID[:len(s.ID)-len(run)-1])
		}
		return out
	}
	for name, tc := range map[string]struct {
		q    domain.SessionSearch
		want string
	}{
		"% is not a wildcard": {domain.SessionSearch{Text: "100%"}, "[pct]"},
		"_ is not a wildcard": {domain.SessionSearch{Text: "db_"}, "[]"},
		"without case":        {domain.SessionSearch{Text: "DISK AT 100"}, "[pct plain]"},
		"in the ticket":       {domain.SessionSearch{Text: "chg-77"}, "[ticket]"},
		"in the requester":    {domain.SessionSearch{Text: "u_" + run}, "[pct plain ticket same-b same-a]"},
		"a protocol":          {domain.SessionSearch{Protocol: "vnc"}, "[plain]"},
		"break-glass":         {domain.SessionSearch{BreakGlass: ptr(true)}, "[plain]"},
		"the window and the most recent first, ties by id": {domain.SessionSearch{RequestedBy: "u_" + run}, "[pct plain ticket same-b same-a]"},
		"after a cursor": {domain.SessionSearch{RequestedBy: "u_" + run, After: &domain.SearchCursor{CreatedAt: base.Add(-4 * time.Minute), ID: "same-b-" + run}}, "[same-a]"},
	} {
		if got := fmt.Sprint(find(tc.q, 10)); got != tc.want {
			t.Fatalf("%s: %s, want %s", name, got, tc.want)
		}
	}
	if got := find(domain.SessionSearch{RequestedBy: "u_" + run}, 2); fmt.Sprint(got) != "[pct plain]" {
		t.Fatalf("limit 2: %v", got)
	}
}

func ptr[T any](v T) *T { return &v }

func TestInMemoryStore_SessionSearchContract(t *testing.T) {
	runSessionSearchContract(t, infrastructure.NewInMemoryStore())
}

func TestPostgresStore_SessionSearchContract(t *testing.T) {
	runSessionSearchContract(t, infrastructure.NewPostgresStore(testDB(t)))
}

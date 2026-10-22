package interfaces_test

// The listing of break-glass requests that wait (ADR-0012) over HTTP: what the
// approver is told, in what shape, and what is refused — with the same rule as the
// decision routes about a dependency's own error message.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

// onlyAsking allows the ordinary session and the request on acc1 — and no approval.
type onlyAsking struct{}

func (onlyAsking) CheckAccess(_ context.Context, _ []string, resource, _ string) (bool, string, error) {
	return resource == "vault:account:acc1" || resource == "breakglass:account:acc1", "", nil
}

// rolesSeen allows everything and notes the roles it was asked for.
type rolesSeen struct {
	mu    sync.Mutex
	roles [][]string
}

func (r *rolesSeen) CheckAccess(_ context.Context, roles []string, _, _ string) (bool, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles = append(r.roles, append([]string(nil), roles...))
	return true, "", nil
}

type listed struct {
	Items []struct {
		ID, Status, RequestedBy, Justification, PrivilegedAccountID string
		BreakGlass                                                  bool
		ExpiresAt                                                   string
	}
	Page, PageSize, TotalItems int
	Truncated                  bool
}

func get(t *testing.T, svc *application.SessionBrokerService, query string) (*listed, string, int) {
	t.Helper()
	rec := send(svc, http.MethodGet, "/sessions?"+query, "")
	var out listed
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("not JSON: %v: %s", err, rec.Body.String())
		}
	}
	return &out, rec.Body.String(), rec.Code
}

func TestListOverHTTP_TheApproverSeesWhatHeMayDecide_AndTheShapeIsThatOfTheOtherLists(t *testing.T) {
	svc := approvalService(allowAuthz{}, quietAudit{})
	id := requestOverHTTP(t, svc)

	out, raw, code := get(t, svc, "status=pending_approval&callerId=bob&actorRoles=lead")
	if code != http.StatusOK || len(out.Items) != 1 {
		t.Fatalf("%d %s", code, raw)
	}
	it := out.Items[0]
	if it.ID != id || it.Status != "pending_approval" || it.RequestedBy != "alice" || it.PrivilegedAccountID != "acc1" ||
		!it.BreakGlass || it.Justification == "" || it.ExpiresAt == "" {
		t.Fatalf("item = %+v: the approver decides on this, it has to be whole", it)
	}
	if out.Page != 1 || out.PageSize != 20 || out.TotalItems != 1 {
		t.Fatalf("paging = %d/%d/%d, want 1/20/1 like GET /vault/accounts", out.Page, out.PageSize, out.TotalItems)
	}
	if strings.Contains(raw, "truncated") {
		t.Fatalf("`truncated` appears only when it is true: %s", raw)
	}
}

func TestListOverHTTP_AnEmptyListIsAnEmptyArray_ForTheAuthorAndForWhoHasNoAuthority(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
	requestOverHTTP(t, svc) // alice's

	_, own, code := get(t, svc, "status=pending_approval&callerId=alice&actorRoles=lead")
	if code != http.StatusOK || !strings.Contains(own, `"items":[]`) || !strings.Contains(own, `"totalItems":0`) {
		t.Fatalf("the author: %d %s", code, own)
	}

	noAuthority := application.NewSessionBrokerService(store, onlyAsking{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
	_, stranger, code := get(t, noAuthority, "status=pending_approval&callerId=mallory&actorRoles=sre")
	if code != http.StatusOK || stranger != own {
		t.Fatalf("who has no authority gets %d %s, want exactly what the author gets (%s): the list must not say that requests exist", code, stranger, own)
	}
}

func TestListOverHTTP_RefusesWhatItDoesNotServe(t *testing.T) {
	svc := approvalService(allowAuthz{}, quietAudit{})
	requestOverHTTP(t, svc)
	for name, c := range map[string]struct {
		method, query string
		want          int
	}{
		"no status":                 {http.MethodGet, "callerId=bob", http.StatusBadRequest},
		"another status":            {http.MethodGet, "status=active&callerId=bob", http.StatusBadRequest},
		"a status in other letters": {http.MethodGet, "status=PENDING_APPROVAL&callerId=bob", http.StatusBadRequest},
		"nobody asking":             {http.MethodGet, "status=pending_approval", http.StatusForbidden},
		"an empty caller":           {http.MethodGet, "status=pending_approval&callerId=", http.StatusForbidden},
		"delete":                    {http.MethodDelete, "status=pending_approval&callerId=bob", http.StatusMethodNotAllowed},
		"put":                       {http.MethodPut, "status=pending_approval&callerId=bob", http.StatusMethodNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := send(svc, c.method, "/sessions?"+c.query, ""); rec.Code != c.want {
				t.Fatalf("%d %q, want %d", rec.Code, rec.Body.String(), c.want)
			}
		})
	}
}

func TestListOverHTTP_APageIsServedAsClamped_AndTheRolesAreSplitOnCommas(t *testing.T) {
	seen := &rolesSeen{}
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), seen, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
	for i := 0; i < 3; i++ {
		requestOverHTTP(t, svc)
	}

	out, _, _ := get(t, svc, "status=pending_approval&callerId=bob&actorRoles=lead,sre&pageSize=2&page=2")
	if len(out.Items) != 1 || out.Page != 2 || out.PageSize != 2 || out.TotalItems != 3 {
		t.Fatalf("page 2 of size 2 over 3: %d items, %d/%d/%d", len(out.Items), out.Page, out.PageSize, out.TotalItems)
	}
	out, _, _ = get(t, svc, "status=pending_approval&callerId=bob&pageSize=1000&page=abc")
	if out.Page != 1 || out.PageSize != 20 || len(out.Items) != 3 {
		t.Fatalf("garbage is served as the defaults: %d/%d, %d items", out.Page, out.PageSize, len(out.Items))
	}

	seen.mu.Lock()
	defer seen.mu.Unlock()
	foundBoth := false
	for _, r := range seen.roles {
		if len(r) == 2 && r[0] == "lead" && r[1] == "sre" {
			foundBoth = true
		}
	}
	if !foundBoth {
		t.Fatalf("actorRoles=lead,sre never reached the Authorization Service as two roles: %v", seen.roles)
	}
	// The last call had no actorRoles at all: it asked for no role, not for the empty one.
	if last := seen.roles[len(seen.roles)-1]; len(last) != 0 {
		t.Fatalf("a call with no actorRoles asked for the roles %q", last)
	}
}

func TestListOverHTTP_ADependencyFailureIsA503_WithoutItsMessage_ButInTheLog(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	store := infrastructure.NewInMemoryStore()
	good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
	requestOverHTTP(t, good)
	down := application.NewSessionBrokerService(store, downAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)

	rec := send(down, http.MethodGet, "/sessions?status=pending_approval&callerId=bob&actorRoles=lead", "")
	assertUnavailableWithoutLeak(t, rec)
	if !strings.Contains(logged.String(), "10.9.8.7") {
		t.Fatalf("the cause belongs in the Broker's log, and is not there: %q", logged.String())
	}
}

func TestListOverHTTP_SaysWhenTheListWasCut(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
	now := time.Now().UTC()
	for i := 0; i <= application.MaxPendingScanned; i++ { // one more than the bound
		err := store.Save(context.Background(), &domain.Session{
			ID: fmt.Sprintf("session_cut_%03d", i), Status: domain.StatusPendingApproval, Protocol: "ssh", RequestedBy: "alice",
			PrivilegedAccountID: "acc1", Justification: "recorder down", BreakGlass: true, CreatedAt: now,
			ExpiresAt: now.Add(10 * time.Minute), DurationMinutes: 20,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	out, raw, code := get(t, svc, "status=pending_approval&callerId=bob&actorRoles=lead&pageSize=100")
	if code != http.StatusOK || !out.Truncated || out.TotalItems != application.MaxPendingScanned || !strings.Contains(raw, `"truncated":true`) {
		t.Fatalf("%d %s: a list that was cut must say so", code, raw)
	}
}

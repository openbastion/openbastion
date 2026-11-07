package application_test

// ADR-0078: each OIDC provider keeps its issuer. Another issuer refuses the start; a change is
// declared from the exact issuer bound, and written to the audit before the binding changes.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

const issuerA, issuerB, issuerC = "https://idp-a.example", "https://idp-b.example", "https://idp-c.example"

type detailedEvent struct {
	action, resourceType, resourceID string
	details                          map[string]string
}

// detailedAudit is an audit that writes details, and that can be down.
type detailedAudit struct {
	fakeAudit
	mu       sync.Mutex
	detailed []detailedEvent
	// onWrite runs as an event is written: what the store holds at that moment.
	onWrite func()
}

func (a *detailedAudit) EmitEventWithDetails(_ context.Context, _, action, rt, rid string, details map[string]string, _ bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down {
		return errors.New("audit-service: connection refused")
	}
	if a.onWrite != nil {
		a.onWrite()
	}
	a.detailed = append(a.detailed, detailedEvent{action, rt, rid, details})
	return nil
}

func corp(issuer, previous string) application.IssuerDeclaration {
	return application.IssuerDeclaration{Provider: "corp", Issuer: issuer, PreviousIssuer: previous, Name: `oidc "corp"`, Declare: `oidc "corp": previous_issuer`}
}

func variables(issuer, previous string) application.IssuerDeclaration {
	return application.IssuerDeclaration{Provider: "", Issuer: issuer, PreviousIssuer: previous, Name: "OIDC_ISSUER", Declare: "OIDC_PREVIOUS_ISSUER"}
}

type issuerWorld struct {
	svc   *application.AuthenticationService
	store *infrastructure.InMemoryStore
	audit *detailedAudit
}

func newIssuerWorld(t *testing.T) *issuerWorld {
	t.Helper()
	w := &issuerWorld{svc: newTestService(t), store: infrastructure.NewInMemoryStore(), audit: &detailedAudit{}}
	w.svc.WithAudit(w.audit, nil)
	return w
}

func (w *issuerWorld) bind(t *testing.T, decls ...application.IssuerDeclaration) ([]application.IssuerOutcome, error) {
	t.Helper()
	return w.svc.BindIssuers(context.Background(), w.store, decls)
}

// boundTo reads what the store holds, without changing it.
func (w *issuerWorld) boundTo(t *testing.T, provider string) string {
	t.Helper()
	var issuer string
	err := w.store.BindIssuers(context.Background(), map[string]string{provider: "(none)"}, func(b map[string]domain.IssuerBinding) (map[string]string, error) {
		if b[provider].Created {
			return nil, errors.New("not bound")
		}
		issuer = b[provider].Issuer
		return nil, nil
	})
	if err != nil {
		return ""
	}
	return issuer
}

func TestBindIssuers_TheFirstStartBindsTheIssuer_TheSameIssuerChangesNothing(t *testing.T) {
	w := newIssuerWorld(t)
	out, err := w.bind(t, corp(issuerA, ""), variables(issuerB, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || !out[0].Created || !out[1].Created {
		t.Fatalf("outcomes %+v, want two bindings created", out)
	}
	if w.boundTo(t, "corp") != issuerA || w.boundTo(t, "") != issuerB {
		t.Fatalf("bound: corp=%q, variables=%q", w.boundTo(t, "corp"), w.boundTo(t, ""))
	}
	out, err = w.bind(t, corp(issuerA, ""), variables(issuerB, ""))
	if err != nil || out[0].Created || out[0].ReboundFrom != "" {
		t.Fatalf("the same issuers again: %+v %v, want nothing changed", out, err)
	}
	if len(w.audit.detailed) != 0 {
		t.Fatalf("a binding is not a change: nothing to write, got %+v", w.audit.detailed)
	}
}

func TestBindIssuers_AnotherIssuerUnderTheSameProvider_RefusesTheStart_ByEveryWay(t *testing.T) {
	for name, tc := range map[string]struct{ first, then application.IssuerDeclaration }{
		"the variables":              {variables(issuerA, ""), variables(issuerB, "")},
		"an entry of the file":       {corp(issuerA, ""), corp(issuerB, "")},
		"an entry that adopts their": {variables(issuerA, ""), application.IssuerDeclaration{Provider: "", Issuer: issuerB, Name: `oidc "other" (adopt_legacy_accounts)`, Declare: `oidc "other": previous_issuer`}},
	} {
		t.Run(name, func(t *testing.T) {
			w := newIssuerWorld(t)
			if _, err := w.bind(t, tc.first); err != nil {
				t.Fatal(err)
			}
			_, err := w.bind(t, tc.then)
			if !errors.Is(err, application.ErrIssuerChanged) {
				t.Fatalf("another issuer: %v, want ErrIssuerChanged", err)
			}
			for _, want := range []string{tc.then.Name, issuerA, issuerB, tc.then.Declare, "new id"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not say %q: %v", want, err)
				}
			}
			if got := w.boundTo(t, tc.first.Provider); got != issuerA {
				t.Fatalf("bound to %q after a refusal, want %q", got, issuerA)
			}
		})
	}
}

func TestBindIssuers_AChangeDeclaredFromTheIssuerBound_IsWrittenToTheAuditBeforeTheBindingChanges(t *testing.T) {
	w := newIssuerWorld(t)
	if _, err := w.bind(t, corp(issuerA, "")); err != nil {
		t.Fatal(err)
	}
	var boundWhenWritten string
	w.audit.onWrite = func() { boundWhenWritten = w.store.IssuerOf("corp") }
	out, err := w.bind(t, corp(issuerB, issuerA))
	if err != nil {
		t.Fatal(err)
	}
	if out[0].ReboundFrom != issuerA {
		t.Fatalf("outcome %+v, want a change from %s", out[0], issuerA)
	}
	if boundWhenWritten != issuerA {
		t.Fatalf("when the change was written, the binding was already %q: the audit comes first", boundWhenWritten)
	}
	if got := w.boundTo(t, "corp"); got != issuerB {
		t.Fatalf("bound to %q, want %q", got, issuerB)
	}
	want := detailedEvent{application.ActionIdentityProviderRebound, "identity_provider", "corp", map[string]string{"previous_issuer": issuerA, "issuer": issuerB}}
	if len(w.audit.detailed) != 1 || w.audit.detailed[0].action != want.action || w.audit.detailed[0].resourceID != want.resourceID ||
		w.audit.detailed[0].details["previous_issuer"] != issuerA || w.audit.detailed[0].details["issuer"] != issuerB {
		t.Fatalf("audit %+v, want %+v", w.audit.detailed, want)
	}
	// Once changed, the declaration is inert, and said to be removed.
	out, err = w.bind(t, corp(issuerB, issuerA))
	if err != nil || out[0].ReboundFrom != "" || !out[0].StalePrevious || len(w.audit.detailed) != 1 {
		t.Fatalf("the declaration kept: %+v %v, %d event(s); want inert and said", out, err, len(w.audit.detailed))
	}
}

func TestBindIssuers_TheProviderOfTheVariables_IsWrittenUnderAName(t *testing.T) {
	w := newIssuerWorld(t)
	_, _ = w.bind(t, variables(issuerA, ""))
	if _, err := w.bind(t, variables(issuerB, issuerA)); err != nil {
		t.Fatal(err)
	}
	if len(w.audit.detailed) != 1 || w.audit.detailed[0].resourceID != "(variables)" {
		t.Fatalf("audit %+v, want the resource (variables)", w.audit.detailed)
	}
}

func TestBindIssuers_AChangeDeclaredFromAnotherIssuer_IsRefused(t *testing.T) {
	w := newIssuerWorld(t)
	_, _ = w.bind(t, corp(issuerA, ""))
	_, err := w.bind(t, corp(issuerB, issuerC))
	if !errors.Is(err, application.ErrIssuerChanged) || !strings.Contains(err.Error(), issuerC) {
		t.Fatalf("a change from %s while bound to %s: %v, want ErrIssuerChanged naming it", issuerC, issuerA, err)
	}
	if w.boundTo(t, "corp") != issuerA || len(w.audit.detailed) != 0 {
		t.Fatalf("bound to %q, %d event(s): nothing may change", w.boundTo(t, "corp"), len(w.audit.detailed))
	}
}

func TestBindIssuers_TheAuditDown_ADeclaredChangeIsNotMade(t *testing.T) {
	w := newIssuerWorld(t)
	_, _ = w.bind(t, corp(issuerA, ""))
	w.audit.down = true
	_, err := w.bind(t, corp(issuerB, issuerA))
	if !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("the audit down: %v, want ErrAuditUnavailable", err)
	}
	if got := w.boundTo(t, "corp"); got != issuerA {
		t.Fatalf("bound to %q with the audit down, want %q", got, issuerA)
	}
}

func TestBindIssuers_AnAuditWithoutDetails_CannotWriteAChange_SoItIsNotMade(t *testing.T) {
	w := newIssuerWorld(t)
	w.svc.WithAudit(&fakeAudit{}, nil)
	_, _ = w.bind(t, corp(issuerA, ""))
	if _, err := w.bind(t, corp(issuerB, issuerA)); !errors.Is(err, application.ErrAuditUnavailable) || w.boundTo(t, "corp") != issuerA {
		t.Fatalf("no detailed audit: %v, bound to %q; want refused and unchanged", err, w.boundTo(t, "corp"))
	}
}

func TestBindIssuers_OneRefused_NothingIsRecorded_NorAnyChangeWritten(t *testing.T) {
	w := newIssuerWorld(t)
	_, _ = w.bind(t, corp(issuerA, ""), variables(issuerA, ""))
	newcomer := application.IssuerDeclaration{Provider: "newcomer", Issuer: issuerC, Name: `oidc "newcomer"`, Declare: `oidc "newcomer": previous_issuer`}
	// corp's change is declared and valid; the variables' is not: neither the change nor the newcomer stays.
	_, err := w.bind(t, corp(issuerB, issuerA), variables(issuerB, ""), newcomer)
	if !errors.Is(err, application.ErrIssuerChanged) {
		t.Fatalf("%v, want ErrIssuerChanged", err)
	}
	if w.boundTo(t, "corp") != issuerA || w.boundTo(t, "newcomer") != "" || len(w.audit.detailed) != 0 {
		t.Fatalf("corp=%q newcomer=%q, %d event(s): a refused start leaves nothing behind", w.boundTo(t, "corp"), w.boundTo(t, "newcomer"), len(w.audit.detailed))
	}
}

func TestBindIssuers_ARemovedIDComesBackWithAnotherIssuer_IsRefused(t *testing.T) {
	w := newIssuerWorld(t)
	_, _ = w.bind(t, corp(issuerA, ""))
	_, _ = w.bind(t, variables(issuerC, "")) // corp gone from the configuration
	if _, err := w.bind(t, corp(issuerB, "")); !errors.Is(err, application.ErrIssuerChanged) {
		t.Fatalf("corp back with another issuer: %v, want ErrIssuerChanged", err)
	}
}

func TestBindIssuers_TwoDeclarationsOfOneProvider_AreRefused(t *testing.T) {
	w := newIssuerWorld(t)
	if _, err := w.bind(t, variables(issuerA, ""), variables(issuerA, "")); err == nil {
		t.Fatal("the same provider declared twice was accepted")
	}
}

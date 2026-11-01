package infrastructure_test

// ADR-0043: CheckAccount tells an account that does not exist, one that is not pinned, and a
// Vault that fails — and reads only whether there is a pinned key.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func TestAccountLookup_CheckAccount(t *testing.T) {
	var approval bool
	check := func(status int, body string) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.EscapedPath() != "/vault/v1/accounts/acc%2F1" {
				t.Errorf("asked %s", r.URL.EscapedPath())
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		var err error
		approval, err = (&infrastructure.AccountLookupHTTPClient{BaseURL: srv.URL}).CheckAccount(context.Background(), "acc/1")
		return err
	}
	if err := check(http.StatusOK, `{"id":"acc/1","hostKeyFingerprint":"SHA256:k"}`); err != nil || approval {
		t.Fatalf("pinned: %v, approval %v", err, approval)
	}
	// ADR-0067: the account says whether a session on it waits for another person.
	if err := check(http.StatusOK, `{"id":"acc/1","hostKeyFingerprint":"SHA256:k","approvalRequired":true}`); err != nil || !approval {
		t.Fatalf("an account that requires approval: %v, approval %v", err, approval)
	}
	if err := check(http.StatusOK, `{"id":"acc/1","hostKeyFingerprint":""}`); !errors.Is(err, domain.ErrAccountNotPinned) {
		t.Fatalf("not pinned: %v", err)
	}
	if err := check(http.StatusNotFound, "account not found"); !errors.Is(err, domain.ErrAccountNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusForbidden, http.StatusInternalServerError} {
		if err := check(status, "x"); err == nil || errors.Is(err, domain.ErrAccountNotFound) || errors.Is(err, domain.ErrAccountNotPinned) {
			t.Fatalf("%d taken for a refusal: %v", status, err)
		}
	}
	if err := check(http.StatusOK, "not json"); err == nil || errors.Is(err, domain.ErrAccountNotPinned) {
		t.Fatalf("an unreadable answer: %v", err)
	}
}

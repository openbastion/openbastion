package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

// ADR-0044: the notice carries the end of the session; the Vault having it (200) or not having
// the account (404) clears the debt; anything else keeps it, to be sent again.
func TestVaultClient_RotateAfterUse(t *testing.T) {
	ended := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	notify := func(status int) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				AccountID, SessionID string
				EndedAt              time.Time
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.URL.Path != "/vault/v1/rotate-after-use" || body.AccountID != "acc" || body.SessionID != "s1" || !body.EndedAt.Equal(ended) {
				t.Errorf("told %s %+v", r.URL.Path, body)
			}
			w.WriteHeader(status)
		}))
		defer srv.Close()
		return (&infrastructure.VaultAuthorizationHTTPClient{BaseURL: srv.URL}).RotateAfterUse(context.Background(), "acc", "s1", ended)
	}
	for _, s := range []int{http.StatusOK, http.StatusNotFound} {
		if err := notify(s); err != nil {
			t.Fatalf("%d: %v", s, err)
		}
	}
	for _, s := range []int{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusBadRequest, http.StatusForbidden} {
		if err := notify(s); err == nil {
			t.Fatalf("%d cleared the debt", s)
		}
	}
}

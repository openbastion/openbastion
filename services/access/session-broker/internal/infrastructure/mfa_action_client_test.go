package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func TestMFAActionClient_RoundTrip(t *testing.T) {
	binding := infrastructure.MFAActionBinding{ActorUserID: "user-1", SessionID: "session-1", AccountID: "account-1", Protocol: "ssh", Action: "secret:inject"}
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("unexpected request metadata")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		ctx, ok := body["context"].(map[string]any)
		if !ok || ctx["actor_user_id"] != binding.ActorUserID {
			t.Errorf("actor binding missing: %#v", body["context"])
		}
		for key, want := range map[string]string{"session_id": binding.SessionID, "account_id": binding.AccountID, "protocol": binding.Protocol, "action": binding.Action} {
			if body[key] != want {
				t.Errorf("%s=%v, want %s", key, body[key], want)
			}
		}
		switch r.URL.Path {
		case "/auth/v1/internal/action-step-up/start":
			_, _ = w.Write([]byte(`{"challenge":"opaque-challenge","expires_in":120,"factors":["totp"]}`))
		case "/auth/v1/internal/action-step-up/verify":
			if body["challenge"] != "opaque-challenge" || body["factor"] != "totp" || body["totp_code"] != "123456" {
				t.Errorf("proof missing: %#v", body)
			}
			_, _ = w.Write([]byte(`{"grant":"opaque-grant","expires_in":30}`))
		case "/auth/v1/internal/action-step-up/consume":
			if body["grant"] != "opaque-grant" {
				t.Errorf("grant missing: %#v", body)
			}
			_, _ = w.Write([]byte(`{"consumed":true}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &infrastructure.MFAActionClient{BaseURL: server.URL, Client: server.Client()}
	started, err := client.Start(context.Background(), binding)
	if err != nil || started.Challenge != "opaque-challenge" || started.ExpiresIn != 120 || !reflect.DeepEqual(started.Factors, []string{"totp"}) {
		t.Fatalf("Start=%+v err=%v", started, err)
	}
	grant, err := client.Verify(context.Background(), binding, infrastructure.MFAActionProof{Challenge: started.Challenge, Factor: "totp", TOTPCode: "123456"})
	if err != nil || grant.Grant != "opaque-grant" || grant.ExpiresIn != 30 {
		t.Fatalf("Verify=%+v err=%v", grant, err)
	}
	if err := client.Consume(context.Background(), binding, grant.Grant); err != nil {
		t.Fatal(err)
	}
	want := []string{"/auth/v1/internal/action-step-up/start", "/auth/v1/internal/action-step-up/verify", "/auth/v1/internal/action-step-up/consume"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths=%v want=%v", paths, want)
	}
}

func TestMFAActionClient_RefusesUpstreamFailureWithoutLeakingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sensitive upstream diagnostic", http.StatusForbidden)
	}))
	defer server.Close()
	client := &infrastructure.MFAActionClient{BaseURL: server.URL, Client: server.Client()}
	_, err := client.Start(context.Background(), infrastructure.MFAActionBinding{ActorUserID: "u", SessionID: "s", AccountID: "a", Protocol: "ssh", Action: "secret:inject"})
	if err == nil || strings.Contains(err.Error(), "sensitive upstream diagnostic") {
		t.Fatalf("unsafe upstream failure: %v", err)
	}
}

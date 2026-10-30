package integration_test

// What the Audit Service accepts into the signed trail is bounded (ADR-0025), on a real process.
//
// Before ADR-0025 the Audit Service took any body of any size, and any value in any field: an
// emitter (or whoever holds an emitter's certificate) could append a megabyte, a newline that
// forges a line in a log, or an action name nobody emits, and it was hashed into the chain for
// good. This is that, written first and seen to fail.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAuditBounds_TheTrailTakesOnlyWhatAnEmitterCanMean_OnARealProcess(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-25")
	audit := startService(t, root, auditBin, "19421")

	emit := func(body []byte) (int, string) {
		t.Helper()
		resp, err := http.Post(audit.baseURL+"/audit/v1/emit-event", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	event := func(actor, action, typ, id string) []byte {
		raw, _ := json.Marshal(map[string]any{"actor_id": actor, "action": action, "resource_type": typ, "resource_id": id, "success": true})
		return raw
	}

	t.Run("every event the services emit today is taken", func(t *testing.T) {
		for _, action := range []string{
			"session.create", "session.breakglass_requested", "session.read", "session.listed", "session.terminate",
			"session.connect", "session.breakglass_approved", "session.breakglass_rejected", "session.recording_unavailable",
			"session.recording_lost", "session.breakglass", "session.expire", "session.revoked", "recording.read",
		} {
			for _, actor := range []string{"user_3f9a1c2b7d4e5f60", ""} {
				if code, text := emit(event(actor, action, "session", "session_0123456789abcdef")); code != http.StatusOK {
					t.Fatalf("%s by %q: %d %s", action, actor, code, text)
				}
			}
		}
		if code, text := emit(event("u_carol", "recording.read", "session", strings.Repeat("x", 256))); code != http.StatusOK {
			t.Fatalf("the longest session id the Recorder accepts: %d %s", code, text)
		}
	})

	t.Run("what no emitter can mean is refused, and the refusal does not repeat it", func(t *testing.T) {
		for name, body := range map[string][]byte{
			"a resource id of 257 bytes":       event("u_1", "recording.read", "session", strings.Repeat("x", 257)),
			"an actor of 257 bytes":            event(strings.Repeat("a", 257), "session.read", "session", "s1"),
			"a newline in the resource id":     event("u_1", "session.read", "session", "s1\nFORGED log line"),
			"a control byte in the actor":      event("u_1\x1b[31m", "session.read", "session", "s1"),
			"invalid UTF-8 in the resource id": []byte(`{"actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"s\xff1","success":true}`),
			"no action":                        event("u_1", "", "session", "s1"),
			"an action with a space":           event("u_1", "session read", "session", "s1"),
			"an action in capitals":            event("u_1", "Session.Read", "session", "s1"),
			"an action of 65 bytes":            event("u_1", strings.Repeat("a", 65), "session", "s1"),
			"no resource type":                 event("u_1", "session.read", "", "s1"),
			"a resource type with a slash":     event("u_1", "session.read", "session/x", "s1"),
			"no resource id":                   event("u_1", "session.read", "session", ""),
			"not JSON":                         []byte("not json FORGED"),
		} {
			code, text := emit(body)
			if code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s, want 400", name, code, text)
			}
			for _, echo := range []string{"FORGED", "xxxxxxxxxx", "aaaaaaaaaa", "\x1b"} {
				if strings.Contains(text, echo) {
					t.Fatalf("%s: the refusal repeats what was sent: %q", name, text)
				}
			}
		}
	})

	t.Run("a body larger than any event is refused before it is read whole", func(t *testing.T) {
		big := event("u_1", "session.read", "session", "s1")
		big = append(big[:len(big)-1], []byte(`,"padding":"`+strings.Repeat("p", 1<<20)+`"}`)...)
		if code, text := emit(big); code != http.StatusRequestEntityTooLarge {
			t.Fatalf("a 1 MiB body: %d %.200s, want 413", code, text)
		}
	})

	t.Run("an event is posted, not got", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/emit-event")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET emit-event: %d, want 405", resp.StatusCode)
		}
	})

	t.Run("the trail is still whole, and still takes events", func(t *testing.T) {
		if code, text := emit(event("u_1", "session.read", "session", "s1")); code != http.StatusOK {
			t.Fatalf("after the refusals: %d %s", code, text)
		}
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: %d", resp.StatusCode)
		}
	})
}

package interfaces

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/engine"
)

// Each clipboard direction the Broker granted rides the one-use ticket on its own field and
// reaches the Listener's metadata (ADR-0096 §1); absent means refused.
func TestEstablishSessionCarriesEachClipboardDirectionToTheSession(t *testing.T) {
	for _, c := range []struct{ to, from bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		s := testHTTPServer(readyGate{}).WithRDP(&engine.RDPCodec{TLSRoots: x509.NewCertPool()})
		w := httptest.NewRecorder()
		body := fmt.Sprintf(`{"session_id":"r1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60,"clipboard_to_target":%v,"clipboard_from_target":%v}`, c.to, c.from)
		s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("%+v: status=%d body=%s", c, w.Code, w.Body.String())
		}
		var out establishResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		pending, err := s.pending.Consume(out.ConnectionTicket, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		meta := screenMetadata(pending)
		if meta.ClipboardToTarget != c.to || meta.ClipboardFromTarget != c.from || meta.SessionID != "r1" {
			t.Fatalf("granted %+v, the session has to=%v from=%v", c, meta.ClipboardToTarget, meta.ClipboardFromTarget)
		}
	}
	// Absent fields are refused rights.
	s := testHTTPServer(readyGate{}).WithRDP(&engine.RDPCodec{TLSRoots: x509.NewCertPool()})
	w := httptest.NewRecorder()
	s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(`{"session_id":"r2","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60}`)))
	var out establishResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	pending, err := s.pending.Consume(out.ConnectionTicket, time.Now().UTC())
	if err != nil || pending.ClipboardToTarget || pending.ClipboardFromTarget {
		t.Fatalf("absent rights: %+v err=%v", pending, err)
	}
}

// Only RDP has a clipboard channel: a VNC request carrying either right is refused before any
// ticket, as a Broker that got something wrong (ADR-0096).
func TestEstablishSessionRefusesAClipboardRightOutsideRDP(t *testing.T) {
	for _, field := range []string{"clipboard_to_target", "clipboard_from_target"} {
		s := testHTTPServer(readyGate{})
		w := httptest.NewRecorder()
		body := `{"session_id":"v1","vault_scope_token":"scope","protocol":"vnc","ttl_seconds":60,"` + field + `":true}`
		s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "connection_ticket") {
			t.Fatalf("VNC with %s: status=%d body=%s", field, w.Code, w.Body.String())
		}
	}
}

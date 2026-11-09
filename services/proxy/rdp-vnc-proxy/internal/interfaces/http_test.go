package interfaces

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/engine"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

type readyGate struct{ err error }

func (g readyGate) Ready(context.Context) error { return g.err }

type noopAudit struct{}

func (noopAudit) EmitEvent(context.Context, string, string, string, bool) error { return nil }

func testHTTPServer(gate readyGate) *HTTPServer {
	return &HTTPServer{pending: infrastructure.NewPendingScreenSessions(), listener: proxycore.NewListener(nil, proxycore.NewTerminator(noopAudit{})), gate: gate, endpoint: "rdp-vnc-proxy:8090"}
}
func TestEstablishSessionIssuesOneUseVNCOnlyTicket(t *testing.T) {
	s := testHTTPServer(readyGate{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(`{"session_id":"s1","vault_scope_token":"scope-secret","protocol":"vnc","ttl_seconds":60}`))
	s.establish(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out establishResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ProxyEndpoint != "rdp-vnc-proxy:8090" || out.ConnectionTicket == "" || strings.Contains(w.Body.String(), "scope-secret") {
		t.Fatalf("unsafe response: %#v %s", out, w.Body.String())
	}
	pending, err := s.pending.Consume(out.ConnectionTicket, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if pending.SessionID != "s1" || pending.ScopeToken != "scope-secret" || pending.Protocol != screenstream.ProtocolVNC {
		t.Fatalf("pending=%#v", pending)
	}
	if _, err := s.pending.Consume(out.ConnectionTicket, time.Now().UTC()); err == nil {
		t.Fatal("proxy ticket was reusable")
	}
}
func TestEstablishSessionRefusesRDPAndRecorderOutageBeforeTicket(t *testing.T) {
	s := testHTTPServer(readyGate{})
	w := httptest.NewRecorder()
	s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(`{"session_id":"s1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60}`)))
	if w.Code != http.StatusConflict {
		t.Fatalf("RDP status=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.gate = readyGate{err: context.DeadlineExceeded}
	s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(`{"session_id":"s2","vault_scope_token":"scope","protocol":"vnc","ttl_seconds":60}`)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("recorder outage status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := s.pending.Consume("scope", time.Now()); err == nil {
		t.Fatal("recorder outage must not issue a ticket")
	}
}

// RDP on (ADR-0088): the ticket carries the RDP protocol, which the screen route reads to pick the
// codec; the request's protocol never picks it.
func TestEstablishSessionIssuesAnRDPTicketWhenRDPIsOn(t *testing.T) {
	s := testHTTPServer(readyGate{}).WithRDP(&engine.RDPCodec{TLSRoots: x509.NewCertPool()})
	w := httptest.NewRecorder()
	s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(`{"session_id":"r1","vault_scope_token":"scope","protocol":"rdp","ttl_seconds":60}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out establishResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	pending, err := s.pending.Consume(out.ConnectionTicket, time.Now().UTC())
	if err != nil || pending.Protocol != screenstream.ProtocolRDP {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	w = httptest.NewRecorder()
	s.establish(w, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(`{"session_id":"r2","vault_scope_token":"scope","protocol":"spice","ttl_seconds":60}`)))
	if w.Code != http.StatusConflict {
		t.Fatalf("an unknown protocol: status=%d", w.Code)
	}
}

// An RDP ticket on a proxy without RDP (switched off after the ticket, or never on) ends at once,
// before any target is dialed.
func TestScreenRefusesAnRDPTicketWithoutTheRDPCodec(t *testing.T) {
	s := testHTTPServer(readyGate{})
	s.codec = &engine.VNCCodec{TLSRoots: x509.NewCertPool()}
	s.recorder = &infrastructure.VideoRecorderClient{}
	ticket, err := s.pending.Register(infrastructure.PendingScreenSession{SessionID: "r1", ScopeToken: "scope", Protocol: screenstream.ProtocolRDP, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(s.screen))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		Subprotocols: []string{screenSubprotocol}, HTTPHeader: http.Header{"Authorization": {"Bearer " + ticket}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := screenstream.Decode(data)
	if err != nil || m.Type != screenstream.TypeEnd || m.EndCode != screenstream.EndCodeTicketInvalid {
		t.Fatalf("%+v %v, want END ticket_invalid", m, err)
	}
}

func TestScreenRejectsInvalidProxyTicketWithStableEndCode(t *testing.T) {
	s := testHTTPServer(readyGate{})
	s.codec = &engine.VNCCodec{TLSRoots: x509.NewCertPool()}
	s.recorder = &infrastructure.VideoRecorderClient{}
	server := httptest.NewServer(http.HandlerFunc(s.screen))
	defer server.Close()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/internal/v1/screen"
	headers := http.Header{}
	headers.Set("Authorization", "Bearer invalid-ticket")
	conn, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPHeader: headers, Subprotocols: []string{screenSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test done")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("message type=%v", typ)
	}
	msg, err := screenstream.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != screenstream.TypeEnd || msg.EndCode != screenstream.EndCodeTicketInvalid || msg.Text != "ticket_invalid" {
		t.Fatalf("invalid-ticket END=%#v", msg)
	}
}

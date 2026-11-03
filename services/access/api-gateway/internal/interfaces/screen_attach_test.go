package interfaces

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

type unusedScreenDialer struct{}

func (unusedScreenDialer) Dial(context.Context, string, string) (*websocket.Conn, error) {
	return nil, nil
}

func TestConnectVNC_HidesProxyTicketBehindOneUseHttpOnlyCookie(t *testing.T) {
	expires := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["callerId"] != "operator-1" {
			t.Errorf("caller=%q", body["callerId"])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"proxyEndpoint": "rdp-vnc-proxy:8090", "ticket": "secret-ticket-never-returned", "protocol": "vnc", "expiresAt": expires})
	}))
	defer broker.Close()
	g := NewGatewayServer(nil, nil, nil, "", "", "", "", "").WithScreenAttach(unusedScreenDialer{}, false)
	r := httptest.NewRequest(http.MethodPost, "/sessions/session-1/connect", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	g.handleConnectAction(w, r, broker.URL, "session-1", "operator-1")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v", cookies)
	}
	c := cookies[0]
	if c.Name != "ob_screen_attach" || !c.HttpOnly || c.Secure || c.Path != "/sessions/session-1/screen" || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe attach cookie: %#v", c)
	}
	if strings.Contains(w.Body.String(), "secret-ticket-never-returned") || strings.Contains(w.Body.String(), "rdp-vnc-proxy:8090") {
		t.Fatalf("ticket/endpoint leaked to browser: %s", w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["protocol"] != "vnc" || response["attach"] != "/sessions/session-1/screen" {
		t.Fatalf("response=%v", response)
	}
	attach, err := g.screenAttaches.Consume(c.Value, "session-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if attach.Ticket != "secret-ticket-never-returned" || attach.Endpoint != "rdp-vnc-proxy:8090" {
		t.Fatalf("stored attach=%#v", attach)
	}
	if _, err := g.screenAttaches.Consume(c.Value, "session-1", time.Now()); err == nil {
		t.Fatal("attach cookie was reusable")
	}
}

func TestConnectVNC_FailsClosedWhenAttachRelayIsNotConfigured(t *testing.T) {
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"proxyEndpoint":"proxy:8090","ticket":"secret","protocol":"vnc","expiresAt":"2099-01-01T00:00:00Z"}`))
	}))
	defer broker.Close()
	g := NewGatewayServer(nil, nil, nil, "", "", "", "", "")
	w := httptest.NewRecorder()
	g.handleConnectAction(w, httptest.NewRequest(http.MethodPost, "/connect", strings.NewReader("{}")), broker.URL, "s", "u")
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func newWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"openbastion.screen.v1"}})
		if err != nil {
			return
		}
		accepted <- conn
	}))
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	client, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{Subprotocols: []string{"openbastion.screen.v1"}})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var peer *websocket.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		client.Close(websocket.StatusInternalError, "timeout")
		server.Close()
		t.Fatal("WebSocket peer was not accepted")
	}
	cleanup := func() {
		_ = client.Close(websocket.StatusNormalClosure, "test cleanup")
		_ = peer.Close(websocket.StatusNormalClosure, "test cleanup")
		server.Close()
	}
	return client, peer, cleanup
}

func TestRelayScreenWebSocketsRelaysValidatedBinaryMessagesBothWays(t *testing.T) {
	browserClient, gatewayClient, cleanupBrowser := newWebSocketPair(t)
	defer cleanupBrowser()
	proxyClient, proxyServer, cleanupProxy := newWebSocketPair(t)
	defer cleanupProxy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relayScreenWebSockets(ctx, gatewayClient, proxyClient) }()
	input, err := screenstream.EncodeInput(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61})
	if err != nil {
		t.Fatal(err)
	}
	if err := browserClient.Write(ctx, websocket.MessageBinary, input); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	defer readCancel()
	typ, gotInput, err := proxyServer.Read(readCtx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageBinary || string(gotInput) != string(input) {
		t.Fatalf("relayed input type=%v data=%x, want %x", typ, gotInput, input)
	}
	hello := screenstream.Message{Type: screenstream.TypeHello, Sequence: 0, Timestamp: time.Now().UTC(), Protocol: screenstream.ProtocolVNC, ExpiresAt: time.Now().Add(time.Minute).UTC(), SessionID: "s1"}
	frame, err := screenstream.Encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxyServer.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
	typ, gotFrame, err := browserClient.Read(readCtx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("relayed frame type=%v", typ)
	}
	decoded, err := screenstream.Decode(gotFrame)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != screenstream.TypeHello || decoded.SessionID != "s1" {
		t.Fatalf("relayed frame=%#v", decoded)
	}
	cancel()
	_ = browserClient.Close(websocket.StatusNormalClosure, "done")
	_ = proxyServer.Close(websocket.StatusNormalClosure, "done")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after connection close")
	}
}

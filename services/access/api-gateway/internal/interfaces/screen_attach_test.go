package interfaces

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/screenstream"
	gatewayinfra "github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
)

type unusedScreenDialer struct{}

func (unusedScreenDialer) Dial(context.Context, string, string) (*websocket.Conn, error) {
	return nil, nil
}

// VNC, and RDP since ADR-0088: a screen ticket never reaches the browser.
func TestConnectVNC_HidesProxyTicketBehindOneUseHttpOnlyCookie(t *testing.T) {
	for _, protocol := range []string{"vnc", "rdp"} {
		t.Run(protocol, func(t *testing.T) { testScreenTicketHidden(t, protocol) })
	}
}

func testScreenTicketHidden(t *testing.T, protocol string) {
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
		_ = json.NewEncoder(w).Encode(map[string]any{"proxyEndpoint": "rdp-vnc-proxy:8090", "ticket": "secret-ticket-never-returned", "protocol": protocol, "expiresAt": expires})
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
	if response["protocol"] != protocol || response["attach"] != "/sessions/session-1/screen" {
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

// The cookie is what attaches a session. A page of another site must not be able to spend it,
// and a refused upgrade must leave it to its owner.
func TestScreenAttach_RefusesAnotherOriginWithoutSpendingTheCookie(t *testing.T) {
	dial := func(url, origin, cookie string) (*websocket.Conn, int, error) {
		headers := http.Header{"Cookie": {"ob_screen_attach=" + cookie}}
		if origin != "" {
			headers.Set("Origin", origin)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: headers, Subprotocols: []string{"openbastion.screen.v1"}})
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return conn, status, err
	}
	register := func(t *testing.T, g *GatewayServer) string {
		t.Helper()
		token, err := g.screenAttaches.Register(gatewayinfra.ScreenAttach{SessionID: "s1", UserID: "u1", Endpoint: "proxy:8090", Ticket: "ticket", ExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	serve := func(t *testing.T, g *GatewayServer) string {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.handleScreenAttach(w, r, "s1") }))
		t.Cleanup(srv.Close)
		return "ws" + strings.TrimPrefix(srv.URL, "http")
	}

	dialer := &countingScreenDialer{}
	g := NewGatewayServer(nil, nil, nil, "", "", "", "", "").WithScreenAttach(dialer, false)
	url := serve(t, g)
	token := register(t, g)
	if conn, status, err := dial(url, "https://evil.example", token); err == nil || status != http.StatusForbidden {
		if conn != nil {
			conn.Close(websocket.StatusNormalClosure, "")
		}
		t.Fatalf("another origin: status %d, err %v", status, err)
	}
	if dialer.calls() != 0 {
		t.Fatal("the proxy was reached for another origin")
	}
	// The cookie survived: its owner still attaches.
	conn, _, err := dial(url, strings.Replace(url, "ws://", "http://", 1), token)
	if err != nil {
		t.Fatalf("same origin refused: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	waitForDial(t, dialer, 1)

	// Named, an origin passes; nothing else does.
	dialer2 := &countingScreenDialer{}
	g2 := NewGatewayServer(nil, nil, nil, "", "", "", "", "").WithScreenAttach(dialer2, false).WithScreenOrigins([]string{"*.preview.example"})
	url2 := serve(t, g2)
	token2 := register(t, g2)
	if conn, status, err := dial(url2, "https://evil.example", token2); err == nil || status != http.StatusForbidden {
		if conn != nil {
			conn.Close(websocket.StatusNormalClosure, "")
		}
		t.Fatalf("an origin not named: status %d, err %v", status, err)
	}
	conn2, _, err := dial(url2, "https://3000-abc.preview.example", token2)
	if err != nil {
		t.Fatalf("a named origin refused: %v", err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")
	waitForDial(t, dialer2, 1)
}

type countingScreenDialer struct {
	mu sync.Mutex
	n  int
}

func (d *countingScreenDialer) Dial(context.Context, string, string) (*websocket.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n++
	return nil, errors.New("no proxy in this test")
}

func (d *countingScreenDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}

func waitForDial(t *testing.T, d *countingScreenDialer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for d.calls() != want {
		if time.Now().After(deadline) {
			t.Fatalf("proxy dialled %d times, want %d", d.calls(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// What a client sends goes on only if the proxy would read it (ADR-0096 §6): a 16-byte input or a
// clipboard text, each decoded; nothing else.
func TestValidScreenInput(t *testing.T) {
	key, _ := screenstream.EncodeInput(screenstream.InputEvent{Type: screenstream.InputKey, Flags: screenstream.KeyPressed, Keysym: 0x61})
	clip, _ := screenstream.EncodeClipboardInput("pasted é €")
	malformed := append([]byte(nil), clip...)
	malformed[2] = 1
	short := append([]byte(nil), clip[:len(clip)-1]...)
	for name, c := range map[string]struct {
		data []byte
		ok   bool
	}{
		"a key":                       {key, true},
		"a clipboard text":            {clip, true},
		"a clipboard text, malformed": {malformed, false},
		"a clipboard text, truncated": {short, false},
		"17 bytes":                    {append(append([]byte(nil), key...), 0), false},
		"an unknown 16-byte input":    {append([]byte{1, 9}, key[2:]...), false},
	} {
		if err := validScreenInput(c.data); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A clipboard text crosses the relay as it was sent.
func TestRelayScreenWebSocketsRelaysAClipboardText(t *testing.T) {
	browserClient, gatewayClient, cleanupBrowser := newWebSocketPair(t)
	defer cleanupBrowser()
	proxyClient, proxyServer, cleanupProxy := newWebSocketPair(t)
	defer cleanupProxy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = relayScreenWebSockets(ctx, gatewayClient, proxyClient) }()
	clip, err := screenstream.EncodeClipboardInput("pasted é €")
	if err != nil {
		t.Fatal(err)
	}
	if err := browserClient.Write(ctx, websocket.MessageBinary, clip); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	defer readCancel()
	if _, got, err := proxyServer.Read(readCtx); err != nil || string(got) != string(clip) {
		t.Fatalf("relayed %x, %v", got, err)
	}
}

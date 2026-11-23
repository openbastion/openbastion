package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// gatedTCPRelay forwards the real TigerVNC TLS stream until its independent X11
// oracle observes a keypress. It then holds the remaining encrypted bytes in
// user space until the proxy closes the session connection; queued bytes are
// discarded instead of being delivered after revocation.
type gatedTCPRelay struct {
	address  string
	upstream string
	keyCount func() int
	baseline int

	pause      chan struct{}
	paused     chan struct{}
	pauseOnce  sync.Once
	pausedOnce sync.Once

	mu      sync.Mutex
	open    int
	pending atomic.Int64
}

func newGatedTCPRelay(t *testing.T, upstream string, baseline int, keyCount func() int) *gatedTCPRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &gatedTCPRelay{
		address: listener.Addr().String(), upstream: upstream, baseline: baseline, keyCount: keyCount,
		pause: make(chan struct{}), paused: make(chan struct{}),
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.open++
			r.mu.Unlock()
			go r.serve(client)
		}
	}()
	return r
}

func (r *gatedTCPRelay) serve(client net.Conn) {
	defer func() {
		_ = client.Close()
		r.mu.Lock()
		r.open--
		r.mu.Unlock()
	}()
	target, err := net.Dial("tcp", r.upstream)
	if err != nil {
		return
	}
	defer target.Close()

	// Read continuously while forwarding is paused. This lets the relay observe
	// the proxy's close, then discard bytes that were never delivered to TigerVNC.
	chunks := make(chan []byte, 128)
	sourceDone := make(chan struct{})
	stopReader := make(chan struct{})
	defer close(stopReader)
	go func() {
		defer close(sourceDone)
		defer close(chunks)
		buf := make([]byte, 64)
		for {
			n, readErr := client.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				r.pending.Add(int64(n))
				select {
				case chunks <- chunk: // small chunks let the independent X11 oracle gate mid-stream
				case <-stopReader:
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	go func() { _, _ = io.Copy(client, target) }()

	paused := false
	for {
		if !paused {
			select {
			case <-r.pause:
				paused = true
				r.pausedOnce.Do(func() { close(r.paused) })
				continue
			default:
			}
		}
		if paused {
			<-sourceDone
			return // proxy closed the session; never drain queued keystrokes
		}
		select {
		case <-r.pause:
			paused = true
			r.pausedOnce.Do(func() { close(r.paused) })
		case chunk, ok := <-chunks:
			if !ok {
				return
			}
			if err := writeRelayFull(target, chunk); err != nil {
				return
			}
			r.pending.Add(-int64(len(chunk)))
			// A short pacing interval lets TigerVNC and xev process the complete
			// TLS record before the next record is forwarded.
			time.Sleep(25 * time.Millisecond)
			if r.keyCount() > r.baseline {
				r.pauseOnce.Do(func() { close(r.pause) })
			}
		}
	}
}

func writeRelayFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (r *gatedTCPRelay) waitPaused(t *testing.T) {
	t.Helper()
	select {
	case <-r.paused:
	case <-time.After(15 * time.Second):
		t.Fatal("the real TigerVNC target did not receive a keypress before the relay gate")
	}
}

func (r *gatedTCPRelay) pendingBytes() int64 { return r.pending.Load() }

func (r *gatedTCPRelay) openConnections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.open
}

func waitForStableTargetKeys(t *testing.T, target *realVNCTarget, stableFor time.Duration) []uint32 {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	last := target.keySequence()
	stableSince := time.Now()
	for {
		select {
		case <-deadline.C:
			t.Fatal("the real X11 key sequence did not become stable before revocation")
		case <-ticker.C:
			current := target.keySequence()
			if fmt.Sprint(current) != fmt.Sprint(last) {
				last = current
				stableSince = time.Now()
				continue
			}
			if time.Since(stableSince) >= stableFor {
				return current
			}
		}
	}
}

// testScreenVaultSecretInjectionRevokedDuringRealTyping proves the cut against
// TigerVNC itself: xev observes a prefix of the actual key events, the relay
// holds the remaining TLS records, and DELETE must close the proxy stream before
// any held event can reach the target.
func testScreenVaultSecretInjectionRevokedDuringRealTyping(
	t *testing.T,
	gatewayURL string,
	api screenAPI,
	mfa *mfaStepUpCredentials,
	target *realVNCTarget,
	accountID string,
	audit *screenAuditSpy,
	relay *gatedTCPRelay,
) *mfaStepUpCredentials {
	t.Helper()
	if mfa == nil || target == nil || relay == nil {
		t.Fatal("SI-02 requires an enrolled step-up identity, real TigerVNC target and gated relay")
	}
	// The session requester must be the enrolled step-up identity: its verified
	// roles carry the exact account and injection policies used by this scenario.
	actorToken := mfa.token
	const secretLength = 128
	if len(target.password) != secretLength {
		t.Fatalf("real target password length = %d, want %d for the deterministic in-flight RFB input", len(target.password), secretLength)
	}

	status, raw := api.in(t).call(actorToken, http.MethodPost, "/sessions", map[string]any{
		"targetAccountId": accountID, "protocol": "vnc", "justification": "SI-02 revoke during real keystroke", "durationMinutes": 10,
	})
	if status != http.StatusCreated {
		t.Fatalf("create SI-02 VNC session: %d %s", status, raw)
	}
	sessionID := jsonField(t, raw, "id")
	revoked := false
	defer func() {
		if !revoked {
			_, _ = api.in(t).call(actorToken, http.MethodDelete, "/sessions/"+sessionID, nil)
		}
	}()

	attach := api.in(t).connect(actorToken, sessionID)
	conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	if hello := readScreen(t, conn); hello.kind != 2 || hello.helloSession != sessionID {
		t.Fatalf("SI-02 screen did not become active: %+v", hello)
	}
	_ = readFrame(t, conn)

	step := mfa.step + 1
	waitForTOTPStep(t, step)
	status, raw = api.in(t).call(actorToken, http.MethodPost, "/sessions/"+sessionID+"/secret-injection-step-up", nil)
	if status != http.StatusOK {
		t.Fatalf("SI-02 step-up: %d %s", status, raw)
	}
	challenge := jsonField(t, raw, "challenge")
	proof, err := json.Marshal(map[string]string{
		"challenge": challenge, "factor": "totp",
		"totp_code": totpCode(t, mfa.totpSecret, time.Unix(step*30+1, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, gatewayURL+"/sessions/"+sessionID+"/secret-injection", bytes.NewReader(proof))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+actorToken)
	request.Header.Set("Content-Type", "application/json")
	type injectionResult struct {
		status int
		body   string
		err    error
	}
	injected := make(chan injectionResult, 1)
	go func() {
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			injected <- injectionResult{err: requestErr}
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		injected <- injectionResult{status: response.StatusCode, body: string(body)}
	}()

	relay.waitPaused(t)
	// The proxy has accepted the write into its transport; the target has only
	// processed a prefix. Revocation must close the stream and discard the rest.
	select {
	case result := <-injected:
		if result.err != nil || result.status != http.StatusNoContent || result.body != "" {
			t.Fatalf("SI-02 injection before concurrent revoke: status=%d body=%q err=%v", result.status, result.body, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the injection request did not finish while the target was receiving the real key stream")
	}
	mfa.step = step
	waitUntil(t, 2*time.Second, "the relay to buffer the remaining encrypted key events", func() bool {
		return relay.pendingBytes() > 0
	})
	prefix := waitForStableTargetKeys(t, target, 100*time.Millisecond)
	if len(prefix) <= relay.baseline || len(prefix) >= relay.baseline+secretLength {
		t.Fatalf("the real target did not stop part-way through the secret: received %d new keypresses", len(prefix)-relay.baseline)
	}
	want := make([]uint32, 0, secretLength)
	for _, r := range target.password {
		want = append(want, uint32(r))
	}
	receivedPrefix := prefix[relay.baseline:]
	if fmt.Sprint(receivedPrefix) != fmt.Sprint(want[:len(receivedPrefix)]) {
		t.Fatalf("the real target received keysym prefix %v, want %v", receivedPrefix, want[:len(receivedPrefix)])
	}

	status, body := api.in(t).call(actorToken, http.MethodDelete, "/sessions/"+sessionID, nil)
	if status/100 != 2 {
		t.Fatalf("revoke during real key stream: %d %s", status, body)
	}
	revoked = true
	waitUntil(t, 5*time.Second, "the proxy-to-target relay to close after revocation", func() bool {
		return relay.openConnections() == 0
	})
	afterAck := target.keySequence()
	if len(afterAck) < len(prefix) || len(afterAck) >= relay.baseline+secretLength {
		t.Fatalf("target keypress count after revoke acknowledgement = %d (prefix before revoke %d, baseline %d, full secret %d)", len(afterAck), len(prefix), relay.baseline, secretLength)
	}
	if !audit.saw("session.secret_injected", sessionID) {
		t.Fatal("the real-target injection has no terminal audit event")
	}
	deadline := time.NewTimer(250 * time.Millisecond)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			return mfa
		case <-ticker.C:
			if after := target.keySequence(); fmt.Sprint(after) != fmt.Sprint(afterAck) {
				t.Fatalf("real TigerVNC received queued key events after revoke acknowledgement: before=%d after=%d", len(afterAck), len(after))
			}
		}
	}
}

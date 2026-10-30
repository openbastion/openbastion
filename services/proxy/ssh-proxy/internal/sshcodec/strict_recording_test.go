package sshcodec_test

// Record-or-refuse (ADR-0008), proved on real SSH: a genuine ssh.Client plays
// the operator, a genuine proxy handler runs the relay under the REQUIRED
// recording policy, and a genuine SSH server plays the target — one that
// reports every line it receives, so the tests can see exactly what reached it.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

// strictRecorder is both halves of the required policy — the acknowledged
// recorder and its readiness probe — with a switch to take it "down" and a
// delay that makes any forwarding-before-acknowledgement visible.
type strictRecorder struct {
	mu      sync.Mutex
	entries []proxycore.CommandEntry
	delay   time.Duration
	down    atomic.Bool
	batches atomic.Int32
}

func (r *strictRecorder) RecordBatch(ctx context.Context, entries []proxycore.CommandEntry) error {
	r.batches.Add(1)
	time.Sleep(r.delay) // the acknowledgement is slow; the target must still wait for it
	if r.down.Load() {
		return errors.New("command-recorder: status 503")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entries...)
	return nil
}

func (r *strictRecorder) Ready(ctx context.Context) error {
	if r.down.Load() {
		return errors.New("command-recorder not ready: status 503")
	}
	return nil
}

func (r *strictRecorder) has(command string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e.Command == command {
			return true
		}
	}
	return false
}

func (r *strictRecorder) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.entries {
		out = append(out, e.Command)
	}
	return out
}

// safeAudit is fakeAudit safe to read while the proxy goroutine is writing.
type safeAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *safeAudit) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, fmt.Sprintf("%s:%v", action, success))
	return nil
}

func (a *safeAudit) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.events...)
}

func (a *safeAudit) waitFor(t *testing.T, event string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range a.snapshot() {
			if e == event {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("audit event %q never emitted; got %v", event, a.snapshot())
}

// countingVault counts credential fetches: a refused session must not burn one.
type countingVault struct {
	fakeVault
	fetches atomic.Int32
}

func (v *countingVault) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (proxycore.Fetched, error) {
	v.fetches.Add(1)
	return v.fakeVault.FetchCredential(ctx, scopeToken, callingProxyID)
}

// targetLog is what the target actually received.
type targetLog struct {
	mu    sync.Mutex
	lines []string
	// premature lists lines that reached the target before the recorder had
	// them — the very thing the policy exists to prevent.
	premature []string
}

func (l *targetLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *targetLog) sawPremature() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.premature...)
}

// strictHarness is a complete proxy under the required policy, in-process.
type strictHarness struct {
	t        *testing.T
	pending  *infrastructure.PendingSessions
	proxy    string // proxy SSH address
	target   string
	vault    *countingVault
	audit    *safeAudit
	recorder *strictRecorder
	log      *targetLog
}

const strictScope = "scope-strict"

// newStrictHarness builds the proxy under the required policy. Options adjust the
// recording configuration (break-glass, for instance) before the proxy starts.
func newStrictHarness(t *testing.T, recorder *strictRecorder, opts ...func(*proxycore.RecordingConfig)) *strictHarness {
	t.Helper()
	const secret = "target-secret-strict"
	h := &strictHarness{t: t, recorder: recorder, log: &targetLog{}, audit: &safeAudit{},
		vault: &countingVault{fakeVault: fakeVault{expectedScopeToken: strictScope, secret: secret}}}

	h.target = startObservedFakeTargetSSHServer(t, secret, func(line string) {
		h.log.mu.Lock()
		defer h.log.mu.Unlock()
		h.log.lines = append(h.log.lines, line)
		// "sudo -s" style prompts aside, every line a test sends is a command
		// the recorder must already hold when it reaches the target.
		if !recorder.has(line) {
			h.log.premature = append(h.log.premature, line)
		}
	})

	listener := proxycore.NewListener(proxycore.NewCredentialFetcher(h.vault, "ssh-proxy"), proxycore.NewTerminator(h.audit))
	listener.Recording = proxycore.RecordingConfig{Policy: proxycore.RecordingRequired, Strict: recorder, Gate: recorder}
	for _, opt := range opts {
		opt(&listener.Recording)
	}

	h.pending = infrastructure.NewPendingSessions()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	server := &interfaces.SSHServer{HostSigner: hostSigner, Pending: h.pending, Listener: listener, DialTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, ln) }()
	h.proxy = ln.Addr().String()
	return h
}

// operator is one connected client, with its output accumulated.
type operator struct {
	t      *testing.T
	stdin  io.Writer
	mu     sync.Mutex
	out    strings.Builder
	closed chan struct{}
}

// connectOpts describes the session the Session Broker would have established.
type connectOpts struct {
	breakGlass bool          // the Broker authorised a recording waiver (ADR-0009)
	lasts      time.Duration // how long the session may run; zero means a minute
}

func (h *strictHarness) connect(sessionID string) *operator {
	h.t.Helper()
	return h.connectWith(sessionID, connectOpts{})
}

func (h *strictHarness) connectWith(sessionID string, o connectOpts) *operator {
	h.t.Helper()
	if o.lasts == 0 {
		o.lasts = time.Minute
	}
	ticket := h.pending.Register(&infrastructure.PendingSession{
		SessionID: sessionID, TargetHost: h.target, TargetUser: "root",
		ScopeToken: strictScope, ExpiresAt: time.Now().UTC().Add(o.lasts), BreakGlass: o.breakGlass,
	})
	client, err := ssh.Dial("tcp", h.proxy, &ssh.ClientConfig{
		User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		h.t.Fatalf("client dial to proxy: %v", err)
	}
	h.t.Cleanup(func() { _ = client.Close() })
	session, err := client.NewSession()
	if err != nil {
		h.t.Fatalf("client session: %v", err)
	}
	h.t.Cleanup(func() { _ = session.Close() })
	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		h.t.Fatalf("client pty: %v", err)
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.Shell(); err != nil {
		h.t.Fatalf("client shell: %v", err)
	}
	op := &operator{t: h.t, stdin: stdin, closed: make(chan struct{})}
	go func() {
		defer close(op.closed)
		one := make([]byte, 256)
		for {
			n, err := stdout.Read(one)
			if n > 0 {
				op.mu.Lock()
				op.out.Write(one[:n])
				op.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return op
}

func (o *operator) output() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.out.String()
}

func (o *operator) waitFor(want string) {
	o.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(o.output(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	o.t.Fatalf("never saw %q; output so far: %q", want, o.output())
}

func (o *operator) waitClosed() {
	o.t.Helper()
	select {
	case <-o.closed:
	case <-time.After(5 * time.Second):
		o.t.Fatalf("the session was not ended; output so far: %q", o.output())
	}
}

// settle waits long enough for anything the proxy wrongly forwarded to have
// reached the target and been logged. Asserting that something did NOT happen
// can only be done by waiting; 300ms is far above the in-process round trip
// (microseconds), so a violation is seen every time, not by luck.
func settle() { time.Sleep(300 * time.Millisecond) }

// -- the proofs -----------------------------------------------------------------------

// A command reaches the target only after the recorder holds it. The
// recorder's acknowledgement is deliberately slow (80ms), so a proxy that
// forwarded first and recorded after would be caught every time.
func TestStrictRecording_ACommandIsRecordedBeforeTheTargetReceivesIt(t *testing.T) {
	recorder := &strictRecorder{delay: 80 * time.Millisecond}
	h := newStrictHarness(t, recorder)
	op := h.connect("session-strict-ok")

	fmt.Fprint(op.stdin, "whoami\r\n")
	op.waitFor("echo:whoami")
	// A pasted script: two lines in one chunk, recorded as one batch.
	fmt.Fprint(op.stdin, "echo one\r\necho two\r\n")
	op.waitFor("echo:echo two")

	if got := h.log.snapshot(); strings.Join(got, "|") != "whoami|echo one|echo two" {
		t.Fatalf("the target received %q", got)
	}
	if bad := h.log.sawPremature(); len(bad) != 0 {
		t.Fatalf("these commands reached the target BEFORE the recorder had them: %q", bad)
	}
	if got := recorder.commands(); strings.Join(got, "|") != "whoami|echo one|echo two" {
		t.Fatalf("the recorder holds %q", got)
	}
	if n := recorder.batches.Load(); n != 2 {
		t.Fatalf("expected 2 acknowledged batches (one per chunk that completed a line), got %d", n)
	}
}

// The recorder dies mid-session. The next command must not execute, the
// operator is told why, the session ends, and the audit trail says so.
func TestStrictRecording_AnUnrecordedCommandIsNeverExecutedAndTheSessionEnds(t *testing.T) {
	recorder := &strictRecorder{}
	h := newStrictHarness(t, recorder)
	op := h.connect("session-strict-lost")

	fmt.Fprint(op.stdin, "whoami\r\n")
	op.waitFor("echo:whoami")

	recorder.down.Store(true)
	// Typing still works; only SUBMITTING a command needs the recorder.
	fmt.Fprint(op.stdin, "cat /etc/shadow\r\n")

	op.waitClosed()
	settle() // a negative assertion: give a wrongly-forwarded command time to arrive
	if !strings.Contains(op.output(), "recording is unavailable") {
		t.Fatalf("the operator was not told why the session ended: %q", op.output())
	}
	if strings.Contains(op.output(), "echo:cat /etc/shadow") {
		t.Fatal("the command was executed on the target")
	}
	for _, line := range h.log.snapshot() {
		if strings.Contains(line, "shadow") {
			t.Fatalf("an unrecorded command reached the target: %q", h.log.snapshot())
		}
	}
	if recorder.has("cat /etc/shadow") {
		t.Fatal("a command that was refused was recorded as if it had run")
	}

	h.audit.waitFor(t, "session.recording_lost:false")
	h.audit.waitFor(t, "session.terminate:false")
}

// A session is refused up front when the recorder is not ready — and the
// single-use credential is not fetched for it.
func TestStrictRecording_ASessionIsRefusedBeforeTheCredentialIsFetched(t *testing.T) {
	recorder := &strictRecorder{}
	recorder.down.Store(true)
	h := newStrictHarness(t, recorder)

	op := h.connect("session-strict-refused")
	op.waitClosed()
	settle()

	if !strings.Contains(op.output(), "recording is unavailable") {
		t.Fatalf("the operator was not told why: %q", op.output())
	}
	if n := h.vault.fetches.Load(); n != 0 {
		t.Fatalf("the credential was fetched %d time(s) for a refused session — a single-use Vault scope would be burnt", n)
	}
	if got := h.log.snapshot(); len(got) != 0 {
		t.Fatalf("the target received %q from a refused session", got)
	}
	h.audit.waitFor(t, "session.recording_unavailable:false")
	for _, e := range h.audit.snapshot() {
		if e == "session.terminate:true" || e == "session.terminate:false" {
			t.Fatalf("a refused session was reported as having run and ended: %v", h.audit.snapshot())
		}
	}

	// The recorder comes back: the next session runs normally.
	recorder.down.Store(false)
	op2 := h.connect("session-strict-recovered")
	fmt.Fprint(op2.stdin, "uptime\r\n")
	op2.waitFor("echo:uptime")
	if !recorder.has("uptime") {
		t.Fatal("the recovered session was not recorded")
	}
}

// A Listener nobody configured (policy at its zero value, no recorder) refuses
// sessions rather than running them unrecorded.
func TestStrictRecording_AnUnconfiguredProxyRefusesEverySession(t *testing.T) {
	const secret = "target-secret-unconfigured"
	target := startFakeTargetSSHServer(t, secret)
	vault := &countingVault{fakeVault: fakeVault{expectedScopeToken: strictScope, secret: secret}}
	audit := &safeAudit{}
	listener := proxycore.NewListener(proxycore.NewCredentialFetcher(vault, "ssh-proxy"), proxycore.NewTerminator(audit)) // Recording: zero value

	pending := infrastructure.NewPendingSessions()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = (&interfaces.SSHServer{HostSigner: hostSigner, Pending: pending, Listener: listener, DialTimeout: 5 * time.Second}).Serve(ctx, ln)
	}()

	h := &strictHarness{t: t, pending: pending, proxy: ln.Addr().String(), target: target, vault: vault, audit: audit}
	op := h.connect("session-unconfigured")
	op.waitClosed()
	if vault.fetches.Load() != 0 {
		t.Fatal("an unconfigured proxy fetched a credential")
	}
	audit.waitFor(t, "session.recording_unavailable:false")
}

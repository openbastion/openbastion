package sshcodec_test

// Break-glass (ADR-0009) and the end of a session, proved on real SSH with the
// harness of the record-or-refuse tests: a genuine operator, a genuine proxy
// handler, and a genuine target that reports every line it receives.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// sinkRecorder is where a waived session's commands go: sent without being
// waited for, and free to fail.
type sinkRecorder struct {
	mu       sync.Mutex
	commands []string
	failing  atomic.Bool
	calls    atomic.Int32
}

func (r *sinkRecorder) Record(ctx context.Context, e proxycore.CommandEntry) error {
	r.calls.Add(1)
	if r.failing.Load() {
		return errors.New("recorder down")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, e.Command)
	return nil
}

func (r *sinkRecorder) has(c string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.commands {
		if x == c {
			return true
		}
	}
	return false
}

// withBreakGlass is what BREAKGLASS_ENABLED=true does to the proxy's configuration.
func withBreakGlass(sink *sinkRecorder) func(*proxycore.RecordingConfig) {
	return func(c *proxycore.RecordingConfig) {
		c.BreakGlass = true
		c.Sink = sink
	}
}

func targetNever(t *testing.T, h *strictHarness, fragment string) {
	t.Helper()
	for _, line := range h.log.snapshot() {
		if strings.Contains(line, fragment) {
			t.Fatalf("the target received %q (%v)", line, h.log.snapshot())
		}
	}
}

// The emergency this exists for: the recorder is down, an authorised operator
// needs a shell. The session runs, the command reaches the target, and the audit
// trail says — before the credential was even fetched — that it is unrecorded.
func TestBreakGlass_AnAuthorisedSessionRunsWhileTheRecorderIsDown(t *testing.T) {
	recorder := &strictRecorder{}
	recorder.down.Store(true)
	sink := &sinkRecorder{}
	h := newStrictHarness(t, recorder, withBreakGlass(sink))

	op := h.connectWith("session-bg", connectOpts{breakGlass: true})
	fmt.Fprint(op.stdin, "systemctl restart postgresql\r\n")
	op.waitFor("echo:systemctl restart postgresql")

	if strings.Contains(op.output(), "recording is unavailable") {
		t.Fatalf("an authorised break-glass session was refused: %q", op.output())
	}
	h.audit.waitFor(t, "session.breakglass:true")
	if n := h.vault.fetches.Load(); n != 1 {
		t.Fatalf("expected the session to fetch its credential once, got %d", n)
	}
	// Recording continues on a best-effort basis: the command was OFFERED to the
	// recorder (here, the sink), it just was not waited for.
	deadline := time.Now().Add(2 * time.Second)
	for !sink.has("systemctl restart postgresql") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !sink.has("systemctl restart postgresql") {
		t.Fatal("the waived session's command was not offered to the recorder")
	}
	for _, e := range h.audit.snapshot() {
		if e == "session.recording_lost:false" || e == "session.recording_unavailable:false" {
			t.Fatalf("a waived session was audited as a recording failure: %v", h.audit.snapshot())
		}
	}
}

// A waived session is never ended by the recorder, nor slowed by it: the sink
// may fail, the operator keeps working.
func TestBreakGlass_AFailingRecorderDoesNotStopAWaivedSession(t *testing.T) {
	recorder := &strictRecorder{}
	recorder.down.Store(true)
	sink := &sinkRecorder{}
	sink.failing.Store(true)
	h := newStrictHarness(t, recorder, withBreakGlass(sink))

	op := h.connectWith("session-bg-sinkdown", connectOpts{breakGlass: true})
	for _, c := range []string{"df -h", "journalctl -u postgresql -n 20", "pg_ctl status"} {
		fmt.Fprint(op.stdin, c+"\r\n")
		op.waitFor("echo:" + c)
	}
	if sink.calls.Load() == 0 {
		t.Fatal("the recorder was not even tried")
	}
	settle()
	select {
	case <-op.closed:
		t.Fatalf("the session was ended: %q", op.output())
	default:
	}
}

// Nothing is waived for a session that did not ask: this proxy allows break-glass,
// but the Broker did not authorise it for this session.
func TestBreakGlass_ASessionThatDidNotAskIsRefusedAsEver(t *testing.T) {
	recorder := &strictRecorder{}
	recorder.down.Store(true)
	h := newStrictHarness(t, recorder, withBreakGlass(&sinkRecorder{}))

	op := h.connectWith("session-nobg", connectOpts{breakGlass: false})
	op.waitClosed()
	settle()

	if !strings.Contains(op.output(), "recording is unavailable") {
		t.Fatalf("the operator was not told why: %q", op.output())
	}
	if h.vault.fetches.Load() != 0 {
		t.Fatal("the credential was fetched for a refused session")
	}
	h.audit.waitFor(t, "session.recording_unavailable:false")
	for _, e := range h.audit.snapshot() {
		if e == "session.breakglass:true" {
			t.Fatalf("a waiver was recorded for a session that did not ask for one: %v", h.audit.snapshot())
		}
	}
}

// And the other lock: the Broker authorised it, but this proxy was never told to
// honour it (BREAKGLASS_ENABLED unset). The proxy decides what it enforces.
func TestBreakGlass_AProxyThatDoesNotAllowItRefusesTheRequest(t *testing.T) {
	recorder := &strictRecorder{}
	recorder.down.Store(true)
	// A sink is configured — somewhere to send commands — but the switch is off:
	// the Sink alone must never be enough to run a session unrecorded.
	h := newStrictHarness(t, recorder, func(c *proxycore.RecordingConfig) { c.Sink = &sinkRecorder{} })

	op := h.connectWith("session-bg-disabled", connectOpts{breakGlass: true})
	op.waitClosed()
	settle()

	if !strings.Contains(op.output(), "recording is unavailable") {
		t.Fatalf("the operator was not told why: %q", op.output())
	}
	if h.vault.fetches.Load() != 0 {
		t.Fatal("the credential was fetched although the proxy does not allow break-glass")
	}
	targetNever(t, h, "")
	for _, e := range h.audit.snapshot() {
		if strings.HasPrefix(e, "session.breakglass") {
			t.Fatalf("a waiver was recorded by a proxy that does not allow it: %v", h.audit.snapshot())
		}
	}
}

// The waiver is for need. A recorder that IS ready keeps its full guarantee —
// every command acknowledged before it is sent on — even if break-glass was asked
// for, and if the recorder then fails mid-session the session ends as any other.
func TestBreakGlass_ARecordableSessionKeepsTheFullGuarantee(t *testing.T) {
	recorder := &strictRecorder{delay: 40 * time.Millisecond}
	h := newStrictHarness(t, recorder, withBreakGlass(&sinkRecorder{}))

	op := h.connectWith("session-bg-recordable", connectOpts{breakGlass: true})
	fmt.Fprint(op.stdin, "whoami\r\n")
	op.waitFor("echo:whoami")

	if !recorder.has("whoami") {
		t.Fatal("a recordable session was not recorded through the acknowledging path")
	}
	if bad := h.log.sawPremature(); len(bad) != 0 {
		t.Fatalf("commands reached the target before the recorder had them: %q", bad)
	}
	for _, e := range h.audit.snapshot() {
		if e == "session.breakglass:true" {
			t.Fatalf("a waiver was recorded for a session whose recorder was ready: %v", h.audit.snapshot())
		}
	}

	recorder.down.Store(true)
	fmt.Fprint(op.stdin, "cat /etc/shadow\r\n")
	op.waitClosed()
	settle()
	targetNever(t, h, "shadow")
	h.audit.waitFor(t, "session.recording_lost:false")
}

// -- the end of a session --------------------------------------------------------

// The session ends when its time does — on a real connection, whatever the
// operator is doing, and with the operator told why.
func TestSessionExpiry_AConnectedSessionIsCutAtItsDeadline(t *testing.T) {
	recorder := &strictRecorder{}
	h := newStrictHarness(t, recorder)

	op := h.connectWith("session-expiring", connectOpts{lasts: 700 * time.Millisecond})
	fmt.Fprint(op.stdin, "date\r\n")
	op.waitFor("echo:date")

	start := time.Now()
	op.waitClosed() // nothing but the clock ends this session
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the session outlived its deadline by %v", took)
	}
	if !strings.Contains(op.output(), "time limit") {
		t.Fatalf("the operator was not told why: %q", op.output())
	}
	h.audit.waitFor(t, "session.expire:true")
	h.audit.waitFor(t, "session.terminate:true")

	// Cut means cut: a session that is over does not execute anything.
	before := len(h.log.snapshot())
	fmt.Fprint(op.stdin, "reboot\r\n")
	settle()
	if after := h.log.snapshot(); len(after) != before {
		t.Fatalf("a session that had expired still reached the target: %q", after)
	}
	targetNever(t, h, "reboot")
}

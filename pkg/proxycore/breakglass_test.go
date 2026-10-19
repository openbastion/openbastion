package proxycore

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// -- break-glass (ADR-0009) and the end of a session ---------------------------

// auditEvent is one audit call, with what was true of the world when it was made.
type auditEvent struct {
	action     string
	success    bool
	ctxErr     error // the context's state at the moment of the call
	vaultCalls int   // how many credentials had been fetched by then
}

// orderedAudit records events in order, and can refuse a chosen action.
type orderedAudit struct {
	mu     sync.Mutex
	vault  *fakeVault
	events []auditEvent
	failOn string
}

func (a *orderedAudit) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	calls := 0
	if a.vault != nil {
		calls = a.vault.calls
	}
	a.events = append(a.events, auditEvent{action: action, success: success, ctxErr: ctx.Err(), vaultCalls: calls})
	if action == a.failOn {
		return errors.New("audit service unavailable")
	}
	return nil
}

func (a *orderedAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.events))
	for i, e := range a.events {
		out[i] = e.action
	}
	return out
}

func (a *orderedAudit) find(action string) (auditEvent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.action == action {
			return e, true
		}
	}
	return auditEvent{}, false
}

// breakGlassListener is a REQUIRED-policy listener, optionally able to waive.
func breakGlassListener(vault *fakeVault, audit *orderedAudit, gate RecordingGate, canWaive bool) *Listener {
	l := NewListener(NewCredentialFetcher(vault, "ssh-proxy-instance-1"), NewTerminator(audit))
	l.Recording = RecordingConfig{Policy: RecordingRequired, Strict: nopBatchRecorder{}, Gate: gate}
	if canWaive {
		l.Recording.BreakGlass = true
		l.Recording.Sink = &captureRecorder{}
	}
	return l
}

var down = errors.New("connection refused")

func TestAdmitSession_TheWaiverIsForNeed_NotForConvenience(t *testing.T) {
	cases := []struct {
		name       string
		gateErr    error
		requested  bool
		canWaive   bool
		wantErr    bool
		wantWaived bool
		wantEvents []string
	}{
		// A ready recorder always wins: break-glass never degrades a session that
		// could have been recorded, and leaves no waiver event for it.
		{"recorder ready, break-glass asked for", nil, true, true, false, false, nil},
		{"recorder ready, not asked for", nil, false, true, false, false, nil},
		// Down: the waiver is granted, and audited.
		{"recorder down, break-glass asked for and allowed", down, true, true, false, true, []string{"session.breakglass"}},
		// Down, and not every condition holds: refused as ever.
		{"recorder down, not asked for", down, false, true, true, false, []string{"session.recording_unavailable"}},
		{"recorder down, asked for but this proxy does not allow it", down, true, false, true, false, []string{"session.recording_unavailable"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := &orderedAudit{}
			l := breakGlassListener(&fakeVault{}, audit, &fakeGate{err: tc.gateErr}, tc.canWaive)

			adm, err := l.AdmitSession(context.Background(), "s1", tc.requested)

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrRecordingUnavailable) {
				t.Fatalf("a refusal must be ErrRecordingUnavailable, got %v", err)
			}
			if adm.Waived() != tc.wantWaived {
				t.Fatalf("Waived() = %v, want %v", adm.Waived(), tc.wantWaived)
			}
			if adm.For("s1") == tc.wantErr {
				t.Fatalf("For(s1) = %v on err = %v", adm.For("s1"), err)
			}
			got := audit.actions()
			if len(got) != len(tc.wantEvents) {
				t.Fatalf("events = %v, want %v", got, tc.wantEvents)
			}
			for i := range got {
				if got[i] != tc.wantEvents[i] {
					t.Fatalf("events = %v, want %v", got, tc.wantEvents)
				}
			}
		})
	}
}

// The waiver is nothing without somewhere to send the commands: enabling it with
// no Sink must not turn into sessions that run unrecorded by accident.
func TestAdmitSession_AWaiverNeedsASinkToSendCommandsTo(t *testing.T) {
	audit := &orderedAudit{}
	l := breakGlassListener(&fakeVault{}, audit, &fakeGate{err: down}, true)
	l.Recording.Sink = nil

	if _, err := l.AdmitSession(context.Background(), "s", true); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("a waiver with no sink must be refused, got %v", err)
	}
}

// BREAKGLASS_ENABLED means nothing under best-effort — which already runs
// unrecorded sessions, for everybody, and has no need of a waiver to say so.
func TestAdmitSession_BestEffortNeverReportsAWaiver(t *testing.T) {
	audit := &orderedAudit{}
	l := breakGlassListener(&fakeVault{}, audit, &fakeGate{err: down}, true)
	l.Recording.Policy = RecordingBestEffort

	adm, err := l.AdmitSession(context.Background(), "s", true)
	if err != nil || adm.Waived() {
		t.Fatalf("best-effort: err=%v waived=%v", err, adm.Waived())
	}
	if len(audit.actions()) != 0 {
		t.Fatalf("no event expected, got %v", audit.actions())
	}
}

// A waiver nobody can see is not granted: if session.breakglass cannot be
// audited, the session does not run — and the credential is not fetched.
func TestServe_AWaiverThatCannotBeAuditedIsRefused(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &orderedAudit{vault: vault, failOn: "session.breakglass"}
	l := breakGlassListener(vault, audit, &fakeGate{err: down}, true)
	codec := &fakeCodec{}

	var client, target buf
	err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t", BreakGlass: true}, codec, &client, &target)

	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if vault.calls != 0 || codec.relayCalledWith != nil {
		t.Fatalf("a refused waiver must not reach the Vault (%d) or the target", vault.calls)
	}
}

// The order is the point: the waiver is on record BEFORE the credential is
// fetched, so there is no window in which a privileged session exists that the
// audit trail does not yet say is unrecorded.
func TestServe_ABreakGlassSessionIsAuditedBeforeItsCredentialIsFetched(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{err: down}, true)

	var client, target buf
	err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t", BreakGlass: true}, &fakeCodec{}, &client, &target)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	waiver, ok := audit.find("session.breakglass")
	if !ok {
		t.Fatalf("no session.breakglass event: %v", audit.actions())
	}
	if waiver.vaultCalls != 0 {
		t.Fatalf("the waiver was audited after %d credential fetch(es); it must come first", waiver.vaultCalls)
	}
	if vault.calls != 1 {
		t.Fatalf("the session should have run: %d fetches", vault.calls)
	}
	got := audit.actions()
	if len(got) != 2 || got[0] != "session.breakglass" || got[1] != "session.terminate" {
		t.Fatalf("events = %v, want [session.breakglass session.terminate]", got)
	}
}

// Without the Broker's authorisation nothing changes: same refusal as ever.
func TestServe_WithoutTheBrokersAuthorisationTheWaiverIsNotAvailable(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{err: down}, true) // this proxy allows it...

	var client, target buf
	err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, &fakeCodec{}, &client, &target) // ...nobody asked

	if !errors.Is(err, ErrRecordingUnavailable) || vault.calls != 0 {
		t.Fatalf("err=%v fetches=%d", err, vault.calls)
	}
	if _, waived := audit.find("session.breakglass"); waived {
		t.Fatal("a waiver was recorded for a session that never asked for one")
	}
}

// -- the Admission is a proof, not a flag ---------------------------------------

func TestServe_AGrantedAdmissionIsNotAskedForTwice(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &orderedAudit{vault: vault}
	gate := &fakeGate{err: down}
	l := breakGlassListener(vault, audit, gate, true)

	adm, err := l.AdmitSession(context.Background(), "s", true)
	if err != nil {
		t.Fatal(err)
	}
	var client, target buf
	if err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t", BreakGlass: true, Admission: adm}, &fakeCodec{}, &client, &target); err != nil {
		t.Fatal(err)
	}
	if gate.calls != 1 {
		t.Fatalf("the recorder was probed %d times; the caller's admission should have been trusted", gate.calls)
	}
	n := 0
	for _, a := range audit.actions() {
		if a == "session.breakglass" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the waiver was audited %d times, want exactly once: %v", n, audit.actions())
	}
}

// An admission earned for another session — or never earned — buys nothing.
func TestServe_AnAdmissionForAnotherSessionIsIgnored(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{}, false)
	good, err := l.AdmitSession(context.Background(), "someone-elses-session", false)
	if err != nil {
		t.Fatal(err)
	}

	// The recorder goes down; the old admission must not carry over to another session.
	l.Recording.Gate = &fakeGate{err: down}
	var client, target buf
	err = l.Serve(context.Background(), SessionMetadata{SessionID: "mine", ScopeToken: "t", Admission: good}, &fakeCodec{}, &client, &target)
	if !errors.Is(err, ErrRecordingUnavailable) || vault.calls != 0 {
		t.Fatalf("a foreign admission was honoured: err=%v fetches=%d", err, vault.calls)
	}

	err = l.Serve(context.Background(), SessionMetadata{SessionID: "mine", ScopeToken: "t", Admission: Admission{}}, &fakeCodec{}, &client, &target)
	if !errors.Is(err, ErrRecordingUnavailable) || vault.calls != 0 {
		t.Fatalf("a zero admission was honoured: err=%v fetches=%d", err, vault.calls)
	}
}

func TestAdmission_ZeroValueIsNotAdmitted(t *testing.T) {
	var a Admission
	if a.For("") || a.For("s") || a.Waived() {
		t.Fatal("the zero Admission must prove nothing")
	}
}

// -- Probe: the early, non-binding question ------------------------------------

func TestProbe_AuditsARefusalButNotAWaiverItWouldGrant(t *testing.T) {
	audit := &orderedAudit{}
	l := breakGlassListener(&fakeVault{}, audit, &fakeGate{err: down}, true)

	if err := l.Probe(context.Background(), "s", true); err != nil {
		t.Fatalf("a waiver this proxy would grant must not be refused early: %v", err)
	}
	if len(audit.actions()) != 0 {
		t.Fatalf("the waiver is audited when it is USED (Serve), not when it is probed: %v", audit.actions())
	}

	if err := l.Probe(context.Background(), "s", false); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("without a waiver the probe refuses: %v", err)
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "session.recording_unavailable" {
		t.Fatalf("the refusal must be audited, got %v", got)
	}

	// A proxy that does not allow it answers a break-glass request as any other.
	audit2 := &orderedAudit{}
	l2 := breakGlassListener(&fakeVault{}, audit2, &fakeGate{err: down}, false)
	if err := l2.Probe(context.Background(), "s", true); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("a proxy with break-glass off must refuse: %v", err)
	}
}

// -- the tap that records a waived session --------------------------------------

type failingRecorder struct{ calls int }

func (r *failingRecorder) Record(context.Context, CommandEntry) error {
	r.calls++
	return errors.New("recorder down")
}

// A waived session is never stalled or ended by the recorder: its commands go to
// the sink, and a sink that fails costs entries, not the session.
func TestNewTapFor_AWaivedSessionIsNotBlockedByAFailingRecorder(t *testing.T) {
	audit := &orderedAudit{}
	l := breakGlassListener(&fakeVault{}, audit, &fakeGate{err: down}, true)
	sink := &failingRecorder{}
	l.Recording.Sink = sink

	adm, err := l.AdmitSession(context.Background(), "s", true)
	if err != nil {
		t.Fatal(err)
	}
	tap, err := l.Recording.NewTapFor(adm)
	if err != nil {
		t.Fatal(err)
	}
	n, err := tap.Write([]byte("systemctl restart postgresql\n"))
	if err != nil || n != len("systemctl restart postgresql\n") {
		t.Fatalf("a waived session's tap must pass the command on whatever the recorder does: n=%d err=%v", n, err)
	}
	// The sink is fed asynchronously by the tap's best-effort path; give it a moment.
	deadline := time.Now().Add(time.Second)
	for sink.calls == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if sink.calls == 0 {
		t.Fatal("the waived session's commands never reached the sink: recording is best-effort, not off")
	}
}

// Whereas when the recorder WAS ready, the session keeps the full guarantee —
// even if the operator asked for break-glass.
func TestNewTapFor_ARecordedSessionKeepsItsAcknowledgingTap(t *testing.T) {
	l := breakGlassListener(&fakeVault{}, &orderedAudit{}, &fakeGate{}, true)
	strict := &scriptedBatchRecorder{err: errors.New("recorder fell over mid-session")}
	l.Recording.Strict = strict

	adm, err := l.AdmitSession(context.Background(), "s", true) // recorder ready -> not waived
	if err != nil || adm.Waived() {
		t.Fatalf("err=%v waived=%v", err, adm.Waived())
	}
	tap, err := l.Recording.NewTapFor(adm)
	if err != nil {
		t.Fatal(err)
	}
	n, err := tap.Write([]byte("rm -rf /var/lib/x\n"))
	if n != 0 || !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("a recorded session must refuse a command it cannot record: n=%d err=%v", n, err)
	}
}

func TestNewTapFor_RefusesWhatWasNotAdmittedOrCannotBeWaived(t *testing.T) {
	l := breakGlassListener(&fakeVault{}, &orderedAudit{}, &fakeGate{err: down}, true)
	if _, err := l.Recording.NewTapFor(Admission{}); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("no admission, no tap: %v", err)
	}

	adm, err := l.AdmitSession(context.Background(), "s", true)
	if err != nil || !adm.Waived() {
		t.Fatal("setup: expected a waiver")
	}
	l.Recording.BreakGlass = false // the proxy is reconfigured after the admission
	if _, err := l.Recording.NewTapFor(adm); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("a waiver this proxy no longer allows must not produce a tap: %v", err)
	}
}

// -- the end of a session -------------------------------------------------------

// untilCancelled is a relay that runs until its context ends, as a live session does.
type untilCancelled struct {
	cred *Credential
	ctx  context.Context
}

func (c *untilCancelled) Relay(ctx context.Context, client, target io.ReadWriter, cred *Credential) error {
	c.cred, c.ctx = cred, ctx
	<-ctx.Done()
	return ctx.Err()
}

func purged(c *Credential) bool {
	for _, b := range c.material {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestServe_CutsASessionAtTheEndOfItsTime(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{}, false)
	codec := &untilCancelled{}

	var client, target buf
	start := time.Now()
	err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t", ExpiresAt: start.Add(150 * time.Millisecond)}, codec, &client, &target)

	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
	if took := time.Since(start); took < 140*time.Millisecond || took > 3*time.Second {
		t.Fatalf("the session lasted %v, want about 150ms", took)
	}
	if !purged(codec.cred) {
		t.Fatal("the credential was not purged when the session was cut")
	}
	got := audit.actions()
	if len(got) != 2 || got[0] != "session.expire" || got[1] != "session.terminate" {
		t.Fatalf("events = %v, want [session.expire session.terminate]", got)
	}
	// An expiry is a normal end, not a failure...
	for _, e := range audit.events {
		if !e.success {
			t.Fatalf("event %s reported as a failure: an expiry is a normal end", e.action)
		}
		// ...and it must be audited on a live context, not on the one that just expired:
		// a deadline that also killed the audit would leave the cut unrecorded.
		if e.ctxErr != nil {
			t.Fatalf("event %s was emitted on a dead context: %v", e.action, e.ctxErr)
		}
	}
}

func TestServe_AFailureBeforeTheDeadlineIsNotReportedAsAnExpiry(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{}, false)

	var client, target buf
	err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t", ExpiresAt: time.Now().Add(time.Hour)}, failingCodec{}, &client, &target)

	if errors.Is(err, ErrSessionExpired) || err == nil {
		t.Fatalf("got %v", err)
	}
	for _, a := range audit.actions() {
		if a == "session.expire" {
			t.Fatalf("an ordinary failure was reported as an expiry: %v", audit.actions())
		}
	}
	if e, _ := audit.find("session.terminate"); e.success {
		t.Fatal("a failed session must still be reported as a failure")
	}
}

// A proxy shutting down cancels the caller's context. That is not the session's
// time running out, and must not be audited as if it were.
func TestServe_ShutdownIsNotAnExpiry(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{}, false)
	codec := &untilCancelled{}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	var client, target buf
	err := l.Serve(ctx, SessionMetadata{SessionID: "s", ScopeToken: "t", ExpiresAt: time.Now().Add(time.Hour)}, codec, &client, &target)

	if errors.Is(err, ErrSessionExpired) {
		t.Fatal("a shutdown was reported as an expiry")
	}
	for _, a := range audit.actions() {
		if a == "session.expire" {
			t.Fatalf("a shutdown was audited as an expiry: %v", audit.actions())
		}
	}
	if !purged(codec.cred) {
		t.Fatal("the credential was not purged on shutdown")
	}
}

// The caller's OWN deadline firing — a request-scoped context, a shutdown grace
// period — is not the session's time running out either, even though the relay
// sees the same DeadlineExceeded. Only the session's end is an expiry.
func TestServe_ACallersDeadlineIsNotAnExpiry(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &orderedAudit{vault: vault}
	l := breakGlassListener(vault, audit, &fakeGate{}, false)
	codec := &untilCancelled{}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	var client, target buf
	err := l.Serve(ctx, SessionMetadata{SessionID: "s", ScopeToken: "t", ExpiresAt: time.Now().Add(time.Hour)}, codec, &client, &target)

	if errors.Is(err, ErrSessionExpired) {
		t.Fatal("the caller's deadline was reported as the session expiring")
	}
	for _, a := range audit.actions() {
		if a == "session.expire" {
			t.Fatalf("the caller's deadline was audited as an expiry: %v", audit.actions())
		}
	}
}

// The relay's deadline is the session's end; a zero ExpiresAt means "no limit",
// for callers that enforce one elsewhere.
func TestServe_TheRelayRunsUnderTheSessionsDeadline(t *testing.T) {
	l := breakGlassListener(&fakeVault{material: []byte("x")}, &orderedAudit{}, &fakeGate{}, false)

	end := time.Now().Add(time.Hour)
	var gotDeadline time.Time
	var hasDeadline bool
	codec := codecFunc(func(ctx context.Context) error { gotDeadline, hasDeadline = ctx.Deadline(); return nil })
	var client, target buf
	if err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t", ExpiresAt: end}, codec, &client, &target); err != nil {
		t.Fatal(err)
	}
	if !hasDeadline || !gotDeadline.Equal(end) {
		t.Fatalf("relay deadline = %v (%v), want %v", gotDeadline, hasDeadline, end)
	}

	hasDeadline = true
	if err := l.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, codec, &client, &target); err != nil {
		t.Fatal(err)
	}
	if hasDeadline {
		t.Fatal("a zero ExpiresAt must mean no limit, but the relay was given a deadline")
	}
}

type codecFunc func(ctx context.Context) error

func (f codecFunc) Relay(ctx context.Context, _, _ io.ReadWriter, _ *Credential) error { return f(ctx) }

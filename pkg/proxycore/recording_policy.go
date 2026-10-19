package proxycore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// This file is the proxy pipeline's answer to one question: what happens to
// a session that cannot be recorded?
//
// OpenBastion's answer (ADR-0008) is: it does not run. Recording is not a
// best-effort side channel of a privileged session, it is a condition of it.
// Concretely, under RecordingRequired:
//
//   - a session is REFUSED, before its single-use credential is fetched, if
//     the recorder is not ready (RecordingConfig.Admit);
//   - a command line is only passed on to the target once the recorder has
//     ACKNOWLEDGED it (the required Recording Tap): a command that could not
//     be recorded is never executed, and the session ends.
//
// What this does not do is make the recording complete. It makes it complete
// *for the commands the proxy captured* — the tap's known limits (history,
// completion and cursor movement are not reconstructed; a secret typed inside
// a command's arguments is stored as typed) are untouched by this policy.

// ErrRecordingUnavailable marks a refusal or a termination caused by the
// recorder, not by the target or the operator. Callers use errors.Is to tell
// it apart from an ordinary relay failure, because it is audited differently
// (session.recording_unavailable / session.recording_lost) and the operator
// is told why.
var ErrRecordingUnavailable = errors.New("recording unavailable")

// RecordingPolicy says what the proxy does with a session it cannot record.
type RecordingPolicy int

const (
	// RecordingRequired refuses what cannot be recorded. It is the zero
	// value ON PURPOSE: a RecordingConfig that nobody filled in refuses every
	// session instead of silently running them unrecorded.
	RecordingRequired RecordingPolicy = iota

	// RecordingBestEffort lets a session continue when recording fails;
	// entries are then dropped (counted and logged by the Async recorder).
	// It exists for development and for tests that are not about recording,
	// and must be chosen explicitly. A proxy running it says so at startup.
	RecordingBestEffort
)

func (p RecordingPolicy) String() string {
	if p == RecordingBestEffort {
		return "best-effort"
	}
	return "required"
}

// ParseRecordingPolicy reads RECORDING_POLICY. An empty value means the safe
// default, required; anything unrecognised is an error rather than a guess —
// a typo in a security setting must not quietly select the weaker mode.
func ParseRecordingPolicy(s string) (RecordingPolicy, error) {
	switch s {
	case "", "required":
		return RecordingRequired, nil
	case "best-effort":
		return RecordingBestEffort, nil
	}
	return RecordingRequired, fmt.Errorf("unknown recording policy %q (expected \"required\" or \"best-effort\")", s)
}

// BatchRecorder records command entries and returns only once they are
// durably accepted — all of them, or none. It is the acknowledged
// counterpart of Recorder.Record, which only enqueues.
type BatchRecorder interface {
	RecordBatch(ctx context.Context, entries []CommandEntry) error
}

// RecordingGate answers "could a session recorded right now be recorded?".
// It is a pre-flight: a cheap early refusal with a clear reason. It is NOT
// what guarantees recording — the acknowledgement of each command is — so a
// recorder that fails the instant after a successful Ready still stops the
// session at the next command.
type RecordingGate interface {
	Ready(ctx context.Context) error
}

// defaultGateTimeout bounds the readiness probe: an unresponsive recorder
// must refuse a session promptly, not leave the operator hanging.
const defaultGateTimeout = 2 * time.Second

// RecordingConfig is a proxy's recording arrangement. Its zero value is
// RecordingRequired with nothing to record to, which refuses everything.
type RecordingConfig struct {
	Policy RecordingPolicy

	// Sink receives commands under RecordingBestEffort; nil discards them.
	Sink Recorder

	// Strict and Gate are what RecordingRequired needs: the acknowledged
	// recorder, and its readiness probe. Both must be set.
	Strict BatchRecorder
	Gate   RecordingGate

	// GateTimeout bounds one readiness probe. Zero means two seconds.
	GateTimeout time.Duration

	// BreakGlass lets a session that asked for it — and that the Session
	// Broker authorised (ADR-0009) — run while the recorder is NOT ready. Off
	// by default. It needs Sink: the non-blocking recorder that the waived
	// session's commands are sent to (and, if it is nil, the waiver is simply
	// unavailable, never an unrecorded session by accident).
	BreakGlass bool
}

// canWaive says whether this proxy may run a break-glass session without a
// recorder: switched on, and with somewhere to send the commands.
func (c RecordingConfig) canWaive() bool {
	return c.Policy == RecordingRequired && c.BreakGlass && c.Sink != nil
}

// Admit reports whether a session may start. Any policy other than the
// explicit best-effort one is treated as required, so an unknown value fails
// closed.
func (c RecordingConfig) Admit(ctx context.Context) error {
	if c.Policy == RecordingBestEffort {
		return nil
	}
	if c.Strict == nil || c.Gate == nil {
		return fmt.Errorf("%w: recording is required but no recorder is configured", ErrRecordingUnavailable)
	}
	timeout := c.GateTimeout
	if timeout <= 0 {
		timeout = defaultGateTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := c.Gate.Ready(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrRecordingUnavailable, err)
	}
	return nil
}

// NewTap returns the Recording Tap for one session under this policy: the
// acknowledging tap when recording is required, the fire-and-forget one when
// it is best-effort. A required policy with no Strict recorder is a
// configuration error, reported as ErrRecordingUnavailable so the session is
// refused rather than run untapped.
func (c RecordingConfig) NewTap(sessionID string) (*RecordingTap, error) {
	if c.Policy == RecordingBestEffort {
		sink := c.Sink
		if sink == nil {
			sink = discardRecorder{}
		}
		return NewRecordingTap(sink, sessionID), nil
	}
	if c.Strict == nil {
		return nil, fmt.Errorf("%w: recording is required but no recorder is configured", ErrRecordingUnavailable)
	}
	return NewRequiredRecordingTap(c.Strict, sessionID), nil
}

// Admission is the proof that a session passed the recording policy, and how:
// normally (the recorder was ready, every command will be acknowledged before it
// is sent on) or by a break-glass waiver (it was not; commands are recorded on a
// best-effort basis). Only Listener.AdmitSession makes a granted one — its fields
// are unexported — so a caller cannot hand Serve an admission it did not earn.
// The zero value is "not admitted".
type Admission struct {
	sessionID string
	granted   bool
	waived    bool
}

// Waived reports whether the session was admitted by a break-glass waiver
// rather than by a ready recorder.
func (a Admission) Waived() bool { return a.granted && a.waived }

// For reports whether a is a granted admission for exactly this session.
func (a Admission) For(sessionID string) bool { return a.granted && a.sessionID == sessionID }

// NewTapFor returns the Recording Tap for an admitted session: the one that
// acknowledges every command when the recorder was ready, the non-blocking one
// when a break-glass waiver stands in for it. An admission that is not granted
// gets no tap — nothing records a session that was never allowed to start.
func (c RecordingConfig) NewTapFor(adm Admission) (*RecordingTap, error) {
	if !adm.granted {
		return nil, fmt.Errorf("%w: the session was not admitted", ErrRecordingUnavailable)
	}
	if adm.Waived() {
		if !c.canWaive() {
			return nil, fmt.Errorf("%w: break-glass is not available on this proxy", ErrRecordingUnavailable)
		}
		return NewRecordingTap(c.Sink, adm.sessionID), nil
	}
	return c.NewTap(adm.sessionID)
}

type discardRecorder struct{}

func (discardRecorder) Record(context.Context, CommandEntry) error { return nil }

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

type discardRecorder struct{}

func (discardRecorder) Record(context.Context, CommandEntry) error { return nil }

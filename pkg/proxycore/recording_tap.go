package proxycore

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// CommandEntry mirrors recording/v1/recording.proto's CommandEntry message.
type CommandEntry struct {
	SessionID string
	Timestamp time.Time
	Command   string
}

// Recorder is the minimal interface the Recording Tap needs against the
// Session Recorder (proto/recording/v1/recording.proto, StreamCommandEntries).
type Recorder interface {
	Record(ctx context.Context, entry CommandEntry) error
}

// RedactedSecretInput is what the Recording Tap records in place of a line
// the operator typed at a secret prompt (sudo, su, ssh, mysql, ...). The
// entry is kept rather than dropped silently so a replay shows THAT input
// was suppressed, and where — see the evasion note on RecordingTap.
const RedactedSecretInput = "[redacted: input at a secret prompt]"

const (
	// maxLineBytes bounds the line being assembled, so binary data pasted
	// or piped without a terminator cannot grow the buffer without limit.
	maxLineBytes = 8192
	// maxOutputTailBytes bounds how much of the target's current output
	// line is kept for secret-prompt detection.
	maxOutputTailBytes = 256
)

// secretPromptRE recognizes the usual "type a secret now" prompts at the
// end of the target's current output line. It is deliberately about the
// PROMPT, not the input: the proxy cannot see the target's terminal echo
// mode, so this heuristic is the only signal it has that what comes next
// is a secret.
var secretPromptRE = regexp.MustCompile(`(?i)(pass(word|phrase|code)|verification code|\bpin\b)[^\n]*:\s*$`)

type escState int

const (
	escNone escState = iota
	escGotESC
	escCSI
	escSS3
)

// RecordingTap captures what the operator types and hands it to a recorder.
// It comes in two modes, chosen by RecordingPolicy (recording_policy.go):
//
//   - best-effort (NewRecordingTap): duplicates the traffic to the recorder
//     without blocking the relay — a slow or unavailable recorder must never
//     stall the session, and entries it cannot take are dropped (counted and
//     logged by the Async recorder).
//   - required (NewRequiredRecordingTap): a completed command line is
//     recorded SYNCHRONOUSLY, and the keystrokes that completed it are only
//     passed on to the target once the recorder has acknowledged them. If it
//     does not, Write fails, nothing of that chunk is forwarded, and the
//     session ends. See the note on Write for why that is enough.
//
// It implements io.Writer so a Codec can wrap its client stream with
// io.TeeReader(client, tap) to capture what the operator types without a
// separate copy loop. Input is turned into command lines the way a
// terminal line editor would: Enter is '\r' on a real PTY (and '\n' for
// piped input), backspace/DEL, Ctrl-C, Ctrl-U and Ctrl-W edit or abort the
// line, and escape sequences (arrow keys, bracketed paste markers) are
// dropped, so a command is recorded as it was submitted rather than as raw
// keystrokes.
//
// What keystroke-level capture cannot do, stated plainly: it does not see
// the shell's own line editing. A command recalled from history (Up, Ctrl-R),
// completed with Tab, or edited after moving the cursor is recorded as the
// operator TYPED it, which can differ from what the shell ran. Closing that
// gap needs target-side or output-side reconstruction and is not attempted
// here.
//
// Secret prompts: Observe feeds the tap the target's output; when the
// current output line looks like a password/passphrase prompt, the next
// input line is recorded as RedactedSecretInput instead of its content —
// otherwise sudo passwords would be stored in the clear in the recording.
// Because the prompt text comes from the target, which the operator
// controls, an insider could print a fake prompt to have ONE following
// command redacted; recording a marker instead of nothing means that
// attempt is visible in the replay, next to the command that printed the
// prompt.
type RecordingTap struct {
	recorder  Recorder      // best-effort mode; nil in required mode
	strict    BatchRecorder // required mode; nil in best-effort mode
	sessionID string

	mu         sync.Mutex
	line       []byte   // the line being assembled from the operator's keystrokes
	skipLF     bool     // the previous terminator was '\r': swallow one directly-following '\n'
	esc        escState // escape-sequence parser state, preserved across Write calls
	outTail    []byte   // the target's current (unterminated) output line, capped
	secretNext bool     // the target just showed a secret prompt
	failed     error    // required mode: the recorder refused; the tap is finished
}

// NewRecordingTap returns the best-effort tap: it never fails the relay.
func NewRecordingTap(recorder Recorder, sessionID string) *RecordingTap {
	return &RecordingTap{recorder: recorder, sessionID: sessionID}
}

// NewRequiredRecordingTap returns the tap for RecordingRequired: it fails the
// relay when the recorder does not acknowledge a command.
func NewRequiredRecordingTap(strict BatchRecorder, sessionID string) *RecordingTap {
	return &RecordingTap{strict: strict, sessionID: sessionID}
}

// Write consumes the operator's keystrokes.
//
// In best-effort mode it never fails: capture must not be able to break the
// relay it is tapping.
//
// In required mode it fails, deliberately, when the recorder does not
// acknowledge a completed command line — returning (0, error). That is the
// whole enforcement mechanism, and it works because of how the relay uses the
// tap: the SSH codec reads the client through io.TeeReader(client, tap), and
// a TeeReader returns the tap's own (n, err) from Read, so io.Copy forwards
// exactly n bytes to the target. n == 0 means NONE of the chunk — in
// particular not the Enter that would have run the command — reaches the
// target, and the error ends the copy and with it the session. A command the
// recorder never acknowledged is therefore never executed.
//
// Only chunks that complete a line wait for the recorder; ordinary
// keystrokes cost nothing, so typing stays as responsive as before and only
// pressing Enter pays one round trip.
func (t *RecordingTap) Write(p []byte) (int, error) {
	now := time.Now().UTC()
	var completed []string

	t.mu.Lock()
	if t.failed != nil {
		err := t.failed
		t.mu.Unlock()
		return 0, err
	}
	for _, b := range p {
		if line, done := t.consume(b); done {
			completed = append(completed, line)
		}
	}
	t.mu.Unlock()

	if t.strict != nil {
		if len(completed) == 0 {
			return len(p), nil
		}
		// One batch for everything this chunk completed (a pasted script
		// arrives as one chunk): all recorded or none, so the recording
		// never shows commands that were then not run. Outside the lock for
		// the same reason as below — the output observer shares it.
		entries := make([]CommandEntry, 0, len(completed))
		for _, command := range completed {
			entries = append(entries, CommandEntry{SessionID: t.sessionID, Timestamp: now, Command: command})
		}
		if err := t.strict.RecordBatch(context.Background(), entries); err != nil {
			err = fmt.Errorf("%w: %v", ErrRecordingUnavailable, err)
			t.mu.Lock()
			t.failed = err
			t.mu.Unlock()
			return 0, err
		}
		return len(p), nil
	}

	// Recorded outside the lock: Record may be slow, and holding the lock
	// would stall the output observer (and so the other half of the relay).
	for _, command := range completed {
		_ = t.recorder.Record(context.Background(), CommandEntry{
			SessionID: t.sessionID,
			Timestamp: now,
			Command:   command,
		})
	}
	return len(p), nil
}

// consume handles one input byte. It reports a finished command line, if
// this byte finished one. Callers hold t.mu.
func (t *RecordingTap) consume(b byte) (line string, done bool) {
	switch t.esc {
	case escGotESC:
		switch b {
		case '[':
			t.esc = escCSI
		case 'O':
			t.esc = escSS3
		default:
			t.esc = escNone // ESC + one byte: an Alt-key chord, dropped
		}
		return "", false
	case escCSI:
		if b >= 0x40 && b <= 0x7e { // final byte
			t.esc = escNone
		} else if b < 0x20 {
			t.esc = escNone // malformed: do not stay stuck in the sequence
		}
		return "", false
	case escSS3:
		t.esc = escNone
		return "", false
	}

	if b != '\n' {
		t.skipLF = false
	}

	switch {
	case b == 0x1b:
		t.esc = escGotESC
	case b == '\r':
		t.skipLF = true
		return t.finishLine()
	case b == '\n':
		if t.skipLF {
			t.skipLF = false
			return "", false
		}
		return t.finishLine()
	case b == 0x7f || b == 0x08: // DEL / backspace
		if len(t.line) > 0 {
			_, size := utf8.DecodeLastRune(t.line)
			t.line = t.line[:len(t.line)-size]
		}
	case b == 0x03: // Ctrl-C: abort the line and any pending secret prompt
		t.line = t.line[:0]
		t.secretNext = false
	case b == 0x15: // Ctrl-U: kill the whole line
		t.line = t.line[:0]
	case b == 0x17: // Ctrl-W: kill the last word
		s := strings.TrimRight(string(t.line), " \t")
		if i := strings.LastIndexAny(s, " \t"); i >= 0 {
			t.line = append(t.line[:0], s[:i+1]...)
		} else {
			t.line = t.line[:0]
		}
	case b < 0x20:
		// Tab, Ctrl-D, Ctrl-A and the rest: not part of the command text.
	default:
		if len(t.line) < maxLineBytes {
			t.line = append(t.line, b)
		}
	}
	return "", false
}

func (t *RecordingTap) finishLine() (string, bool) {
	command := strings.TrimSpace(string(t.line))
	t.line = t.line[:0]
	if t.secretNext {
		t.secretNext = false
		// A blank line at a secret prompt (an empty password) is still
		// worth marking, so no empty-command shortcut before this point.
		return RedactedSecretInput, true
	}
	if command == "" {
		return "", false
	}
	return command, true
}

// Output returns the writer the Codec tees the target's output into, so
// the tap can see secret prompts (see RecordingTap). It never fails.
func (t *RecordingTap) Output() io.Writer { return outputObserver{t} }

type outputObserver struct{ t *RecordingTap }

func (o outputObserver) Write(p []byte) (int, error) {
	o.t.observe(p)
	return len(p), nil
}

func (t *RecordingTap) observe(p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			// New output line: a prompt the operator never answered is
			// stale. The legitimate order — the operator's Enter reaching
			// the tap BEFORE the target echoes the newline — is guaranteed
			// by the relay teeing input before it forwards it.
			t.outTail = t.outTail[:0]
			t.secretNext = false
			continue
		}
		t.outTail = append(t.outTail, b)
		if len(t.outTail) > maxOutputTailBytes {
			t.outTail = t.outTail[len(t.outTail)-maxOutputTailBytes:]
		}
	}
	if secretPromptRE.Match(t.outTail) {
		t.secretNext = true
	}
}

// RecordEvent records one event of the session that is not a typed line — a file transfer
// (ADR-0038) — before whatever caused it is relayed. In required mode it waits for the
// recorder's acknowledgement and returns an error wrapping ErrRecordingUnavailable when there
// is none: the caller must then not relay, and end the session. In best-effort mode it never
// fails. After a refusal the tap is finished, as with a command.
func (t *RecordingTap) RecordEvent(ctx context.Context, event string) error {
	t.mu.Lock()
	if t.failed != nil {
		err := t.failed
		t.mu.Unlock()
		return err
	}
	t.mu.Unlock()
	entry := CommandEntry{SessionID: t.sessionID, Timestamp: time.Now().UTC(), Command: event}
	if t.strict != nil {
		if err := t.strict.RecordBatch(ctx, []CommandEntry{entry}); err != nil {
			err = fmt.Errorf("%w: %v", ErrRecordingUnavailable, err)
			t.mu.Lock()
			t.failed = err
			t.mu.Unlock()
			return err
		}
		return nil
	}
	_ = t.recorder.Record(ctx, entry)
	return nil
}

// RecordSecretInput stores the safe evidence for ADR-0097 in the command
// recording. It never receives or serializes the secret bytes.
func (t *RecordingTap) RecordSecretInput(ctx context.Context, evidence SecretInputEvidence) error {
	if t == nil || ctx == nil || evidence.SessionID != t.sessionID ||
		!safeSecretIdentifier(evidence.AccountID, 128) ||
		!safeSecretIdentifier(evidence.Protocol, 32) {
		return ErrSecretInjectionInvalid
	}
	// Secret injection is never allowed under break-glass: the reference must
	// be durably acknowledged, not merely sent to a best-effort sink.
	if t.strict == nil {
		return ErrSecretInjectionUnavailable
	}
	var marker string
	switch evidence.Source {
	case SecretInputVault:
		if evidence.Length != 0 || evidence.SHA256 != "" {
			return ErrSecretInjectionInvalid
		}
		marker = "[vault secret " + evidence.AccountID + " injection requested via " + evidence.Protocol + "]"
	case SecretInputOperator:
		if evidence.Length < 1 || len(evidence.SHA256) != 64 {
			return ErrSecretInjectionInvalid
		}
		if _, err := hex.DecodeString(evidence.SHA256); err != nil {
			return ErrSecretInjectionInvalid
		}
		marker = fmt.Sprintf("[operator password input requested: %d bytes, sha256 %s]", evidence.Length, evidence.SHA256)
	default:
		return ErrSecretInjectionInvalid
	}
	if err := t.RecordEvent(ctx, marker); err != nil {
		return err
	}
	// The injected bytes deliberately bypass Write, so consume the prompt state
	// here; otherwise the next ordinary command would be falsely redacted.
	t.mu.Lock()
	t.secretNext = false
	t.mu.Unlock()
	return nil
}

var _ SecretInputRecorder = (*RecordingTap)(nil)

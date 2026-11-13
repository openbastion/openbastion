package proxycore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

// The clipboard of a screen session (ADR-0096): a text crosses it in one direction or the other,
// each direction its own right, and every transfer is bounded, audited, then recorded and
// acknowledged before it is delivered. A transfer that cannot be all of that does not happen.

// ClipboardCodec is a ScreenCodec that can open the target's clipboard, in the directions the
// session's rights allow. A codec that is not one opens none.
type ClipboardCodec interface {
	OpenWithClipboard(ctx context.Context, cred *Credential, toTarget, fromTarget bool) (ScreenSession, error)
}

// ClipboardSession is a ScreenSession whose clipboard is open.
type ClipboardSession interface {
	// ClipboardTexts delivers each text copied on the target, whole. It may be nil when copying
	// from the target is not allowed.
	ClipboardTexts() <-chan string
	// OfferClipboardText offers the operator's text to the target's clipboard, where an application
	// takes it when it pastes.
	OfferClipboardText(text string) error
}

// ClipboardEvent is what the audit keeps of a transfer: never the text (ADR-0096 §5).
type ClipboardEvent struct {
	Direction screenstream.ClipboardDirection
	Bytes     int    // the text's size in UTF-8
	SHA256    string // of the text in UTF-8, in hex
	Success   bool
	Reason    string // why a transfer was refused; empty for one that happens
}

// ClipboardAuditor writes session.clipboard. Without one, the proxy opens no clipboard.
type ClipboardAuditor interface {
	EmitClipboard(ctx context.Context, sessionID string, event ClipboardEvent) error
}

// The refusals the audit names.
const (
	ClipboardRefusedRate    = "rate"
	ClipboardRefusedInvalid = "invalid"
	ClipboardRefusedAudit   = "audit_unavailable"
)

// MaxClipboardTransfersPerMinute bounds the transfers of a session, both directions together
// (ADR-0096 §3): past it, a transfer is refused, audited as such, and the session goes on.
const MaxClipboardTransfersPerMinute = 10

// clipboardAuditTimeout bounds the audit of one transfer: the relay waits for it.
const clipboardAuditTimeout = 2 * time.Second

// clipboardBudget remembers the times of the transfers of the last minute.
type clipboardBudget struct{ times []time.Time }

func (b *clipboardBudget) admit(now time.Time) bool {
	kept := b.times[:0]
	for _, at := range b.times {
		if now.Sub(at) < time.Minute {
			kept = append(kept, at)
		}
	}
	b.times = kept
	if len(b.times) >= MaxClipboardTransfersPerMinute {
		return false
	}
	b.times = append(b.times, now)
	return true
}

// ClipboardDetails are the audit details of a transfer (ADR-0068: bounded, never the text).
func ClipboardDetails(event ClipboardEvent) map[string]string {
	direction := "to-target"
	if event.Direction == screenstream.ClipboardFromTarget {
		direction = "from-target"
	}
	details := map[string]string{"direction": direction, "bytes": strconv.Itoa(event.Bytes), "sha256": event.SHA256}
	if event.Reason != "" {
		details["reason"] = event.Reason
	}
	return details
}

// clipboardRelay carries the transfers of one session. It runs on the relay's goroutine: the
// sequence it takes is the next one of the recording, and the frames after it are numbered after it.
type clipboardRelay struct {
	sessionID  string
	audit      ClipboardAuditor
	recorder   FrameRecorder
	session    ClipboardSession
	ackTimeout time.Duration
	budget     clipboardBudget
	now        func() time.Time
}

// transfer moves text in direction, as the next entry of the recording, sequence. It returns the
// message to show the operator, and false when the transfer was refused: nothing then is recorded
// nor delivered, and the session goes on. An error is a recording that is lost, which ends the
// session as a frame's would.
func (r *clipboardRelay) transfer(ctx context.Context, direction screenstream.ClipboardDirection, text string, sequence uint64) (screenstream.Message, bool, error) {
	now := r.now().UTC()
	sum := sha256.Sum256([]byte(text))
	event := ClipboardEvent{Direction: direction, Bytes: len(text), SHA256: hex.EncodeToString(sum[:])}
	refuse := func(reason string) (screenstream.Message, bool, error) {
		event.Success, event.Reason = false, reason
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clipboardAuditTimeout)
		_ = r.audit.EmitClipboard(auditCtx, r.sessionID, event) // a refusal is best effort: it grants nothing
		cancel()
		return screenstream.Message{}, false, nil
	}
	message := screenstream.Message{Type: screenstream.TypeClipboard, Sequence: sequence, Timestamp: now,
		Direction: direction, ClipboardText: text}
	if _, err := screenstream.Encode(message); err != nil {
		return refuse(ClipboardRefusedInvalid)
	}
	if !r.budget.admit(now) {
		return refuse(ClipboardRefusedRate)
	}
	// Audited before anything moves: without the event, no transfer (ADR-0096 §5).
	event.Success = true
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clipboardAuditTimeout)
	err := r.audit.EmitClipboard(auditCtx, r.sessionID, event)
	cancel()
	if err != nil {
		return refuse(ClipboardRefusedAudit)
	}
	// Recorded and acknowledged before it is delivered (ADR-0096 §4).
	ack, err := recordScreenFrame(ctx, r.recorder, r.sessionID, message, r.ackTimeout)
	if err != nil || ack != sequence {
		return screenstream.Message{}, false, fmt.Errorf("%w: clipboard acknowledgement missing or ambiguous", ErrRecordingLost)
	}
	if direction == screenstream.ClipboardToTarget {
		if err := r.session.OfferClipboardText(text); err != nil {
			return screenstream.Message{}, false, fmt.Errorf("%w: the target refused a clipboard text", ErrScreenInputInvalid)
		}
	}
	return message, true, nil
}

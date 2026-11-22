package application

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// MetadataHeadStore keeps the heads of ADR-0116 §3. AppendAttestation appends the event and moves the
// session's head to head in ONE transaction, and only if the stored head is still `previous` (nil:
// none): an event is never written without its head, nor a head without its event.
type MetadataHeadStore interface {
	AppendAttestation(ctx context.Context, e *domain.Event, head domain.MetadataHead, previous *domain.MetadataHead) error
	MetadataHead(ctx context.Context, sessionID string) (*domain.MetadataHead, error) // nil, nil without one
}

// ErrMetadataHeadsUnavailable: this Audit Service keeps no heads (a store without them).
var ErrMetadataHeadsUnavailable = errors.New("this audit service keeps no session metadata heads")

var metadataKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *AuditService) heads() (MetadataHeadStore, error) {
	h, ok := s.store.(MetadataHeadStore)
	if !ok {
		return nil, ErrMetadataHeadsUnavailable
	}
	return h, nil
}

// AttestSessionMetadata records that the Session Broker signed revision `revision` of session
// sessionID's row, whose canonical form has SHA-256 digest, under its key keyID (ADR-0116 §3-§5).
// Only the Session Broker may (emitter, from its certificate; empty only without internal TLS).
//
//   - the head's revision and digest again: idempotent, the head is returned as it is;
//   - the head's revision with another digest: ErrMetadataFork; an older one: ErrMetadataRollback;
//   - more than one ahead: ErrMetadataGap;
//   - one ahead, or a session without a head yet (rows signed before the heads existed, or whose
//     first attestation was lost): the event is written and the head moves, in one transaction.
func (s *AuditService) AttestSessionMetadata(ctx context.Context, emitter, sessionID string, revision uint64, digest []byte, keyID string) (domain.MetadataHead, error) {
	if emitter != "" && emitter != mtls.SessionBroker {
		return domain.MetadataHead{}, fmt.Errorf("%w: only the session broker attests session metadata", domain.ErrInvalidEvent)
	}
	if err := checkID("session_id", sessionID, true); err != nil {
		return domain.MetadataHead{}, err
	}
	if revision == 0 || revision > 1<<62 || len(digest) != sha256.Size || !metadataKeyIDPattern.MatchString(keyID) {
		return domain.MetadataHead{}, fmt.Errorf("%w: a revision of at least 1, a 32-byte digest and a key identifier are required", domain.ErrInvalidEvent)
	}
	store, err := s.heads()
	if err != nil {
		return domain.MetadataHead{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := store.MetadataHead(ctx, sessionID)
	if err != nil {
		return domain.MetadataHead{}, err
	}
	if current != nil {
		switch {
		case revision == current.Revision && bytes.Equal(digest, current.Digest) && keyID == current.KeyID:
			return *current, nil
		case revision == current.Revision:
			return *current, domain.ErrMetadataFork
		case revision < current.Revision:
			return *current, domain.ErrMetadataRollback
		case revision > current.Revision+1:
			return *current, domain.ErrMetadataGap
		}
	}
	e, err := s.nextEvent(ctx, emitter, "", domain.ActionMetadataAttested, "session", sessionID, metadataDetails(revision, digest, keyID), true)
	if err != nil {
		return domain.MetadataHead{}, err
	}
	head := domain.MetadataHead{
		SessionID: sessionID, Revision: revision, Digest: append([]byte(nil), digest...), KeyID: keyID,
		EventID: e.ID, EventTime: e.Timestamp, PrevHash: e.PrevHash, EventHash: e.Hash, ChainKeyID: e.KeyID,
		HashVersion: e.HashVersion, Emitter: e.Emitter,
	}
	if err := store.AppendAttestation(ctx, e, head, current); err != nil {
		return domain.MetadataHead{}, err
	}
	tip := *e
	s.tip = &tip
	return head, nil
}

func metadataDetails(revision uint64, digest []byte, keyID string) map[string]string {
	return map[string]string{
		"revision":        strconv.FormatUint(revision, 10),
		"metadata_sha256": hex.EncodeToString(digest),
		"key_id":          keyID,
	}
}

// SessionMetadataHead is the head of sessionID, nil without one, once checked against the event the
// chain signed (§4): the event is recomputed from the head's own fields and must give the hash the
// chain holds, under the chain key that signed it. That needs no event in the database: an archived
// month leaves its heads verifiable. A head that does not recompute is ErrMetadataHeadTampered.
func (s *AuditService) SessionMetadataHead(ctx context.Context, sessionID string) (*domain.MetadataHead, error) {
	if err := checkID("session_id", sessionID, true); err != nil {
		return nil, err
	}
	store, err := s.heads()
	if err != nil {
		return nil, err
	}
	head, err := store.MetadataHead(ctx, sessionID)
	if err != nil || head == nil {
		return head, err
	}
	key, ok := s.keys.keys[head.ChainKeyID]
	if !ok || head.HashVersion != domain.HashV4 || head.Emitter != mtls.SessionBroker && head.Emitter != "" {
		return nil, domain.ErrMetadataHeadTampered
	}
	e := &domain.Event{
		ID: head.EventID, Timestamp: head.EventTime.UTC(), Action: domain.ActionMetadataAttested, ResourceType: "session",
		ResourceID: head.SessionID, Details: metadataDetails(head.Revision, head.Digest, head.KeyID), Success: true,
		PrevHash: head.PrevHash, HashVersion: head.HashVersion, Emitter: head.Emitter, KeyID: head.ChainKeyID,
	}
	if !hmac.Equal(computeHashV4(key, e), head.EventHash) {
		return nil, domain.ErrMetadataHeadTampered
	}
	return head, nil
}

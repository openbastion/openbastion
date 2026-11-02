package application

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/pkg/refusalbudget"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

const (
	dependencyTimeout             = 5 * time.Second
	MaxFrameBytes                 = 4 << 20
	MaxSegmentBytes               = 4 << 20
	MaxFramePixels                = int64(16_777_216)
	MaxSegmentDuration            = 250 * time.Millisecond
	DefaultReadAuditBurst         = 10
	MaxReadAuditBurst             = 1000
	DefaultReadAuditRatePerMinute = 6
	MaxReadAuditRatePerMinute     = 600
	maxSessionIDBytes             = 256
	AuditActionRead               = "recording.read"
	ActionRead                    = "recording:session:read"
	RecordingResource             = "recording:session:"
	recordingFormat               = "openbastion/video-segment/v1"
	MaxCiphertextBytes            = 8 << 20
	maxActorRoles                 = 100
	maxActorRoleBytes             = 128
)

type RecorderService struct {
	repo                   domain.Repository
	objects                domain.ObjectStore
	keys                   domain.KeyWrapper
	authz                  domain.AuthorizationClient
	audit                  domain.AuditEmitter
	readRefusals           *refusalbudget.Budget
	readAuditBurst         int
	readAuditRatePerMinute int
}

type RecordingWriter struct {
	service   *RecorderService
	sessionID string
	dek       []byte
	closed    bool
}

func NewRecorderService(repo domain.Repository, objects domain.ObjectStore, keys domain.KeyWrapper, authz domain.AuthorizationClient, audit domain.AuditEmitter) *RecorderService {
	return &RecorderService{
		repo: repo, objects: objects, keys: keys, authz: authz, audit: audit,
		readRefusals:   refusalbudget.New(DefaultReadAuditBurst, DefaultReadAuditRatePerMinute),
		readAuditBurst: DefaultReadAuditBurst, readAuditRatePerMinute: DefaultReadAuditRatePerMinute,
	}
}

func (s *RecorderService) WithReadRefusalAudit(burst, perMinute int) *RecorderService {
	s.readRefusals = refusalbudget.New(burst, perMinute)
	s.readAuditBurst, s.readAuditRatePerMinute = burst, perMinute
	return s
}

func (s *RecorderService) ReadRefusalAudit() (burst, perMinute int) {
	return s.readAuditBurst, s.readAuditRatePerMinute
}

func (s *RecorderService) Ready(ctx context.Context) error {
	depCtx, cancel := dependencyContext(ctx)
	err := s.repo.Ready(depCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("postgres is not ready: %w", err)
	}
	depCtx, cancel = dependencyContext(ctx)
	err = s.objects.Ready(depCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("object store is not ready: %w", err)
	}
	depCtx, cancel = dependencyContext(ctx)
	err = s.keys.Ready(depCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("key wrapper is not ready: %w", err)
	}
	return nil
}

func ValidateSegment(segment domain.VideoSegment) error {
	if !usableSessionID(segment.SessionID) {
		return fmt.Errorf("%w: unusable session id", domain.ErrInvalidSegment)
	}
	if segment.Terminal {
		if segment.FirstSequence != 0 || segment.LastSequence != 0 || len(segment.Frames) != 0 || segment.TerminalThroughSequence < 0 {
			return fmt.Errorf("%w: malformed terminal marker", domain.ErrInvalidSegment)
		}
		return nil
	}
	if segment.FirstSequence < 1 || segment.LastSequence < segment.FirstSequence ||
		segment.LastSequence-segment.FirstSequence != int64(len(segment.Frames))-1 || len(segment.Frames) == 0 {
		return fmt.Errorf("%w: sequence bounds do not match the frame count", domain.ErrInvalidSegment)
	}

	var total int64
	var firstTime, lastTime time.Time
	for i, frame := range segment.Frames {
		if frame.Codec != "png" {
			return fmt.Errorf("%w: only PNG frames are accepted", domain.ErrInvalidSegment)
		}
		if frame.Timestamp.IsZero() {
			return fmt.Errorf("%w: frame %d has no timestamp", domain.ErrInvalidSegment, i)
		}
		if len(frame.Data) == 0 || len(frame.Data) > MaxFrameBytes {
			return fmt.Errorf("%w: frame %d is empty or exceeds the frame size limit", domain.ErrInvalidSegment, i)
		}
		total += int64(len(frame.Data))
		if total > MaxSegmentBytes {
			return fmt.Errorf("%w: segment exceeds the size limit", domain.ErrInvalidSegment)
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(frame.Data))
		if err != nil || cfg.Width < 1 || cfg.Height < 1 || int64(cfg.Width)*int64(cfg.Height) > MaxFramePixels {
			return fmt.Errorf("%w: frame %d is not an allowed PNG image", domain.ErrInvalidSegment, i)
		}
		ts := frame.Timestamp.UTC()
		if i == 0 {
			firstTime = ts
		} else if ts.Before(lastTime) {
			return fmt.Errorf("%w: frame timestamps are not ordered", domain.ErrInvalidSegment)
		}
		lastTime = ts
	}
	if lastTime.Sub(firstTime) > MaxSegmentDuration {
		return fmt.Errorf("%w: segment duration exceeds the limit", domain.ErrInvalidSegment)
	}
	return nil
}

func (s *RecorderService) BeginRecording(ctx context.Context, sessionID string) (*RecordingWriter, error) {
	if !usableSessionID(sessionID) {
		return nil, domain.ErrInvalidSegment
	}
	dek, err := newDEK()
	if err != nil {
		return nil, fmt.Errorf("creating video data key: %w", err)
	}
	keyID := s.keys.KeyID()
	if keyID == "" {
		zero(dek)
		return nil, fmt.Errorf("%w: key wrapper has no key id", domain.ErrUnavailable)
	}
	depCtx, cancel := dependencyContext(ctx)
	wrapped, err := s.keys.Wrap(depCtx, dek, dekAAD(keyID, sessionID))
	cancel()
	if err != nil {
		zero(dek)
		return nil, fmt.Errorf("%w: wrapping video data key: %v", domain.ErrUnavailable, err)
	}
	if err := s.repo.BeginRecording(ctx, sessionID, keyID, wrapped); err != nil {
		zero(dek)
		return nil, err
	}
	return &RecordingWriter{service: s, sessionID: sessionID, dek: dek}, nil
}

func (w *RecordingWriter) RecordSegment(ctx context.Context, segment domain.VideoSegment) error {
	if w.closed || w.service == nil || segment.SessionID != w.sessionID {
		return domain.ErrConflict
	}
	if err := ValidateSegment(segment); err != nil {
		return err
	}
	if segment.Terminal {
		return fmt.Errorf("%w: terminal markers are not data segments", domain.ErrInvalidSegment)
	}
	plain, err := json.Marshal(segment)
	if err != nil {
		return fmt.Errorf("encoding video segment: %w", err)
	}
	defer zero(plain)
	ciphertext, err := seal(w.dek, plain, segmentAAD(segment.SessionID, segment.FirstSequence, segment.LastSequence))
	if err != nil {
		return fmt.Errorf("encrypting video segment: %w", err)
	}
	key, err := randomObjectKey()
	if err != nil {
		return fmt.Errorf("creating object key: %w", err)
	}
	depCtx, cancel := dependencyContext(ctx)
	err = w.service.objects.Put(depCtx, key, ciphertext)
	cancel()
	if err != nil {
		return fmt.Errorf("%w: writing encrypted video segment: %v", domain.ErrUnavailable, err)
	}
	sum := sha256.Sum256(ciphertext)
	meta := domain.SegmentMetadata{
		SessionID: segment.SessionID, FirstSequence: segment.FirstSequence,
		LastSequence: segment.LastSequence, ObjectKey: key, SHA256: sum[:],
	}
	depCtx, cancel = dependencyContext(ctx)
	err = w.service.repo.AppendSegment(depCtx, meta)
	cancel()
	if err != nil {
		return err
	}
	return nil
}

func (w *RecordingWriter) Complete(ctx context.Context, throughSequence int64) error {
	if w.closed || w.service == nil || throughSequence < 0 {
		return domain.ErrInvalidSegment
	}
	depCtx, cancel := dependencyContext(ctx)
	err := w.service.repo.CompleteRecording(depCtx, w.sessionID, throughSequence)
	cancel()
	if err != nil {
		return err
	}
	w.Close()
	return nil
}

func (w *RecordingWriter) Close() {
	if !w.closed {
		zero(w.dek)
		w.dek = nil
		w.closed = true
	}
}

func (s *RecorderService) ReadSegment(ctx context.Context, callerID string, actorRoles []string, sessionID string, firstSequence int64) (domain.VideoSegment, bool, error) {
	if !usableSessionID(sessionID) || firstSequence < 1 {
		return domain.VideoSegment{}, false, domain.ErrInvalidSegment
	}
	if !usableSessionID(callerID) || len(actorRoles) > maxActorRoles {
		return domain.VideoSegment{}, false, domain.ErrForbidden
	}
	for _, role := range actorRoles {
		if !usableActorRole(role) {
			return domain.VideoSegment{}, false, domain.ErrForbidden
		}
	}
	depCtx, cancel := dependencyContext(ctx)
	allowed, _, err := s.authz.CheckAccess(depCtx, actorRoles, RecordingResource+sessionID, ActionRead)
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, fmt.Errorf("%w: asking authorization: %v", domain.ErrUnavailable, err)
	}
	if !allowed {
		s.auditRefusedRead(ctx, callerID, sessionID)
		return domain.VideoSegment{}, false, domain.ErrForbidden
	}

	depCtx, cancel = dependencyContext(ctx)
	stored, err := s.repo.GetSegment(depCtx, sessionID, firstSequence)
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, err
	}
	depCtx, cancel = dependencyContext(ctx)
	err = s.audit.EmitEvent(depCtx, callerID, AuditActionRead, "session", sessionID, true)
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, fmt.Errorf("%w: recording the video read: %v", domain.ErrUnavailable, err)
	}
	depCtx, cancel = dependencyContext(ctx)
	ciphertext, err := s.objects.Get(depCtx, stored.ObjectKey)
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, fmt.Errorf("%w: reading encrypted video segment: %v", domain.ErrUnavailable, err)
	}
	if len(ciphertext) > MaxCiphertextBytes {
		return domain.VideoSegment{}, false, domain.ErrIntegrity
	}
	sum := sha256.Sum256(ciphertext)
	if len(stored.SHA256) != len(sum) || subtle.ConstantTimeCompare(sum[:], stored.SHA256) != 1 {
		return domain.VideoSegment{}, false, domain.ErrIntegrity
	}
	depCtx, cancel = dependencyContext(ctx)
	dek, err := s.keys.Unwrap(depCtx, stored.WrappedDEK, dekAAD(stored.KeyID, sessionID))
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, fmt.Errorf("%w: unwrapping video data key: %v", domain.ErrUnavailable, err)
	}
	defer zero(dek)
	plain, err := open(dek, ciphertext, segmentAAD(sessionID, stored.FirstSequence, stored.LastSequence))
	if err != nil {
		return domain.VideoSegment{}, false, domain.ErrIntegrity
	}
	defer zero(plain)
	var segment domain.VideoSegment
	if err := json.Unmarshal(plain, &segment); err != nil {
		return domain.VideoSegment{}, false, domain.ErrIntegrity
	}
	if err := ValidateSegment(segment); err != nil || segment.SessionID != sessionID ||
		segment.FirstSequence != stored.FirstSequence || segment.LastSequence != stored.LastSequence {
		return domain.VideoSegment{}, false, domain.ErrIntegrity
	}
	return segment, stored.Complete, nil
}

func (s *RecorderService) auditRefusedRead(ctx context.Context, callerID, sessionID string) {
	write, firstUnwritten := s.readRefusals.Take(callerID)
	if !write {
		if firstUnwritten {
			log.Printf("video-recorder: refused video reads by user %q are no longer written one by one (budget spent)", callerID)
		}
		return
	}
	depCtx, cancel := dependencyContext(ctx)
	err := s.audit.EmitEvent(depCtx, callerID, AuditActionRead, "session", sessionID, false)
	cancel()
	if err != nil {
		log.Printf("video-recorder: refusal of video read for session %q by user %q could not be audited: %v", sessionID, callerID, err)
	}
}

func dependencyContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, dependencyTimeout)
}

func usableSessionID(id string) bool {
	if id == "" || len(id) > maxSessionIDBytes || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func usableActorRole(role string) bool {
	if role == "" || len(role) > maxActorRoleBytes || !utf8.ValidString(role) {
		return false
	}
	for _, r := range role {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func newDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	return dek, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func dekAAD(keyID, sessionID string) []byte {
	return []byte(fmt.Sprintf("openbastion/video-dek/v1|%d:%s|%d:%s", len(keyID), keyID, len(sessionID), sessionID))
}

func segmentAAD(sessionID string, first, last int64) []byte {
	return []byte(fmt.Sprintf("%s|%d:%s|%d|%d", recordingFormat, len(sessionID), sessionID, first, last))
}

func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("encrypted segment is too short")
	}
	return gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomObjectKey() (string, error) {
	var id [32]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return "", err
	}
	return "recordings/v1/" + hex.EncodeToString(id[:]), nil
}

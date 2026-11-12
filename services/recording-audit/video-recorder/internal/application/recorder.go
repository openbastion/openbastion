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
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/pkg/refusalbudget"
	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

const (
	dependencyTimeout = 5 * time.Second
	MaxFrameBytes     = 4 << 20
	MaxSegmentBytes   = 4 << 20
	// A read serves the run of segments from its first, up to these bounds (ADR-0093): the
	// Gateway's 4 MiB, and half a minute of frames at 50 ms.
	MaxReadFrames                 = 600
	MaxReadBytes                  = 4 << 20
	readFetchConcurrency          = 16
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
	// recordingFormatV2 seals a segment that holds a partial frame (ADR-0092 §5). A segment of key
	// frames only keeps the format 1, byte for byte; a segment opened as format 1 may hold no
	// partial frame, so a format 2 segment cannot pass for an older one.
	recordingFormatV2 = "openbastion/video-segment/v2"
	// CodecPNG is a key frame: a whole PNG. CodecPNGDelta is a partial frame: the screen-stream
	// FRAME_DELTA message, as the operator received it (ADR-0092).
	CodecPNG           = "png"
	CodecPNGDelta      = "png-delta-v1"
	MaxCiphertextBytes = 8 << 20
	maxActorRoles      = 100
	maxActorRoleBytes  = 128
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
	// The screen a partial frame applies to: the size of the last key frame. A partial frame before
	// any key frame, or of another size, is refused (ADR-0092 §2).
	screenWidth, screenHeight int
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
		if frame.Codec != CodecPNG && frame.Codec != CodecPNGDelta {
			return fmt.Errorf("%w: only PNG key frames and partial frames are accepted", domain.ErrInvalidSegment)
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
		if frame.Codec == CodecPNGDelta {
			if _, _, err := validateDeltaFrame(frame, segment.FirstSequence+int64(i)); err != nil {
				return fmt.Errorf("%w: frame %d: %v", domain.ErrInvalidSegment, i, err)
			}
		} else if _, _, err := pngSize(frame.Data); err != nil {
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

// pngSize reads a PNG's size and checks it is a screen the Recorder accepts.
func pngSize(data []byte) (int, int, error) {
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || int64(cfg.Width)*int64(cfg.Height) > MaxFramePixels {
		return 0, 0, errors.New("not an allowed PNG image")
	}
	return cfg.Width, cfg.Height, nil
}

// validateDeltaFrame checks a partial frame (ADR-0092): a FRAME_DELTA message within its bounds, of
// the sequence and the time the segment gives it, each rectangle a PNG of exactly its size. It
// returns the size of the screen the frame applies to.
func validateDeltaFrame(frame domain.VideoFrame, sequence int64) (int, int, error) {
	message, err := screenstream.Decode(frame.Data)
	if err != nil {
		return 0, 0, err
	}
	if message.Type != screenstream.TypeFrameDelta || int64(message.Sequence) != sequence ||
		!message.Timestamp.Equal(frame.Timestamp) ||
		int64(message.Width)*int64(message.Height) > MaxFramePixels {
		return 0, 0, errors.New("not the partial frame of this sequence and time")
	}
	for j, rect := range message.Rects {
		width, height, err := pngSize(rect.PNG)
		if err != nil || uint32(width) != rect.Width || uint32(height) != rect.Height {
			return 0, 0, fmt.Errorf("rectangle %d is not a PNG of its size", j)
		}
	}
	return int(message.Width), int(message.Height), nil
}

// segmentFormat is the format a segment is sealed in: 2 when it holds a partial frame.
func segmentFormat(segment domain.VideoSegment) string {
	for _, frame := range segment.Frames {
		if frame.Codec == CodecPNGDelta {
			return recordingFormatV2
		}
	}
	return recordingFormat
}

// followScreen checks that each partial frame of the segment applies to the screen of the key
// frame before it, and keeps that screen's size for the next segment.
func (w *RecordingWriter) followScreen(segment domain.VideoSegment) error {
	width, height := w.screenWidth, w.screenHeight
	for i, frame := range segment.Frames {
		if frame.Codec == CodecPNG {
			var err error
			if width, height, err = pngSize(frame.Data); err != nil {
				return fmt.Errorf("%w: frame %d is not an allowed PNG image", domain.ErrInvalidSegment, i)
			}
			continue
		}
		deltaWidth, deltaHeight, err := validateDeltaFrame(frame, segment.FirstSequence+int64(i))
		if err != nil {
			return fmt.Errorf("%w: frame %d: %v", domain.ErrInvalidSegment, i, err)
		}
		if width == 0 || deltaWidth != width || deltaHeight != height {
			return fmt.Errorf("%w: frame %d is a partial frame without the key frame of its screen", domain.ErrInvalidSegment, i)
		}
	}
	w.screenWidth, w.screenHeight = width, height
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
	if err := w.followScreen(segment); err != nil {
		return err
	}
	plain, err := json.Marshal(segment)
	if err != nil {
		return fmt.Errorf("encoding video segment: %w", err)
	}
	defer zero(plain)
	ciphertext, err := seal(w.dek, plain, segmentAAD(segmentFormat(segment), segment.SessionID, segment.FirstSequence, segment.LastSequence))
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

	// The run of stored segments from firstSequence, without a gap (ADR-0093): one segment per frame
	// as the proxy records them, so at most MaxReadFrames of them.
	depCtx, cancel = dependencyContext(ctx)
	stored, err := s.repo.GetSegmentsFrom(depCtx, sessionID, firstSequence, MaxReadFrames)
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, err
	}
	if len(stored) == 0 || stored[0].FirstSequence != firstSequence {
		return domain.VideoSegment{}, false, domain.ErrNotFound
	}
	run := 1
	for run < len(stored) && stored[run].FirstSequence == stored[run-1].LastSequence+1 &&
		stored[run].KeyID == stored[0].KeyID {
		run++
	}
	stored = stored[:run]
	// One audit event for the read, before anything is fetched or decrypted, naming the range
	// it may serve: what is served is that range or a beginning of it (ADR-0070, ADR-0093).
	depCtx, cancel = dependencyContext(ctx)
	err = s.audit.EmitEvent(depCtx, callerID, AuditActionRead, "session", sessionID, true, map[string]string{
		"first_sequence": strconv.FormatInt(firstSequence, 10),
		"last_sequence":  strconv.FormatInt(stored[len(stored)-1].LastSequence, 10),
	})
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, fmt.Errorf("%w: recording the video read: %v", domain.ErrUnavailable, err)
	}
	ciphertexts, err := s.fetchSegments(ctx, stored)
	if err != nil {
		return domain.VideoSegment{}, false, err
	}
	depCtx, cancel = dependencyContext(ctx)
	dek, err := s.keys.Unwrap(depCtx, stored[0].WrappedDEK, dekAAD(stored[0].KeyID, sessionID))
	cancel()
	if err != nil {
		return domain.VideoSegment{}, false, fmt.Errorf("%w: unwrapping video data key: %v", domain.ErrUnavailable, err)
	}
	defer zero(dek)
	// Each segment verified on its own before it joins the answer; one that fails refuses all of
	// it. The answer stops before MaxReadFrames frames or MaxReadBytes of frame data, and always
	// holds its first segment.
	result := domain.VideoSegment{SessionID: sessionID, FirstSequence: firstSequence}
	var frameBytes int
	for i, meta := range stored {
		sum := sha256.Sum256(ciphertexts[i])
		if len(meta.SHA256) != len(sum) || subtle.ConstantTimeCompare(sum[:], meta.SHA256) != 1 {
			return domain.VideoSegment{}, false, domain.ErrIntegrity
		}
		segment, err := openSegment(dek, ciphertexts[i], sessionID, meta.FirstSequence, meta.LastSequence)
		if err != nil || segment.SessionID != sessionID ||
			segment.FirstSequence != meta.FirstSequence || segment.LastSequence != meta.LastSequence {
			return domain.VideoSegment{}, false, domain.ErrIntegrity
		}
		size := 0
		for _, frame := range segment.Frames {
			size += len(frame.Data)
		}
		if i > 0 && (len(result.Frames)+len(segment.Frames) > MaxReadFrames || frameBytes+size > MaxReadBytes) {
			break
		}
		result.Frames = append(result.Frames, segment.Frames...)
		result.LastSequence = segment.LastSequence
		frameBytes += size
	}
	return result, stored[0].Complete, nil
}

// fetchSegments reads the encrypted segments from the object store, a few at a time and in order.
func (s *RecorderService) fetchSegments(ctx context.Context, stored []domain.StoredSegment) ([][]byte, error) {
	out := make([][]byte, len(stored))
	errs := make([]error, len(stored))
	limit := make(chan struct{}, readFetchConcurrency)
	var wg sync.WaitGroup
	for i, meta := range stored {
		wg.Add(1)
		limit <- struct{}{}
		go func(i int, key string) {
			defer wg.Done()
			defer func() { <-limit }()
			depCtx, cancel := dependencyContext(ctx)
			defer cancel()
			ciphertext, err := s.objects.Get(depCtx, key)
			if err == nil && len(ciphertext) > MaxCiphertextBytes {
				err = domain.ErrIntegrity
			}
			out[i], errs[i] = ciphertext, err
		}(i, meta.ObjectKey)
	}
	wg.Wait()
	for _, err := range errs {
		if errors.Is(err, domain.ErrIntegrity) {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("%w: reading encrypted video segment: %v", domain.ErrUnavailable, err)
		}
	}
	return out, nil
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
	err := s.audit.EmitEvent(depCtx, callerID, AuditActionRead, "session", sessionID, false, nil)
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

// openSegment decrypts a stored segment under format 1, then format 2, and keeps it only if the
// format it opened under is the one its frames call for (ADR-0092 §5): a format 2 segment cannot
// pass for a format 1 one, nor the reverse.
func openSegment(dek, ciphertext []byte, sessionID string, first, last int64) (domain.VideoSegment, error) {
	format := recordingFormat
	plain, err := open(dek, ciphertext, segmentAAD(format, sessionID, first, last))
	if err != nil {
		format = recordingFormatV2
		plain, err = open(dek, ciphertext, segmentAAD(format, sessionID, first, last))
	}
	if err != nil {
		return domain.VideoSegment{}, domain.ErrIntegrity
	}
	defer zero(plain)
	var segment domain.VideoSegment
	if err := json.Unmarshal(plain, &segment); err != nil {
		return domain.VideoSegment{}, domain.ErrIntegrity
	}
	if err := ValidateSegment(segment); err != nil || segmentFormat(segment) != format {
		return domain.VideoSegment{}, domain.ErrIntegrity
	}
	return segment, nil
}

func dekAAD(keyID, sessionID string) []byte {
	return []byte(fmt.Sprintf("openbastion/video-dek/v1|%d:%s|%d:%s", len(keyID), keyID, len(sessionID), sessionID))
}

func segmentAAD(format, sessionID string, first, last int64) []byte {
	return []byte(fmt.Sprintf("%s|%d:%s|%d|%d", format, len(sessionID), sessionID, first, last))
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

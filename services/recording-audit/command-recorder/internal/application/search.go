package application

// The search of recorded commands (ADR-0080): no index and no copy in clear. The sessions of a
// bounded window are decrypted on the fly, after each one's authorization, and the plaintext is
// dropped. The search is written to the audit before anything is decrypted, with a keyed digest
// of the text searched, never the text; every session the answer discloses commands of is a
// recording.read, written before the answer is served. Any of it unwritten: nothing is served.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
)

// The bounds of a search (ADR-0080, points 2 and 6): constants, not settings.
const (
	SearchMinQuery      = 3
	SearchMaxQuery      = 256
	SearchMaxWindow     = 31 * 24 * time.Hour
	SearchMaxSessions   = 200
	SearchMaxPerSession = 50
	// SearchMaxHits bounds the whole answer: 200 sessions of 50 commands of 8 KiB would be 80 MB.
	SearchMaxHits = 1000
	// SearchKeyBytes is the size of the key of the digest of q.
	SearchKeyBytes = 32
)

// AuditActionSearch is the audit action of a search, written before anything is decrypted.
const AuditActionSearch = "recording.search"

// ErrSearchDisabled: no key for the digest of q, so no search (ADR-0080, point 4).
var ErrSearchDisabled = errors.New("the search of recordings is not configured")

// ErrInvalidSearch: a query or a window outside the bounds.
var ErrInvalidSearch = errors.New("invalid search")

// DetailedAuditEmitter writes an event with bounded details (ADR-0068).
type DetailedAuditEmitter interface {
	EmitEventWithDetails(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error
}

// SearchHit is one command found, and when it was typed.
type SearchHit struct {
	Timestamp time.Time
	Command   string
}

// SearchSession is a session of which the answer discloses commands.
type SearchSession struct {
	SessionID string
	Hits      []SearchHit
}

// SearchResult is the answer to a search.
type SearchResult struct {
	SearchID string
	Sessions []SearchSession
	// Truncated: there were more sessions in the window than one search looks into, or more
	// commands found than one answer holds; a narrower window finds the rest.
	Truncated bool
}

// WithSearchKey turns the search on, with the key of the digest of q (SEARCH_AUDIT_KEY_FILE).
func (s *RecorderService) WithSearchKey(key []byte) *RecorderService {
	s.searchKey = append([]byte(nil), key...)
	return s
}

// SearchEnabled says whether the search has its key.
func (s *RecorderService) SearchEnabled() bool { return len(s.searchKey) == SearchKeyBytes }

// fold is how a query and a command are compared: NFC, then Unicode case folding.
var folder = cases.Fold()

func fold(text string) string { return folder.String(norm.NFC.String(text)) }

// Search looks for q in the commands of the sessions whose recording started in [from, to).
// callerID and actorRoles are the Gateway's, from the verified token.
func (s *RecorderService) Search(ctx context.Context, callerID string, actorRoles []string, q string, from, to time.Time) (SearchResult, error) {
	if !s.SearchEnabled() {
		return SearchResult{}, ErrSearchDisabled
	}
	if callerID == "" {
		return SearchResult{}, fmt.Errorf("%w: searching recordings needs an authenticated user", domain.ErrForbidden)
	}
	needle := fold(q)
	if n := utf8.RuneCountInString(norm.NFC.String(q)); n < SearchMinQuery || n > SearchMaxQuery || !utf8.ValidString(q) {
		return SearchResult{}, fmt.Errorf("%w: the text searched is %d to %d characters", ErrInvalidSearch, SearchMinQuery, SearchMaxQuery)
	}
	if from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > SearchMaxWindow {
		return SearchResult{}, fmt.Errorf("%w: the window is from before to, at most %d days", ErrInvalidSearch, int(SearchMaxWindow.Hours()/24))
	}
	emitter, ok := s.audit.(DetailedAuditEmitter)
	if !ok {
		return SearchResult{}, fmt.Errorf("%w: no audit that writes a search's details", domain.ErrUnavailable)
	}

	candidates, err := s.repo.RecordingsStartedBetween(ctx, from, to, SearchMaxSessions+1)
	if err != nil {
		return SearchResult{}, err
	}
	result := SearchResult{}
	if len(candidates) > SearchMaxSessions {
		candidates, result.Truncated = candidates[:SearchMaxSessions], true
	}
	// Each session is authorized before anything of it is decrypted; a refused one is not
	// opened and not in the answer.
	var allowed []string
	for _, c := range candidates {
		ok, _, err := s.authz.CheckAccess(ctx, actorRoles, RecordingResource(c.SessionID), ActionRead)
		if err != nil {
			return SearchResult{}, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
		}
		if ok {
			allowed = append(allowed, c.SessionID)
		}
	}
	id, err := searchID()
	if err != nil {
		return SearchResult{}, err
	}
	result.SearchID = id
	mac := hmac.New(sha256.New, s.searchKey)
	mac.Write([]byte(needle))
	details := map[string]string{
		"from":       from.UTC().Format(time.RFC3339),
		"to":         to.UTC().Format(time.RFC3339),
		"candidates": strconv.Itoa(len(candidates)),
		"allowed":    strconv.Itoa(len(allowed)),
		"refused":    strconv.Itoa(len(candidates) - len(allowed)),
		"truncated":  strconv.FormatBool(result.Truncated),
		"q_hmac":     hex.EncodeToString(mac.Sum(nil)),
	}
	// Before anything is decrypted; unwritten, nothing is.
	if err := emitter.EmitEventWithDetails(ctx, callerID, AuditActionSearch, "recording_search", id, details, true); err != nil {
		return SearchResult{}, fmt.Errorf("%w (recording the search: %v)", domain.ErrUnavailable, err)
	}

	total := 0
	for _, sessionID := range allowed {
		if total >= SearchMaxHits {
			result.Truncated = true
			break
		}
		var hits []SearchHit
		err := s.repo.EachCommand(ctx, sessionID, func(e domain.CommandEntry) bool {
			if strings.Contains(fold(e.Command), needle) {
				hits = append(hits, SearchHit{Timestamp: e.Timestamp, Command: e.Command})
				total++
			}
			if total >= SearchMaxHits {
				result.Truncated = true
				return false
			}
			return len(hits) < SearchMaxPerSession
		})
		if err != nil {
			return SearchResult{}, err
		}
		if len(hits) > 0 {
			result.Sessions = append(result.Sessions, SearchSession{SessionID: sessionID, Hits: hits})
		}
	}
	// Every session whose commands the answer discloses is a read, written before it is served.
	for _, found := range result.Sessions {
		if err := emitter.EmitEventWithDetails(ctx, callerID, AuditActionRead, "session", found.SessionID, map[string]string{"search_id": id}, true); err != nil {
			return SearchResult{}, fmt.Errorf("%w (recording a read by the search: %v)", domain.ErrUnavailable, err)
		}
	}
	return result, nil
}

func searchID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "search-" + hex.EncodeToString(b), nil
}

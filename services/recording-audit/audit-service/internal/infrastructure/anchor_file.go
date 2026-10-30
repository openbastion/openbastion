package infrastructure

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// FileAnchorSink keeps anchors as JSON lines appended to a file (ADR-0028). The file must live
// where the database has no say — another volume, another host, an append-only (WORM) mount:
// this type cannot check that, the deployment must.
//
// The file is created when the sink is made; afterwards it is only ever appended to, never
// created again: a file that has disappeared is not a fresh start, it is anchors that cannot
// be read (domain.ErrAnchorsUnavailable).
type FileAnchorSink struct {
	path string
	mu   sync.Mutex
}

// anchorLine is one line of the file: an anchor (no kind — the format of ADR-0028, unchanged)
// or a checkpoint (kind "checkpoint", ADR-0032).
type anchorLine struct {
	Kind    string    `json:"kind,omitempty"`
	EventID string    `json:"event_id,omitempty"`
	Hash    string    `json:"hash,omitempty"`
	At      time.Time `json:"at"`
	KeyID   string    `json:"key_id"`
	MAC     string    `json:"mac"`

	Archive        string `json:"archive,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Count          int    `json:"count,omitempty"`
	FirstID        string `json:"first_id,omitempty"`
	PrevHash       string `json:"prev_hash,omitempty"`
	LastID         string `json:"last_id,omitempty"`
	LastHash       string `json:"last_hash,omitempty"`
	LastVersion    int    `json:"last_version,omitempty"`
	AnchorsCovered int    `json:"anchors_covered,omitempty"`
}

const checkpointKind = "checkpoint"

// NewFileAnchorSink opens (creating if needed, mode 0600) the anchor file at path. Its
// directory must exist: a mistyped path is an error at start-up, not anchors written nowhere.
func NewFileAnchorSink(path string) (*FileAnchorSink, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("the anchor file must be an absolute path")
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("the directory of the anchor file does not exist")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the anchor file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &FileAnchorSink{path: path}, nil
}

// Append adds one anchor at the end of the file and syncs it to disk before returning.
func (s *FileAnchorSink) Append(ctx context.Context, a domain.Anchor) error {
	return s.appendLine(anchorLine{EventID: a.EventID, Hash: hex.EncodeToString(a.Hash), At: a.At, KeyID: a.KeyID, MAC: hex.EncodeToString(a.MAC)})
}

// AppendCheckpoint adds one checkpoint at the end of the file, synced, as Append does.
func (s *FileAnchorSink) AppendCheckpoint(ctx context.Context, c domain.Checkpoint) error {
	return s.appendLine(anchorLine{Kind: checkpointKind, At: c.At, KeyID: c.KeyID, MAC: hex.EncodeToString(c.MAC),
		Archive: c.Archive, SHA256: hex.EncodeToString(c.SHA256), Count: c.Count, FirstID: c.FirstID,
		PrevHash: hex.EncodeToString(c.PrevHash), LastID: c.LastID, LastHash: hex.EncodeToString(c.LastHash),
		LastVersion: c.LastVersion, AnchorsCovered: c.AnchorsCovered})
}

func (s *FileAnchorSink) appendLine(l anchorLine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line, err := json.Marshal(l)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0) // never O_CREATE: see the type
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrAnchorsUnavailable, err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// All reads every anchor, in the order they were appended. A line that is neither an anchor nor
// a checkpoint is an error: the file was written by something else, or edited.
func (s *FileAnchorSink) All(ctx context.Context) ([]domain.Anchor, error) {
	anchors, _, err := s.read()
	return anchors, err
}

// Checkpoints reads every checkpoint, in the order they were appended.
func (s *FileAnchorSink) Checkpoints(ctx context.Context) ([]domain.Checkpoint, error) {
	_, checkpoints, err := s.read()
	return checkpoints, err
}

func (s *FileAnchorSink) read() ([]domain.Anchor, []domain.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: the anchor file is gone", domain.ErrAnchorsUnavailable)
		}
		return nil, nil, fmt.Errorf("%w: %v", domain.ErrAnchorsUnavailable, err)
	}
	var anchors []domain.Anchor
	var checkpoints []domain.Checkpoint
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		edited := fmt.Errorf("anchor line %d is not an anchor — the anchor file was edited", n)
		var l anchorLine
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil {
			return nil, nil, edited
		}
		mac, errMAC := hex.DecodeString(l.MAC)
		switch l.Kind {
		case "":
			hash, err := hex.DecodeString(l.Hash)
			if err != nil || errMAC != nil || l.EventID == "" || l.Archive != "" || l.LastID != "" {
				return nil, nil, edited
			}
			anchors = append(anchors, domain.Anchor{EventID: l.EventID, Hash: hash, At: l.At, KeyID: l.KeyID, MAC: mac})
		case checkpointKind:
			sum, err1 := hex.DecodeString(l.SHA256)
			prev, err2 := hex.DecodeString(l.PrevHash)
			last, err3 := hex.DecodeString(l.LastHash)
			if err1 != nil || err2 != nil || err3 != nil || errMAC != nil || l.Archive == "" || l.LastID == "" || l.EventID != "" {
				return nil, nil, edited
			}
			if len(prev) == 0 {
				prev = nil
			}
			checkpoints = append(checkpoints, domain.Checkpoint{Archive: l.Archive, SHA256: sum, Count: l.Count, FirstID: l.FirstID,
				PrevHash: prev, LastID: l.LastID, LastHash: last, LastVersion: l.LastVersion, AnchorsCovered: l.AnchorsCovered,
				At: l.At, KeyID: l.KeyID, MAC: mac})
		default:
			return nil, nil, edited
		}
	}
	return anchors, checkpoints, sc.Err()
}

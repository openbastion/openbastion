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

type anchorLine struct {
	EventID string    `json:"event_id"`
	Hash    string    `json:"hash"`
	At      time.Time `json:"at"`
	KeyID   string    `json:"key_id"`
	MAC     string    `json:"mac"`
}

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
	s.mu.Lock()
	defer s.mu.Unlock()
	line, err := json.Marshal(anchorLine{EventID: a.EventID, Hash: hex.EncodeToString(a.Hash), At: a.At, KeyID: a.KeyID, MAC: hex.EncodeToString(a.MAC)})
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

// All reads every anchor, in the order they were appended. A line that is not an anchor is an
// error: the file was written by something else, or edited.
func (s *FileAnchorSink) All(ctx context.Context) ([]domain.Anchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: the anchor file is gone", domain.ErrAnchorsUnavailable)
		}
		return nil, fmt.Errorf("%w: %v", domain.ErrAnchorsUnavailable, err)
	}
	var out []domain.Anchor
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		var l anchorLine
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil {
			return nil, fmt.Errorf("anchor line %d is not an anchor — the anchor file was edited", n)
		}
		hash, err1 := hex.DecodeString(l.Hash)
		mac, err2 := hex.DecodeString(l.MAC)
		if err1 != nil || err2 != nil || l.EventID == "" {
			return nil, fmt.Errorf("anchor line %d is not an anchor — the anchor file was edited", n)
		}
		out = append(out, domain.Anchor{EventID: l.EventID, Hash: hash, At: l.At, KeyID: l.KeyID, MAC: mac})
	}
	return out, sc.Err()
}

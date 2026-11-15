package infrastructure

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// FileArchiver writes the archives of the chain (ADR-0032) as JSON lines, one file per month,
// into a directory the database does not control — another volume, ideally append-only (WORM):
// this type cannot check that, the deployment must. An archive is never overwritten.
type FileArchiver struct {
	dir string
}

// archiveLine is one archived event, every field as the database holds it.
type archiveLine struct {
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"ts"`
	ActorID      string            `json:"actor_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Details      map[string]string `json:"details,omitempty"`
	Success      bool              `json:"success"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
	HashVersion  int               `json:"hash_version"`
	Emitter      string            `json:"emitter"`
	KeyID        string            `json:"chain_key_id"`
}

const maxArchiveReadBytes = 256 << 20

var archiveName = regexp.MustCompile(`^audit-[0-9]{4}-[0-9]{2}\.jsonl$`)

// NewFileArchiver checks that dir is an absolute path to an existing directory.
func NewFileArchiver(dir string) (*FileArchiver, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("the archive directory must be an absolute path")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, errors.New("the archive directory does not exist")
	}
	return &FileArchiver{dir: dir}, nil
}

func (a *FileArchiver) path(name string) (string, error) {
	if !archiveName.MatchString(name) {
		return "", fmt.Errorf("%q is not an archive name", name)
	}
	return filepath.Join(a.dir, name), nil
}

// Write writes the archive in a temporary file, syncs it, renames it into place, syncs the
// directory, then reads it back and returns the SHA-256 of what is on disk — after checking it
// is what was meant to be written. An archive of that name already there is kept if it holds
// exactly these events, and is an error otherwise: it is never overwritten.
func (a *FileArchiver) Write(ctx context.Context, name string, events []*domain.Event) ([]byte, error) {
	path, err := a.path(name)
	if err != nil {
		return nil, err
	}
	var content bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(archiveLine{ID: e.ID, Timestamp: e.Timestamp, ActorID: e.ActorID, Action: e.Action,
			ResourceType: e.ResourceType, ResourceID: e.ResourceID, Details: e.Details, Success: e.Success, PrevHash: hex.EncodeToString(e.PrevHash),
			Hash: hex.EncodeToString(e.Hash), HashVersion: e.HashVersion, Emitter: e.Emitter, KeyID: e.KeyID})
		if err != nil {
			return nil, err
		}
		content.Write(line)
		content.WriteByte('\n')
	}
	want := sha256.Sum256(content.Bytes())

	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, content.Bytes()) {
			return want[:], nil
		}
		return nil, fmt.Errorf("archive %s already exists and holds something else — it is never overwritten", name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	tmp, err := os.CreateTemp(a.dir, "."+name+".tmp-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name()) // gone once renamed; left over only on failure
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(content.Bytes()); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// Link, not rename: a link fails if the name exists, so an archive that appeared in the
	// meantime is never replaced.
	if err := os.Link(tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("putting archive %s in place: %w", name, err)
	}
	if d, err := os.Open(a.dir); err == nil {
		err = d.Sync()
		d.Close()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	got, err := a.Sum(ctx, name)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got, want[:]) {
		return nil, fmt.Errorf("archive %s does not read back as written", name)
	}
	return got, nil
}

// Read parses an archive without modifying it. Every line must be one complete, strict
// archiveLine; malformed, unknown, truncated, or oversized records fail closed.
func (a *FileArchiver) Read(ctx context.Context, name string) ([]*domain.Event, []byte, error) {
	path, err := a.path(name)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxArchiveReadBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxArchiveReadBytes {
		return nil, nil, fmt.Errorf("archive %s exceeds the maximum read size", name)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, nil, fmt.Errorf("archive %s is empty or lacks its final JSONL newline", name)
	}
	sum := sha256.Sum256(raw)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var events []*domain.Event
	for line := 1; sc.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var record archiveLine
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&record); err != nil {
			return nil, nil, fmt.Errorf("archive %s line %d: invalid JSON record: %w", name, line, err)
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, nil, fmt.Errorf("archive %s line %d: trailing JSON data", name, line)
		}
		prev, errPrev := hex.DecodeString(record.PrevHash)
		hash, errHash := hex.DecodeString(record.Hash)
		if record.ID == "" || record.Timestamp.IsZero() || errPrev != nil || errHash != nil || len(hash) == 0 {
			return nil, nil, fmt.Errorf("archive %s line %d: missing or malformed event fields", name, line)
		}
		events = append(events, &domain.Event{ID: record.ID, Timestamp: record.Timestamp, ActorID: record.ActorID,
			Action: record.Action, ResourceType: record.ResourceType, ResourceID: record.ResourceID,
			Details: record.Details, Success: record.Success, PrevHash: prev, Hash: hash,
			HashVersion: record.HashVersion, Emitter: record.Emitter, KeyID: record.KeyID})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading archive %s: %w", name, err)
	}
	if len(events) == 0 {
		return nil, nil, fmt.Errorf("archive %s is empty", name)
	}
	return events, sum[:], nil
}

// Sum returns the SHA-256 of the archive as it is on disk.
func (a *FileArchiver) Sum(ctx context.Context, name string) ([]byte, error) {
	path, err := a.path(name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

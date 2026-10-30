package infrastructure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"ts"`
	ActorID      string    `json:"actor_id"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Success      bool      `json:"success"`
	PrevHash     string    `json:"prev_hash"`
	Hash         string    `json:"hash"`
	HashVersion  int       `json:"hash_version"`
	Emitter      string    `json:"emitter"`
	KeyID        string    `json:"chain_key_id"`
}

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
			ResourceType: e.ResourceType, ResourceID: e.ResourceID, Success: e.Success, PrevHash: hex.EncodeToString(e.PrevHash),
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

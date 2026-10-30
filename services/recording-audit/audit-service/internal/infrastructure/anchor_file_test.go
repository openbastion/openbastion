package infrastructure_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// The anchor file (ADR-0028): appended to, read back in order, private, and never re-created.
func TestFileAnchorSink_AppendsAndReadsBackInOrder(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	sink, err := infrastructure.NewFileAnchorSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file is not created private: %v %v", info, err)
	}
	if all, err := sink.All(ctx); err != nil || len(all) != 0 {
		t.Fatalf("a new file: %v %v", all, err)
	}
	at := time.Date(2026, 10, 30, 12, 0, 0, 123456000, time.UTC)
	for i, id := range []string{"evt_1", "evt_2"} {
		if err := sink.Append(ctx, domain.Anchor{EventID: id, Hash: []byte{byte(i), 1}, At: at, KeyID: "k", MAC: []byte{9, byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := sink.All(ctx)
	if err != nil || len(all) != 2 || all[0].EventID != "evt_1" || all[1].EventID != "evt_2" || string(all[1].Hash) != "\x01\x01" || !all[1].At.Equal(at) || string(all[1].MAC) != "\x09\x01" {
		t.Fatalf("read back %+v %v", all, err)
	}
	// Reopening an existing file keeps what it holds.
	again, err := infrastructure.NewFileAnchorSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if all, _ := again.All(ctx); len(all) != 2 {
		t.Fatalf("reopened: %d anchors, want 2", len(all))
	}
}

func TestFileAnchorSink_AFileThatIsGoneIsUnavailable_NotAFreshStart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	sink, _ := infrastructure.NewFileAnchorSink(path)
	_ = os.Remove(path)
	if _, err := sink.All(ctx); !errors.Is(err, domain.ErrAnchorsUnavailable) {
		t.Fatalf("All on a file that is gone: %v", err)
	}
	if err := sink.Append(ctx, domain.Anchor{EventID: "evt_1"}); !errors.Is(err, domain.ErrAnchorsUnavailable) {
		t.Fatalf("Append on a file that is gone: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Append re-created the file")
	}
}

func TestFileAnchorSink_ALineThatIsNotAnAnchorIsAnError(t *testing.T) {
	ctx := context.Background()
	for _, line := range []string{"not json", `{"event_id":"evt_1","hash":"zz","mac":"00"}`, `{"event_id":"","hash":"00","mac":"00"}`, `{"event_id":"evt_1","hash":"00","mac":"00","extra":1}`} {
		path := filepath.Join(t.TempDir(), "anchors.jsonl")
		sink, _ := infrastructure.NewFileAnchorSink(path)
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := sink.All(ctx)
		if err == nil || errors.Is(err, domain.ErrAnchorsUnavailable) || !strings.Contains(err.Error(), "edited") {
			t.Fatalf("%q: %v, want an error saying the file was edited", line, err)
		}
	}
}

func TestNewFileAnchorSink_RefusesAPathThatCannotBeRight(t *testing.T) {
	for _, path := range []string{"", "anchors.jsonl", "/nonexistent-dir-for-openbastion/anchors.jsonl"} {
		if _, err := infrastructure.NewFileAnchorSink(path); err == nil {
			t.Fatalf("%q was accepted", path)
		}
	}
}

// Checkpoints (ADR-0032) live in the anchor file, in order, without changing how an anchor is
// written: a file written before ADR-0032 reads the same.
func TestFileAnchorSink_KeepsCheckpointsWithTheAnchors_AndAnAnchorLineIsUnchanged(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	sink, _ := infrastructure.NewFileAnchorSink(path)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	_ = sink.Append(ctx, domain.Anchor{EventID: "evt_1", Hash: []byte{1}, At: at, KeyID: "k", MAC: []byte{9}})
	c := domain.Checkpoint{Archive: "audit-2025-01.jsonl", SHA256: []byte{7}, Count: 3, FirstID: "evt_0", LastID: "evt_2",
		LastHash: []byte{2}, LastVersion: 3, AnchorsCovered: 1, At: at, KeyID: "k", MAC: []byte{8}}
	if err := sink.AppendCheckpoint(ctx, c); err != nil {
		t.Fatal(err)
	}
	_ = sink.Append(ctx, domain.Anchor{EventID: "evt_5", Hash: []byte{5}, At: at, KeyID: "k", MAC: []byte{9}})
	raw, _ := os.ReadFile(path)
	first := strings.SplitN(string(raw), "\n", 2)[0]
	if first != `{"event_id":"evt_1","hash":"01","at":"2026-10-30T12:00:00Z","key_id":"k","mac":"09"}` {
		t.Fatalf("an anchor line changed format: %s", first)
	}
	anchors, err := sink.All(ctx)
	if err != nil || len(anchors) != 2 || anchors[1].EventID != "evt_5" {
		t.Fatalf("anchors %+v %v", anchors, err)
	}
	cps, err := sink.Checkpoints(ctx)
	if err != nil || len(cps) != 1 {
		t.Fatalf("checkpoints %+v %v", cps, err)
	}
	got := cps[0]
	if got.Archive != c.Archive || string(got.SHA256) != "\x07" || got.Count != 3 || got.FirstID != "evt_0" || got.PrevHash != nil ||
		got.LastID != "evt_2" || string(got.LastHash) != "\x02" || got.LastVersion != 3 || got.AnchorsCovered != 1 ||
		!got.At.Equal(at) || got.KeyID != "k" || string(got.MAC) != "\x08" {
		t.Fatalf("checkpoint read back %+v", got)
	}
}

func TestFileAnchorSink_ALineOfAnUnknownKindOrHalfOfEachIsAnError(t *testing.T) {
	for name, line := range map[string]string{
		"unknown kind":                 `{"kind":"other","at":"2026-10-30T12:00:00Z","key_id":"k","mac":"09"}`,
		"a checkpoint with no archive": `{"kind":"checkpoint","last_id":"evt_2","at":"2026-10-30T12:00:00Z","key_id":"k","mac":"09"}`,
		"a checkpoint naming an event": `{"kind":"checkpoint","event_id":"evt_1","archive":"a","last_id":"e","at":"2026-10-30T12:00:00Z","key_id":"k","mac":"09"}`,
		"an anchor with an archive":    `{"event_id":"evt_1","hash":"01","archive":"a","at":"2026-10-30T12:00:00Z","key_id":"k","mac":"09"}`,
	} {
		path := filepath.Join(t.TempDir(), "anchors.jsonl")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sink, _ := infrastructure.NewFileAnchorSink(path)
		if _, err := sink.Checkpoints(context.Background()); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
}

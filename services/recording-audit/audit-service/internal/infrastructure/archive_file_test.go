package infrastructure_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func archivedEvents() []*domain.Event {
	at := time.Date(2025, 1, 3, 9, 0, 0, 123456000, time.UTC)
	return []*domain.Event{
		{ID: "evt_1", Timestamp: at, ActorID: "u_1", Action: "session.read", ResourceType: "session", ResourceID: "s1", Details: map[string]string{"ticket": "CHG0001234"}, Success: true, Hash: []byte{1}, HashVersion: 4, Emitter: "session-broker", KeyID: "k"},
		{ID: "evt_2", Timestamp: at.Add(time.Second), Action: "session.expire", ResourceType: "session", ResourceID: "s1", PrevHash: []byte{1}, Hash: []byte{2}, HashVersion: 3, KeyID: "k"},
	}
}

// An archive (ADR-0032): every field of every event, private, read back, never overwritten.
func TestFileArchiver_WritesEveryFieldAndReadsBack(t *testing.T) {
	dir := t.TempDir()
	a, err := infrastructure.NewFileArchiver(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sum, err := a.Write(ctx, "audit-2025-01.jsonl", archivedEvents())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit-2025-01.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(raw); string(want[:]) != string(sum) {
		t.Fatal("the sum returned is not the sum of the file")
	}
	want := `{"id":"evt_1","ts":"2025-01-03T09:00:00.123456Z","actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"s1","details":{"ticket":"CHG0001234"},"success":true,"prev_hash":"","hash":"01","hash_version":4,"emitter":"session-broker","chain_key_id":"k"}
{"id":"evt_2","ts":"2025-01-03T09:00:01.123456Z","actor_id":"","action":"session.expire","resource_type":"session","resource_id":"s1","success":false,"prev_hash":"01","hash":"02","hash_version":3,"emitter":"","chain_key_id":"k"}
`
	if string(raw) != want {
		t.Fatalf("archive:\n%s\nwant:\n%s", raw, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("%d files in the directory, want only the archive (no temporary left)", len(entries))
	}
	if again, err := a.Sum(ctx, "audit-2025-01.jsonl"); err != nil || string(again) != string(sum) {
		t.Fatalf("Sum: %v", err)
	}
}

func TestFileArchiver_AnArchiveIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	a, _ := infrastructure.NewFileArchiver(dir)
	ctx := context.Background()
	first, err := a.Write(ctx, "audit-2025-01.jsonl", archivedEvents())
	if err != nil {
		t.Fatal(err)
	}
	// The same events again (a pass interrupted after the write): kept, same sum.
	if again, err := a.Write(ctx, "audit-2025-01.jsonl", archivedEvents()); err != nil || string(again) != string(first) {
		t.Fatalf("the same archive written again: %v", err)
	}
	// Other events under the same name: refused, the file untouched.
	before, _ := os.ReadFile(filepath.Join(dir, "audit-2025-01.jsonl"))
	if _, err := a.Write(ctx, "audit-2025-01.jsonl", archivedEvents()[:1]); err == nil || !strings.Contains(err.Error(), "never overwritten") {
		t.Fatalf("got %v, want a refusal", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "audit-2025-01.jsonl"))
	if string(before) != string(after) {
		t.Fatal("the archive was changed")
	}
}

func TestFileArchiver_RefusesWhatCannotBeRight(t *testing.T) {
	for _, dir := range []string{"", "archives", "/nonexistent-dir-for-openbastion"} {
		if _, err := infrastructure.NewFileArchiver(dir); err == nil {
			t.Fatalf("archive directory %q accepted", dir)
		}
	}
	a, _ := infrastructure.NewFileArchiver(t.TempDir())
	for _, name := range []string{"../audit-2025-01.jsonl", "audit-2025-1.jsonl", "audit.jsonl", "x/audit-2025-01.jsonl", ""} {
		if _, err := a.Write(context.Background(), name, archivedEvents()); err == nil {
			t.Fatalf("archive name %q accepted", name)
		}
	}
	if _, err := a.Sum(context.Background(), "audit-2025-02.jsonl"); err == nil {
		t.Fatal("the sum of an archive that does not exist")
	}
}

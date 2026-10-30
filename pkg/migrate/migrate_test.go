package migrate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoad_ReadsNumberedFilesInOrder(t *testing.T) {
	ms, err := Load(fstest.MapFS{
		"002_more.sql": {Data: []byte("SELECT 2;")},
		"001_init.sql": {Data: []byte("SELECT 1;")},
		"003_a_b9.sql": {Data: []byte("SELECT 3;")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 {
		t.Fatalf("%d migrations, want 3", len(ms))
	}
	for i, want := range []string{"001_init.sql", "002_more.sql", "003_a_b9.sql"} {
		if ms[i].Version != i+1 || ms[i].Name != want {
			t.Fatalf("position %d: %d %s, want %d %s", i, ms[i].Version, ms[i].Name, i+1, want)
		}
	}
	sum := sha256.Sum256([]byte("SELECT 2;"))
	if string(ms[1].Checksum) != string(sum[:]) || ms[1].SQL != "SELECT 2;" {
		t.Fatal("the checksum is the SHA-256 of the file's text")
	}
}

func TestLoad_RefusesWhatIsNotAContinuousNumberedSet(t *testing.T) {
	for name, files := range map[string]fstest.MapFS{
		"a gap":                {"001_init.sql": {}, "003_more.sql": {}},
		"a duplicate":          {"001_init.sql": {}, "001_other.sql": {}},
		"not starting at 001":  {"002_init.sql": {}},
		"no number":            {"001_init.sql": {}, "init.sql": {}},
		"two digits":           {"01_init.sql": {}},
		"capitals":             {"001_Init.sql": {}},
		"a space":              {"001_in it.sql": {}},
		"another extension":    {"001_init.sql": {}, "002_more.txt": {}},
		"nothing":              {},
		"version 000":          {"000_init.sql": {}, "001_more.sql": {}},
		"a dash, not an under": {"001-init.sql": {}},
	} {
		if _, err := Load(files); err == nil {
			t.Fatalf("%s: loaded, want a refusal", name)
		}
	}
}

func TestLockKey_OnePerComponent(t *testing.T) {
	seen := map[int64]string{}
	for _, c := range []string{"", "authentication", "authorization", "session-broker", "password-vault", "audit-service", "command-recorder"} {
		k := LockKey(c)
		if other, ok := seen[k]; ok {
			t.Fatalf("%q and %q share lock %d", c, other, k)
		}
		seen[k] = c
		if LockKey(c) != k {
			t.Fatalf("the lock of %q is not stable", c)
		}
	}
}

func TestApply_NeedsAComponentName(t *testing.T) {
	_, err := Apply(context.Background(), nil, "", fstest.MapFS{"001_init.sql": {}})
	if err == nil || !strings.Contains(err.Error(), "component") {
		t.Fatalf("got %v, want a refusal naming the component", err)
	}
}

func TestResult_LogSaysWhatWasAppliedAndWhatIsUnknown(t *testing.T) {
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	Result{Current: 2}.Log("svc", logf)
	if len(lines) != 0 {
		t.Fatalf("nothing applied, nothing unknown: %q, want no line", lines)
	}
	Result{Applied: []int{1, 2}, Current: 2, Unknown: []int{3}}.Log("svc", logf)
	if len(lines) != 2 || !strings.Contains(lines[0], "[1 2] applied") || !strings.Contains(lines[0], "version 2") ||
		!strings.Contains(lines[1], "WARNING") || !strings.Contains(lines[1], "[3]") || !strings.Contains(lines[1], "newer than this binary") {
		t.Fatalf("got %q", lines)
	}
}

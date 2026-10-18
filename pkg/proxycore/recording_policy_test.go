package proxycore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseRecordingPolicy(t *testing.T) {
	for in, want := range map[string]RecordingPolicy{"": RecordingRequired, "required": RecordingRequired, "best-effort": RecordingBestEffort} {
		got, err := ParseRecordingPolicy(in)
		if err != nil || got != want {
			t.Errorf("ParseRecordingPolicy(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	// A typo in a security setting is an error, never a quiet fall to the weak mode.
	for _, bad := range []string{"Best-Effort", "besteffort", "off", "none", "optional", "true", " required"} {
		got, err := ParseRecordingPolicy(bad)
		if err == nil {
			t.Errorf("ParseRecordingPolicy(%q) accepted a value it does not know", bad)
		}
		if got != RecordingRequired {
			t.Errorf("ParseRecordingPolicy(%q) returned %v on error; the safe value is required", bad, got)
		}
	}
}

func TestRecordingPolicy_ZeroValueIsRequired(t *testing.T) {
	var p RecordingPolicy
	if p != RecordingRequired || p.String() != "required" {
		t.Fatalf("the zero value must be the strict policy, got %v (%s)", p, p)
	}
}

type blockingGate struct{}

func (blockingGate) Ready(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

func TestRecordingConfig_Admit(t *testing.T) {
	ctx := context.Background()
	down := &fakeGate{err: errors.New("dial tcp 10.0.0.9:8087: connection refused")}

	t.Run("an unconfigured config refuses", func(t *testing.T) {
		if err := (RecordingConfig{}).Admit(ctx); !errors.Is(err, ErrRecordingUnavailable) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("required needs both the acknowledged recorder and the probe", func(t *testing.T) {
		if err := (RecordingConfig{Strict: nopBatchRecorder{}}).Admit(ctx); !errors.Is(err, ErrRecordingUnavailable) {
			t.Fatalf("no gate: got %v", err)
		}
		if err := (RecordingConfig{Gate: &fakeGate{}}).Admit(ctx); !errors.Is(err, ErrRecordingUnavailable) {
			t.Fatalf("no recorder: got %v", err)
		}
	})
	t.Run("a ready recorder admits", func(t *testing.T) {
		if err := (RecordingConfig{Strict: nopBatchRecorder{}, Gate: &fakeGate{}}).Admit(ctx); err != nil {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a failing probe refuses and says why", func(t *testing.T) {
		err := (RecordingConfig{Strict: nopBatchRecorder{}, Gate: down}).Admit(ctx)
		if !errors.Is(err, ErrRecordingUnavailable) || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an unresponsive probe refuses within its timeout", func(t *testing.T) {
		start := time.Now()
		err := (RecordingConfig{Strict: nopBatchRecorder{}, Gate: blockingGate{}, GateTimeout: 50 * time.Millisecond}).Admit(ctx)
		if !errors.Is(err, ErrRecordingUnavailable) {
			t.Fatalf("got %v", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("took %v: the probe is not bounded", time.Since(start))
		}
	})
	t.Run("best-effort admits even when the recorder is down", func(t *testing.T) {
		gate := &fakeGate{err: errors.New("down")}
		if err := (RecordingConfig{Policy: RecordingBestEffort, Strict: nopBatchRecorder{}, Gate: gate}).Admit(ctx); err != nil {
			t.Fatalf("got %v", err)
		}
		if gate.calls != 0 {
			t.Fatal("best-effort must not even probe the recorder")
		}
	})
	t.Run("an unknown policy value fails closed", func(t *testing.T) {
		if err := (RecordingConfig{Policy: RecordingPolicy(42), Gate: down, Strict: nopBatchRecorder{}}).Admit(ctx); !errors.Is(err, ErrRecordingUnavailable) {
			t.Fatalf("an out-of-range policy was treated as permissive: %v", err)
		}
	})
}

func TestRecordingConfig_NewTap(t *testing.T) {
	t.Run("required without a recorder is refused, not run untapped", func(t *testing.T) {
		if tap, err := (RecordingConfig{}).NewTap("s"); tap != nil || !errors.Is(err, ErrRecordingUnavailable) {
			t.Fatalf("got %v, %v", tap, err)
		}
	})
	t.Run("required gives the acknowledging tap", func(t *testing.T) {
		rec := &scriptedBatchRecorder{}
		tap, err := (RecordingConfig{Strict: rec, Gate: &fakeGate{}}).NewTap("s")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = tap.Write([]byte("ls\r"))
		if len(rec.batches) != 1 {
			t.Fatalf("the tap did not use the acknowledged recorder: %v", rec.batches)
		}
	})
	t.Run("best-effort with no sink still taps, into nothing", func(t *testing.T) {
		tap, err := (RecordingConfig{Policy: RecordingBestEffort}).NewTap("s")
		if err != nil {
			t.Fatal(err)
		}
		if n, err := tap.Write([]byte("ls\r")); err != nil || n != 3 {
			t.Fatalf("got %d, %v", n, err)
		}
	})
	t.Run("best-effort uses the sink", func(t *testing.T) {
		rec := &captureRecorder{}
		tap, _ := (RecordingConfig{Policy: RecordingBestEffort, Sink: rec}).NewTap("s")
		_, _ = tap.Write([]byte("ls\r"))
		assertCommands(t, rec, "ls")
	})
}

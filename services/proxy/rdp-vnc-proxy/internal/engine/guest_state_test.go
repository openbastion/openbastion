package engine

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Windows virtual machine's state at the moment a Windows test fails (ADR-0071, CI
// instability "B": the target lost during TestRDPWindows_Measure, then nothing until the end of
// the job; NOTES_SANDBOX.md of 13 November asked for the QEMU console at the moment of the loss).
//
// RDP_WINDOWS_GUEST_STATE names a program (testdata/rdp/windows/guest-state.sh in CI) called with
// RDP_WINDOWS_DUMP and the test's name; it leaves the console's screen and QEMU's, the container's
// and the host's state there. Only the first failures are captured: after a loss every later test
// fails too, and the moment that matters is the first.
const maxGuestStateCaptures = 3

var guestStates struct {
	sync.Mutex
	taken int
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// captureGuestStateOnFailure registers, for t, the capture of the guest's state if t fails.
func captureGuestStateOnFailure(t *testing.T) {
	t.Helper()
	program, dir := os.Getenv("RDP_WINDOWS_GUEST_STATE"), os.Getenv("RDP_WINDOWS_DUMP")
	if program == "" || dir == "" {
		return
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		if report, ok := captureGuestState(program, dir, t.Name(), time.Minute); ok {
			t.Logf("the guest's state at this failure: %s", report)
		}
	})
}

// captureGuestState runs program once for name, within limit, unless maxGuestStateCaptures
// captures were taken already. It returns what the program printed, and whether it ran.
func captureGuestState(program, dir, name string, limit time.Duration) (string, bool) {
	guestStates.Lock()
	if guestStates.taken >= maxGuestStateCaptures {
		guestStates.Unlock()
		return "", false
	}
	guestStates.taken++
	n := guestStates.taken
	guestStates.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	label := "guest-state-" + string(rune('0'+n)) + "-" + strings.Trim(unsafeName.ReplaceAllString(name, "-"), "-")
	cmd := exec.CommandContext(ctx, program, dir, label)
	// A child of the program (docker, python3) can keep the output open after the program is
	// killed: past this delay the pipes are closed and the test goes on.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	report := strings.TrimSpace(string(out))
	if err != nil {
		report += " (" + err.Error() + ")"
	}
	return report, true
}

func TestCaptureGuestState_NamesEachCaptureAndStopsAfterTheFirstOnes(t *testing.T) {
	dir := t.TempDir()
	program := dir + "/state.sh"
	// The program records what it was asked: its directory and the capture's name.
	if err := os.WriteFile(program, []byte("#!/bin/sh\necho \"$1|$2\" >> \"$1/calls\"\necho \"$1/$2.txt\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	guestStates.Lock()
	guestStates.taken = 0
	guestStates.Unlock()
	for i := 0; i < maxGuestStateCaptures+2; i++ {
		report, ran := captureGuestState(program, dir, "TestRDPWindows_Measure/partial-frames", 10*time.Second)
		if ran != (i < maxGuestStateCaptures) {
			t.Fatalf("capture %d ran %v", i+1, ran)
		}
		if ran && !strings.HasSuffix(report, ".txt") {
			t.Fatalf("capture %d reported %q", i+1, report)
		}
	}
	calls, _ := os.ReadFile(dir + "/calls")
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != maxGuestStateCaptures || lines[0] != dir+"|guest-state-1-TestRDPWindows_Measure-partial-frames" {
		t.Fatalf("calls: %q", lines)
	}
	// A program that does not answer in time is stopped, and the test goes on.
	guestStates.Lock()
	guestStates.taken = 0
	guestStates.Unlock()
	slow := dir + "/slow.sh"
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if report, ran := captureGuestState(slow, dir, "x", 500*time.Millisecond); !ran || !strings.Contains(report, "killed") && !strings.Contains(report, "deadline") {
		t.Fatalf("a slow program: %v %q", ran, report)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("a slow program held the test %v", time.Since(start))
	}
}

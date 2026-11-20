package integration_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// freshWindowsSession logs every session of the Windows target off before a browser test opens its
// screen, so that the test logs on to a new session instead of reconnecting to the one the
// previous test left disconnected.
//
// Why: reconnecting to that session sometimes ends it within a second, before the first frame.
// Windows says why in its LocalSessionManager log (CI of PR #240, fr-FR, 2026-11-20 01:12:49 UTC):
// event 25 (reconnection to session 4), then event 40 with reason 17,
// ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE — the session's display driver did not report in time.
// The page showed "La session est terminée." (session_ended); the PRs #234, #239 and #240 met it.
//
// The logoff goes through the share, as the logoff test's does (rdp-setup.ps1): the runner writes
// logoff-request, the SYSTEM loop of Windows logs every session off within 30 s and writes
// logoff-done.txt, which the next pass copies back to the share. Notepad, which the clipboard test
// uses, is started again at every logon (HKLM Run). Without RDP_WINDOWS_SHARED (a local run), there
// is nothing to ask and the test goes on as it is.
func freshWindowsSession(t *testing.T) {
	t.Helper()
	shared := os.Getenv("RDP_WINDOWS_SHARED")
	if shared == "" {
		t.Log("RDP_WINDOWS_SHARED not set: the target's sessions are not logged off first")
		return
	}
	done := filepath.Join(shared, "logoff-done.txt")
	before, _ := os.ReadFile(done)
	if err := os.WriteFile(filepath.Join(shared, "logoff-request"), []byte("logoff\n"), 0o644); err != nil {
		t.Fatalf("asking Windows to log its sessions off: %v", err)
	}
	for deadline := time.Now().Add(150 * time.Second); ; {
		if now, err := os.ReadFile(done); err == nil && len(now) > 0 && !bytes.Equal(now, before) {
			t.Logf("Windows logged its sessions off before this test: %s", bytes.TrimSpace(now))
			// The logoff has run; the session's teardown, a moment more.
			time.Sleep(5 * time.Second)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Windows did not log its sessions off within 150 s (no new logoff-done.txt on the share)")
		}
		time.Sleep(2 * time.Second)
	}
}

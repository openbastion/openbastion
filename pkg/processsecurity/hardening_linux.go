//go:build linux

package processsecurity

import (
	"fmt"
	"syscall"
)

const (
	prGetDumpable = 3
	prSetDumpable = 4
)

// HardenSecretProcess disables Linux core dumps and marks this process non-dumpable.
// The latter also blocks ordinary ptrace access; CAP_SYS_PTRACE and kernel-level access
// remain outside this process-level control.
func HardenSecretProcess() error {
	limit := syscall.Rlimit{Cur: 0, Max: 0}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &limit); err != nil {
		return fmt.Errorf("set RLIMIT_CORE=0: %w", err)
	}
	if _, err := prctl(prSetDumpable); err != nil {
		return fmt.Errorf("set PR_SET_DUMPABLE=0: %w", err)
	}
	var actual syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &actual); err != nil {
		return fmt.Errorf("verify RLIMIT_CORE: %w", err)
	}
	if actual.Cur != 0 || actual.Max != 0 {
		return fmt.Errorf("RLIMIT_CORE remains enabled (soft=%d hard=%d)", actual.Cur, actual.Max)
	}
	dumpable, err := prctl(prGetDumpable)
	if err != nil {
		return fmt.Errorf("verify PR_GET_DUMPABLE: %w", err)
	}
	if dumpable != 0 {
		return fmt.Errorf("process remains dumpable (PR_GET_DUMPABLE=%d)", dumpable)
	}
	return nil
}

// prctl uses Linux's stable syscall ABI; keeping this package stdlib-only avoids
// introducing a platform dependency for two integer operations.
func prctl(option uintptr) (int, error) {
	value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, option, 0, 0, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(value), nil
}

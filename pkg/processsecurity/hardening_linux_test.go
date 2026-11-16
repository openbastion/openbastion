//go:build linux

package processsecurity

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestHardenSecretProcessDisablesCoreDumpsAndDumpability(t *testing.T) {
	if os.Getenv("OPENBASTION_HARDENING_TEST_CHILD") == "1" {
		if err := HardenSecretProcess(); err != nil {
			t.Fatal(err)
		}
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil {
			t.Fatal(err)
		}
		if limit.Cur != 0 || limit.Max != 0 {
			t.Fatalf("RLIMIT_CORE not disabled: %+v", limit)
		}
		dumpable, err := prctl(prGetDumpable)
		if err != nil {
			t.Fatal(err)
		}
		if dumpable != 0 {
			t.Fatalf("process is dumpable: %d", dumpable)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenSecretProcessDisablesCoreDumpsAndDumpability$")
	cmd.Env = append(os.Environ(), "OPENBASTION_HARDENING_TEST_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hardened subprocess failed: %v\n%s", err, output)
	}
}

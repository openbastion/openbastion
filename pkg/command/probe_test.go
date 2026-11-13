package command

import (
	"context"
	"errors"
	"io"
	"testing"
)

// `<service> probe` passes its port and path to the probe, needs a port, and fails as the probe does.
func TestProbeCommand(t *testing.T) {
	var gotPort int
	var gotPath string
	fail := false
	run := func(args ...string) error { // a fresh command each time, as each healthcheck starts one
		gotPort, gotPath = 0, ""
		cmd := NewProbeCommand(func(_ context.Context, port int, path string) error {
			gotPort, gotPath = port, path
			if fail {
				return errors.New("down")
			}
			return nil
		})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		return cmd.Execute()
	}
	if err := run("--port", "8088", "--path", "/readyz"); err != nil || gotPort != 8088 || gotPath != "/readyz" {
		t.Fatalf("probe --port 8088 --path /readyz: %v, asked %d %q", err, gotPort, gotPath)
	}
	if err := run("--port", "8090"); err != nil || gotPath != "/healthz" {
		t.Fatalf("the default path: %v, %q", err, gotPath)
	}
	if err := run(); err == nil || gotPort != 0 {
		t.Fatalf("without a port: %v, probe called with %d", err, gotPort)
	}
	fail = true
	if err := run("--port", "8088"); err == nil {
		t.Fatal("a probe that fails: the command succeeded")
	}
}

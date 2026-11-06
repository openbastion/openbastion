package command

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/buildinfo"
	"github.com/spf13/cobra"
)

func TestVersionCommand(t *testing.T) {
	info := buildinfo.Info{Version: "dev", GoVersion: "go1.27.3", Built: "b75be22", OSArch: "linux/amd64"}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "detailed", args: []string{"version"}, want: "Version:           dev\nGo version:        go1.27.3\nBuilt:             b75be22\nOS/Arch:           linux/amd64\n"},
		{name: "short", args: []string{"version", "--short"}, want: "dev\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newTestRoot(newVersionCommand(func() buildinfo.Info { return info }))
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetArgs(tt.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if got := out.String(); got != tt.want {
				t.Fatalf("output = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionCommandRejectsArgumentsAndUnknownFlags(t *testing.T) {
	for _, args := range [][]string{{"unexpected"}, {"--unknown"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			root := newTestRoot(newVersionCommand(buildinfo.Current))
			root.SetArgs(append([]string{"version"}, args...))
			if err := root.Execute(); err == nil {
				t.Fatalf("Execute(%v) unexpectedly succeeded", args)
			}
		})
	}
}

func TestVersionCommandPropagatesOutputError(t *testing.T) {
	want := errors.New("writer failed")
	root := newTestRoot(newVersionCommand(buildinfo.Current))
	root.SetOut(errorWriter{err: want})
	root.SetArgs([]string{"version", "--short"})
	if err := root.Execute(); !errors.Is(err, want) {
		t.Fatalf("Execute() error = %v, want %v", err, want)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestVersionCommandDoesNotReadBuildInfoUntilExecuted(t *testing.T) {
	calls := 0
	version := newVersionCommand(func() buildinfo.Info {
		calls++
		return buildinfo.Info{Version: "dev"}
	})
	if calls != 0 {
		t.Fatalf("build info read during construction: %d calls", calls)
	}
	root := newTestRoot(version)
	root.SetArgs([]string{"version", "--short"})
	root.SetOut(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("build info read %d times, want 1", calls)
	}
}

func newTestRoot(version *cobra.Command) *cobra.Command {
	root := &cobra.Command{Use: "openbastion-test", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(version)
	return root
}

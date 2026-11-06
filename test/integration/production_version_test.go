package integration_test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestVersion_AllProductionExecutablesExposeTheSameSideEffectFreeCommand(t *testing.T) {
	root := repoRoot(t)
	version := "0.0.1-dev+production-cli-test"
	binaries := []struct {
		name string
		pkg  string
	}{
		{"openbastion-cli", "./cli/openbastion-cli"},
		{"openbastion-pki", "./pkg/mtls/cmd/openbastion-pki"},
		{"api-gateway", "./services/access/api-gateway/cmd/api-gateway"},
		{"authentication", "./services/access/authentication/cmd/authentication"},
		{"authorization", "./services/access/authorization/cmd/authorization"},
		{"session-broker", "./services/access/session-broker/cmd/session-broker"},
		{"ssh-proxy", "./services/proxy/ssh-proxy/cmd/ssh-proxy"},
		{"rdp-vnc-proxy", "./services/proxy/rdp-vnc-proxy/cmd/rdp-vnc-proxy"},
		{"password-vault", "./services/vault/password-vault/cmd/password-vault"},
		{"audit-service", "./services/recording-audit/audit-service/cmd/audit-service"},
		{"command-recorder", "./services/recording-audit/command-recorder/cmd/command-recorder"},
		{"video-recorder", "./services/recording-audit/video-recorder/cmd/video-recorder"},
	}
	for _, binary := range binaries {
		t.Run(binary.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), binary.name)
			build := exec.Command("go", "build", "-ldflags", "-X github.com/openbastion/openbastion/pkg/buildinfo.Version="+version, "-o", path, binary.pkg)
			build.Dir, build.Env = root, buildEnv(root)
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build %s: %v\n%s", binary.pkg, err, output)
			}
			env := overrideEnv(buildEnv(root), map[string]string{
				"INTERNAL_TLS": "invalid", "PORT": "not-a-port", "GRPC_PORT": "not-a-port",
				"DATABASE_URL": "invalid", "TOKEN_SIGNING_KEY_HEX": "invalid", "KMS_KEY_HEX": "invalid",
				"AUDIT_CHAIN_KEY_HEX": "invalid", "TRANSIT_ADDR": "://invalid",
			})
			detailed := exec.Command(path, "version")
			detailed.Env = env
			output, err := detailed.CombinedOutput()
			if err != nil {
				t.Fatalf("version initialized or failed: %v\n%s", err, output)
			}
			lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
			if len(lines) != 4 || lines[0] != "Version:           "+version || lines[1] != "Go version:        "+runtime.Version() || !strings.HasPrefix(lines[2], "Built:             ") || lines[3] != fmt.Sprintf("OS/Arch:           %s/%s", runtime.GOOS, runtime.GOARCH) {
				t.Fatalf("version output does not match the four-field contract: %q", output)
			}
			built := strings.TrimPrefix(lines[2], "Built:             ")
			if built != "unknown" && !regexp.MustCompile(`^[a-f0-9]{7}$`).MatchString(built) {
				t.Fatalf("Built field is neither unknown nor a seven-character VCS revision: %q", built)
			}
			short := exec.Command(path, "version", "--short")
			short.Env = env
			output, err = short.CombinedOutput()
			if err != nil || string(output) != version+"\n" {
				t.Fatalf("version --short = %q, %v; want exactly %q", output, err, version+"\n")
			}
		})
	}
}

func overrideEnv(base []string, values map[string]string) []string {
	out := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := values[key]; !replaced {
			out = append(out, entry)
		}
	}
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

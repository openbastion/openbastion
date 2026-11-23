package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/dbpool"
)

const validManifest = `postgres:
  max_connections: 100
  reserved_connections: 20
services:
  authentication: {max_instances: 1, max_open_per_instance: 10}
  authorization: {max_instances: 1, max_open_per_instance: 10}
  session-broker: {max_instances: 1, max_open_per_instance: 10}
  audit-service: {max_instances: 1, max_open_per_instance: 10}
  password-vault: {max_instances: 1, max_open_per_instance: 10}
  command-recorder: {max_instances: 1, max_open_per_instance: 10}
  video-recorder: {max_instances: 1, max_open_per_instance: 10}
`

func TestRunAcceptsValidManifest(t *testing.T) {
	if err := run(writeManifest(t, validManifest)); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown field",
			body: strings.Replace(validManifest, "max_connections: 100", "max_connections: 100\n  typo: 1", 1),
			want: "field typo not found",
		},
		{
			name: "multiple documents",
			body: validManifest + "---\npostgres: {}\n",
			want: "exactly one YAML document",
		},
		{
			name: "duplicate key",
			body: strings.Replace(validManifest, "  max_connections: 100", "  max_connections: 100\n  max_connections: 200", 1),
			want: "already defined",
		},
		{
			name: "over budget",
			body: strings.Replace(validManifest, "max_connections: 100", "max_connections: 80", 1),
			want: "budget exceeded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(writeManifest(t, tt.body))
			if err == nil {
				t.Fatalf("run() returned no error, want containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capacity.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateComposeRequiresIdleDefaultToFollowOpenLimit(t *testing.T) {
	body, err := os.ReadFile("../../deploy/docker-compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(body)
	compose = strings.Replace(compose, "${AUTHENTICATION_DB_POOL_MAX_OPEN_CONNS-10}", "${AUTHENTICATION_DB_POOL_MAX_OPEN_CONNS-3}", 1)
	compose = strings.Replace(compose, "${AUTHENTICATION_DB_POOL_MAX_IDLE_CONNS-10}", "${AUTHENTICATION_DB_POOL_MAX_IDLE_CONNS-3}", 1)
	body = []byte(compose)
	path := filepath.Join(t.TempDir(), "compose.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	budget := testBudget()
	budget.Services["authentication"] = structServiceBudget(3)
	if err := validateCompose(path, budget); err != nil {
		t.Fatalf("valid min(open, 10) Compose defaults rejected: %v", err)
	}
	compose = strings.Replace(string(body), "${AUTHENTICATION_DB_POOL_MAX_IDLE_CONNS-3}", "${AUTHENTICATION_DB_POOL_MAX_IDLE_CONNS-10}", 1)
	body = []byte(compose)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCompose(path, budget); err == nil {
		t.Fatal("Compose idle default greater than open limit was accepted")
	}
}

func testBudget() dbpool.CapacityBudget {
	services := make(map[string]dbpool.ServiceBudget)
	for _, name := range dbpool.KnownServiceNames() {
		services[name] = dbpool.ServiceBudget{MaxInstances: 1, MaxOpenPerInstance: 10}
	}
	return dbpool.CapacityBudget{MaxConnections: 100, ReservedConnections: 20, Services: services}
}

func structServiceBudget(maxOpen int64) dbpool.ServiceBudget {
	return dbpool.ServiceBudget{
		MaxInstances:       1,
		MaxOpenPerInstance: maxOpen,
	}
}

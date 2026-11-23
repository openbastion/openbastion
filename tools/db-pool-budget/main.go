// Command db-pool-budget validates a cluster-wide PostgreSQL connection capacity manifest.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/openbastion/openbastion/pkg/dbpool"
	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Services map[string]yaml.Node `yaml:"services"`
}

type manifest struct {
	Postgres struct {
		MaxConnections      int64 `yaml:"max_connections"`
		ReservedConnections int64 `yaml:"reserved_connections"`
	} `yaml:"postgres"`
	Services map[string]dbpool.ServiceBudget `yaml:"services"`
}

func main() {
	path := flag.String("manifest", "../../deploy/postgresql/capacity.yaml", "path to the cluster capacity YAML manifest")
	compose := flag.String("compose", "../../deploy/docker-compose/docker-compose.yml", "path to the production Docker Compose file")
	base44 := flag.String("base44", "../../deploy/base44/docker-compose.yml", "path to the Base44 Compose file")
	flag.Parse()
	if err := run(*path, *compose, *base44); err != nil {
		fmt.Fprintf(os.Stderr, "db-pool-budget: %v\n", err)
		os.Exit(1)
	}
}

func run(path string, composePaths ...string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening manifest: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var input manifest
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("decoding manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("manifest must contain exactly one YAML document")
		}
		return fmt.Errorf("reading end of manifest: %w", err)
	}

	budget := dbpool.CapacityBudget{
		MaxConnections:      input.Postgres.MaxConnections,
		ReservedConnections: input.Postgres.ReservedConnections,
		Services:            input.Services,
	}
	result, err := dbpool.ValidateBudget(budget)
	if err != nil {
		return err
	}
	if len(composePaths) == 0 {
		composePaths = []string{"../../deploy/docker-compose/docker-compose.yml", "../../deploy/base44/docker-compose.yml"}
	}
	for _, composePath := range composePaths {
		if err := validateCompose(composePath, budget); err != nil {
			return err
		}
	}

	names := dbpool.KnownServiceNames()
	sort.Strings(names)
	fmt.Printf("PostgreSQL capacity budget: PASS\n")
	for _, name := range names {
		service := input.Services[name]
		fmt.Printf("  %-20s %4d instances × %4d max_open = %6d\n", name, service.MaxInstances, service.MaxOpenPerInstance, service.MaxInstances*service.MaxOpenPerInstance)
	}
	fmt.Printf("  %-20s %6d\n", "application total", result.ApplicationConnections)
	fmt.Printf("  %-20s %6d\n", "reserved", input.Postgres.ReservedConnections)
	fmt.Printf("  %-20s %6d\n", "total planned", result.TotalPlanned)
	fmt.Printf("  %-20s %6d\n", "max_connections", input.Postgres.MaxConnections)
	fmt.Printf("  %-20s %6d\n", "remaining", result.Remaining)
	return nil
}

func validateCompose(path string, budget dbpool.CapacityBudget) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening Compose file %s: %w", path, err)
	}
	defer file.Close()
	var input composeFile
	if err := yaml.NewDecoder(file).Decode(&input); err != nil {
		return fmt.Errorf("decoding Compose file %s: %w", path, err)
	}
	for service, spec := range budget.Services {
		serviceNode, ok := input.Services[service]
		if !ok {
			return fmt.Errorf("dbpool: Compose file %s does not declare service %s", path, service)
		}
		var environment map[string]any
		for i := 0; i+1 < len(serviceNode.Content); i += 2 {
			if serviceNode.Content[i].Value == "environment" {
				if err := serviceNode.Content[i+1].Decode(&environment); err != nil {
					return fmt.Errorf("dbpool: decoding environment for %s in %s: %w", service, path, err)
				}
				break
			}
		}
		prefix := strings.ToUpper(strings.ReplaceAll(service, "-", "_"))
		wantOpen := fmt.Sprintf("${%s_DB_POOL_MAX_OPEN_CONNS-%d}", prefix, spec.MaxOpenPerInstance)
		idleDefault := spec.MaxOpenPerInstance
		if idleDefault > dbpool.DefaultMaxIdleConns {
			idleDefault = dbpool.DefaultMaxIdleConns
		}
		wantIdle := fmt.Sprintf("${%s_DB_POOL_MAX_IDLE_CONNS-%d}", prefix, idleDefault)
		if got, ok := environment["DB_POOL_MAX_OPEN_CONNS"].(string); !ok || got != wantOpen {
			return fmt.Errorf("dbpool: Compose file %s service %s must set DB_POOL_MAX_OPEN_CONNS to %s", path, service, wantOpen)
		}
		if got, ok := environment["DB_POOL_MAX_IDLE_CONNS"].(string); !ok || got != wantIdle {
			return fmt.Errorf("dbpool: Compose file %s service %s must set DB_POOL_MAX_IDLE_CONNS to %s", path, service, wantIdle)
		}
	}
	return nil
}

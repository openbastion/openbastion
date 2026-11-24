package dbpool

import (
	"fmt"
	"math"
	"sort"
)

// knownServices is the complete, immutable set of OpenBastion processes with a PostgreSQL pool.
var knownServices = [...]string{
	"audit-service",
	"authentication",
	"authorization",
	"command-recorder",
	"password-vault",
	"session-broker",
	"video-recorder",
}

// KnownServiceNames returns a fresh copy of the bounded service-name allowlist.
func KnownServiceNames() []string {
	return append([]string(nil), knownServices[:]...)
}

// ServiceBudget describes the maximum simultaneous instances and per-process pool ceiling.
type ServiceBudget struct {
	MaxInstances       int64 `yaml:"max_instances" json:"max_instances"`
	MaxOpenPerInstance int64 `yaml:"max_open_per_instance" json:"max_open_per_instance"`
}

// CapacityBudget is scoped to one PostgreSQL server/cluster, not one database.
type CapacityBudget struct {
	MaxConnections      int64                    `yaml:"max_connections" json:"max_connections"`
	ReservedConnections int64                    `yaml:"reserved_connections" json:"reserved_connections"`
	Services            map[string]ServiceBudget `yaml:"services" json:"services"`
}

// BudgetResult contains the arithmetic the validator reports to operators.
type BudgetResult struct {
	ApplicationConnections int64
	TotalPlanned           int64
	Remaining              int64
}

// ValidateBudget requires an exact declaration of all seven database services and
// checks every multiplication and addition before evaluating the cluster ceiling.
func ValidateBudget(b CapacityBudget) (BudgetResult, error) {
	if b.MaxConnections <= 0 {
		return BudgetResult{}, fmt.Errorf("dbpool: max_connections must be positive")
	}
	if b.ReservedConnections < 0 {
		return BudgetResult{}, fmt.Errorf("dbpool: reserved_connections must not be negative")
	}
	if b.ReservedConnections > b.MaxConnections {
		return BudgetResult{}, fmt.Errorf("dbpool: reserved_connections (%d) exceeds max_connections (%d)", b.ReservedConnections, b.MaxConnections)
	}

	known := make(map[string]struct{}, len(knownServices))
	for _, name := range knownServices {
		known[name] = struct{}{}
	}
	for name := range b.Services {
		if _, ok := known[name]; !ok {
			return BudgetResult{}, fmt.Errorf("dbpool: unknown PostgreSQL service %q", name)
		}
	}
	if len(b.Services) != len(knownServices) {
		missing := make([]string, 0)
		for _, name := range knownServices {
			if _, ok := b.Services[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return BudgetResult{}, fmt.Errorf("dbpool: missing PostgreSQL service declarations: %v", missing)
	}

	var application int64
	for _, name := range knownServices {
		service := b.Services[name]
		if service.MaxInstances <= 0 {
			return BudgetResult{}, fmt.Errorf("dbpool: services.%s.max_instances must be positive", name)
		}
		if service.MaxOpenPerInstance < 1 || service.MaxOpenPerInstance > MaxOpenConns {
			return BudgetResult{}, fmt.Errorf("dbpool: services.%s.max_open_per_instance must be between 1 and %d", name, MaxOpenConns)
		}
		if service.MaxInstances > math.MaxInt64/service.MaxOpenPerInstance {
			return BudgetResult{}, fmt.Errorf("dbpool: connection multiplication overflows for service %s", name)
		}
		connections := service.MaxInstances * service.MaxOpenPerInstance
		if application > math.MaxInt64-connections {
			return BudgetResult{}, fmt.Errorf("dbpool: application connection total overflows")
		}
		application += connections
	}
	if application > math.MaxInt64-b.ReservedConnections {
		return BudgetResult{}, fmt.Errorf("dbpool: total planned connections overflow")
	}
	total := application + b.ReservedConnections
	if total > b.MaxConnections {
		return BudgetResult{}, fmt.Errorf("dbpool: PostgreSQL connection budget exceeded: %d application + %d reserved = %d, max_connections is %d", application, b.ReservedConnections, total, b.MaxConnections)
	}
	return BudgetResult{
		ApplicationConnections: application,
		TotalPlanned:           total,
		Remaining:              b.MaxConnections - total,
	}, nil
}

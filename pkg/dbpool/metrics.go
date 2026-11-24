package dbpool

import (
	"database/sql"
	"fmt"
	"net/http"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// RegisterMetrics exposes a bounded-cardinality Prometheus text endpoint. The
// caller must add GET /metrics to the service's mTLS caller allowlist.
func RegisterMetrics(mux *http.ServeMux, service string, db *sql.DB, config Config) error {
	if mux == nil {
		return fmt.Errorf("dbpool: metrics mux is nil")
	}
	if db == nil {
		return fmt.Errorf("dbpool: metrics database is nil")
	}
	if !isKnownService(service) {
		return fmt.Errorf("dbpool: unknown metrics service %q", service)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	mux.Handle("/metrics", MetricsHandler(service, db, config))
	return nil
}

// MetricsHandler renders the current database/sql pool snapshot without
// introducing a registry, exporter dependency, background goroutine or labels
// derived from requests.
func MetricsHandler(service string, db *sql.DB, config Config) http.Handler {
	if db == nil || !isKnownService(service) || config.Validate() != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stats := db.Stats()
		w.Header().Set("Content-Type", metricsContentType)
		w.Header().Set("Cache-Control", "no-store")
		labels := fmt.Sprintf("{service=%q}", service)
		writeGauge := func(name, help string, value any) {
			_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s%s %v\n", name, help, name, name, labels, value)
		}
		writeCounter := func(name, help string, value any) {
			_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s%s %v\n", name, help, name, name, labels, value)
		}
		writeGauge("openbastion_db_connections_open", "Current open database connections.", stats.OpenConnections)
		writeGauge("openbastion_db_connections_in_use", "Current database connections in use.", stats.InUse)
		writeGauge("openbastion_db_connections_idle", "Current idle database connections.", stats.Idle)
		writeGauge("openbastion_db_connections_max_open", "Configured maximum open database connections.", stats.MaxOpenConnections)
		writeGauge("openbastion_db_connections_max_idle", "Configured maximum idle database connections.", config.MaxIdleConns)
		writeCounter("openbastion_db_pool_wait_count_total", "Total number of waits for a database connection.", stats.WaitCount)
		writeCounter("openbastion_db_pool_wait_duration_seconds_total", "Cumulative time spent waiting for database connections.", stats.WaitDuration.Seconds())
	})
}

func isKnownService(service string) bool {
	for _, known := range knownServices {
		if service == known {
			return true
		}
	}
	return false
}

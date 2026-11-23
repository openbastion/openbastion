package dbpool

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type emptyConnector struct{}

func (emptyConnector) Connect(context.Context) (driver.Conn, error) {
	return emptyConn{}, nil
}

func (emptyConnector) Driver() driver.Driver {
	return emptyDriver{}
}

type emptyDriver struct{}

func (emptyDriver) Open(string) (driver.Conn, error) {
	return emptyConn{}, nil
}

type emptyConn struct{}

func (emptyConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}

func (emptyConn) Close() error {
	return nil
}

func (emptyConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}

func TestMetricsHandlerExposesBoundedPoolStats(t *testing.T) {
	db := sql.OpenDB(emptyConnector{})
	defer db.Close()
	cfg := Config{MaxOpenConns: 7, MaxIdleConns: 3}
	if err := Configure(db, cfg); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	MetricsHandler("audit-service", db, cfg).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d", r.Code)
	}
	wantMetrics := []string{
		`openbastion_db_connections_open{service="audit-service"} 0`,
		`openbastion_db_connections_max_open{service="audit-service"} 7`,
		`openbastion_db_connections_max_idle{service="audit-service"} 3`,
		`openbastion_db_pool_wait_count_total{service="audit-service"} 0`,
		`openbastion_db_pool_wait_duration_seconds_total{service="audit-service"} 0`,
	}
	for _, want := range wantMetrics {
		if !strings.Contains(r.Body.String(), want) {
			t.Errorf("missing %q in %s", want, r.Body.String())
		}
	}
	if r.Header().Get("Content-Type") != metricsContentType {
		t.Fatalf("content type=%q", r.Header().Get("Content-Type"))
	}
	if strings.Contains(r.Body.String(), "dsn") || strings.Contains(r.Body.String(), "password") {
		t.Fatalf("unexpected connection detail in metrics: %s", r.Body.String())
	}
}

func TestMetricsHandlerRejectsNonGet(t *testing.T) {
	db := sql.OpenDB(emptyConnector{})
	defer db.Close()
	r := httptest.NewRecorder()
	MetricsHandler("authentication", db, Defaults()).ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/metrics", strings.NewReader("x")))
	if r.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", r.Code)
	}
}

func TestRegisterMetricsRequiresKnownServiceAndValidPool(t *testing.T) {
	db := sql.OpenDB(emptyConnector{})
	defer db.Close()
	if err := RegisterMetrics(http.NewServeMux(), "unknown", db, Defaults()); err == nil {
		t.Fatal("RegisterMetrics accepted an unknown service label")
	}
	if err := RegisterMetrics(http.NewServeMux(), "authentication", db, Config{MaxOpenConns: 0}); err == nil {
		t.Fatal("RegisterMetrics accepted an invalid pool configuration")
	}
	mux := http.NewServeMux()
	if err := RegisterMetrics(mux, "authentication", db, Defaults()); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRecorder()
	mux.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if r.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d", r.Code)
	}
}

func TestConfigureAppliesOpenAndIdleLimits(t *testing.T) {
	db := sql.OpenDB(emptyConnector{})
	defer db.Close()
	config := Config{MaxOpenConns: 3, MaxIdleConns: 1}
	if err := Configure(db, config); err != nil {
		t.Fatal(err)
	}
	var connections []*sql.Conn
	for i := 0; i < 3; i++ {
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	stats := db.Stats()
	if stats.MaxOpenConnections != 3 || stats.Idle != 1 || stats.MaxIdleClosed != 2 {
		t.Fatalf("pool stats = %+v, want max-open=3 idle=1 max-idle-closed=2", stats)
	}
}

func TestConfigureRejectsNilDatabaseAndInvalidLimits(t *testing.T) {
	if err := Configure(nil, Defaults()); err == nil {
		t.Fatal("Configure accepted a nil database")
	}
	db := sql.OpenDB(emptyConnector{})
	defer db.Close()
	if err := Configure(db, Config{MaxOpenConns: 0, MaxIdleConns: 0}); err == nil {
		t.Fatal("Configure accepted an unbounded pool")
	}
}

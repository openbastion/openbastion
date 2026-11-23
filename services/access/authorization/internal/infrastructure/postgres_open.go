package infrastructure

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/dbpool"
)

// connectTimeout bounds each new connection, the TCP dial and PostgreSQL's startup, when the DSN
// sets no connect_timeout. Without it lib/pq waits forever on an address that drops packets or a
// server that never answers: through sql.Open, the context of PingContext never reaches lib/pq's
// dial, and lib/pq's startup exchange watches no context at all. A test shortens it.
var connectTimeout = 10 * time.Second

// The default pool limits retain the historical 10/10 behavior (ADR-0135). The idle ceiling is
// a subset of the open ceiling: it is never added to the cluster-wide connection budget.
const poolSize = dbpool.DefaultMaxOpenConns

// openPool opens the pool through a lib/pq connector, so the context of each call also bounds the
// dial, with connectTimeout as connect_timeout unless the DSN sets its own, and the configured
// per-process open/idle ceilings.
func openPool(dsn string, configs ...dbpool.Config) (*sql.DB, error) {
	config := dbpool.Defaults()
	if len(configs) > 1 {
		return nil, fmt.Errorf("postgres pool: at most one configuration is allowed")
	}
	if len(configs) == 1 {
		config = configs[0]
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	cfg, err := pq.NewConfig(dsn)
	if err != nil {
		return nil, err
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = connectTimeout
	}
	connector, err := pq.NewConnectorConfig(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	if err := dbpool.Configure(db, config); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

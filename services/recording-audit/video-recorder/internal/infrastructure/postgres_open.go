package infrastructure

import (
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// connectTimeout bounds each new connection, the TCP dial and PostgreSQL's startup, when the DSN
// sets no connect_timeout. Without it lib/pq waits forever on an address that drops packets or a
// server that never answers: through sql.Open, the context of PingContext never reaches lib/pq's
// dial, and lib/pq's startup exchange watches no context at all. A test shortens it.
var connectTimeout = 10 * time.Second

// openPool opens the pool through a lib/pq connector, so the context of each call also bounds the
// dial, with connectTimeout as connect_timeout unless the DSN sets its own.
func openPool(dsn string) (*sql.DB, error) {
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
	return sql.OpenDB(connector), nil
}

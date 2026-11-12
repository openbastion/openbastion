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

// poolSize is how many connections the pool keeps, open and idle. database/sql keeps two idle
// connections by default and opens as many as are asked for: fifty sessions recording at once then
// opened and closed a connection for nearly every frame, until the host ran out of ports and frames
// were lost. Ten held at most per instance: seven services stay within PostgreSQL's default of 100
// connections, and fifty recording sessions lost nothing (NOTES_SANDBOX.md, 12 November 2026).
const poolSize = 10

// openPool opens the pool through a lib/pq connector, so the context of each call also bounds the
// dial, with connectTimeout as connect_timeout unless the DSN sets its own, and poolSize connections
// kept.
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
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(poolSize)
	db.SetMaxIdleConns(poolSize)
	return db, nil
}

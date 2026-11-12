package infrastructure

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

// The pool keeps poolSize connections open and idle: with database/sql's default of two idle
// connections, fifty sessions recording at once opened and closed a connection for nearly every
// frame, until the host ran out of ports ("cannot assign requested address") and frames were lost.
func TestPostgres_PoolKeepsItsConnections(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := openPool(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := db.Stats().MaxOpenConnections; got != poolSize {
		t.Fatalf("at most %d open connections, want %d", got, poolSize)
	}
	ctx := context.Background()
	var conns []*sql.Conn
	for i := 0; i < poolSize; i++ {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.PingContext(ctx); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if stats := db.Stats(); stats.Idle != poolSize || stats.MaxIdleClosed != 0 {
		t.Fatalf("after %d connections are released: %d idle, %d closed for want of room; want all %d kept",
			poolSize, stats.Idle, stats.MaxIdleClosed, poolSize)
	}
}

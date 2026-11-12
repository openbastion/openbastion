package infrastructure

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// silentServer accepts TCP connections and never says a word: an address that answers the dial
// but not PostgreSQL's startup, like a hung server or a proxy with nothing behind it.
func silentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

func openGivesUpWithin(t *testing.T, dsn string, within time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		db, err := OpenPostgres(context.Background(), dsn)
		if db != nil {
			_ = db.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent server was taken for PostgreSQL")
		}
		t.Logf("refused as it should be: %v", err)
	case <-time.After(within):
		t.Fatalf("still waiting for a silent server after %s: startup would hang", within)
	}
}

// A DSN without connect_timeout gets connectTimeout: the service gives up instead of hanging.
func TestOpenPostgres_GivesUpOnASilentServer(t *testing.T) {
	defer func(old time.Duration) { connectTimeout = old }(connectTimeout)
	connectTimeout = 300 * time.Millisecond
	openGivesUpWithin(t, "postgres://u:p@"+silentServer(t)+"/db?sslmode=disable", 5*time.Second)
}

// The DSN's own connect_timeout wins over the default.
func TestOpenPostgres_KeepsTheDSNsConnectTimeout(t *testing.T) {
	defer func(old time.Duration) { connectTimeout = old }(connectTimeout)
	connectTimeout = time.Hour
	openGivesUpWithin(t, "postgres://u:p@"+silentServer(t)+"/db?sslmode=disable&connect_timeout=1", 5*time.Second)
}

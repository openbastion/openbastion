// Package migrate applies a service's versioned schema migrations to its PostgreSQL
// database (ADR-0030): each numbered file once, in order, each in its own transaction,
// under an advisory lock so that replicas starting together do not race, and never a file
// whose text changed after it was applied.
//
// It uses database/sql and the standard library only; the caller brings the driver.
package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
)

// Migration is one numbered file.
type Migration struct {
	Version  int
	Name     string // the file name, e.g. "001_init.sql"
	SQL      string
	Checksum []byte // SHA-256 of SQL
}

// Result says what Apply found and did.
type Result struct {
	Applied []int // versions applied by this call
	Current int   // highest version this binary knows, now applied
	Unknown []int // versions recorded in the database that this binary does not know
}

var fileName = regexp.MustCompile(`^([0-9]{3})_[a-z0-9_]+\.sql$`)

// Load reads the migrations at the root of files: every *.sql file must be named
// NNN_name.sql, and the versions must run 1, 2, 3… with no gap and no duplicate.
func Load(files fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q is not named NNN_name.sql", e.Name())
		}
		raw, err := fs.ReadFile(files, e.Name())
		if err != nil {
			return nil, err
		}
		v, _ := strconv.Atoi(m[1])
		sum := sha256.Sum256(raw)
		out = append(out, Migration{Version: v, Name: e.Name(), SQL: string(raw), Checksum: sum[:]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migration versions must run 1, 2, 3… with no gap or duplicate: %s is at position %d", m.Name, i+1)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no migration to apply")
	}
	return out, nil
}

// LockKey is the advisory lock a component's migrations are applied under: one per
// component, so that services sharing a database do not wait on each other.
func LockKey(component string) int64 {
	sum := sha256.Sum256([]byte("openbastion.migrate.lock\x00" + component))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

const createTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	component  TEXT        NOT NULL,
	version    INTEGER     NOT NULL,
	name       TEXT        NOT NULL,
	checksum   BYTEA       NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (component, version)
)`

// Apply brings the database to the component's latest migration. It holds the
// component's advisory lock for the whole pass, applies each missing migration in its
// own transaction together with its row in schema_migrations, and refuses — before
// applying anything — when a migration already applied no longer has the text it was
// applied with.
func Apply(ctx context.Context, db *sql.DB, component string, files fs.FS) (Result, error) {
	var res Result
	if component == "" {
		return res, errors.New("a migration needs the name of its component")
	}
	migrations, err := Load(files)
	if err != nil {
		return res, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	// A session lock, on this connection: released by the unlock below, or by the
	// server when the connection goes.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, LockKey(component)); err != nil {
		return res, fmt.Errorf("taking the migration lock: %w", err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, LockKey(component))

	// Created under the lock: two components creating it together would race exactly as
	// the schemas did, so this one statement takes a lock of its own.
	if err := createMigrationsTable(ctx, conn); err != nil {
		return res, err
	}

	applied := map[int]Migration{}
	rows, err := conn.QueryContext(ctx, `SELECT version, name, checksum FROM schema_migrations WHERE component = $1`, component)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		var m Migration
		if err := rows.Scan(&m.Version, &m.Name, &m.Checksum); err != nil {
			rows.Close()
			return res, err
		}
		applied[m.Version] = m
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	known := map[int]bool{}
	for _, m := range migrations {
		known[m.Version] = true
		if done, ok := applied[m.Version]; ok && (!bytes.Equal(done.Checksum, m.Checksum) || done.Name != m.Name) {
			return res, fmt.Errorf("migration %s of %s was changed after it was applied: write a new migration instead", m.Name, component)
		}
	}
	for v := range applied {
		if !known[v] {
			res.Unknown = append(res.Unknown, v)
		}
	}
	sort.Ints(res.Unknown)

	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			continue
		}
		if err := applyOne(ctx, conn, component, m); err != nil {
			return res, fmt.Errorf("migration %s of %s: %w", m.Name, component, err)
		}
		res.Applied = append(res.Applied, m.Version)
	}
	res.Current = migrations[len(migrations)-1].Version
	return res, nil
}

func createMigrationsTable(ctx context.Context, conn *sql.Conn) error {
	key := LockKey("") // shared by every component (none is named \"\"), held only for this statement
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, key); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}
	return tx.Commit()
}

func applyOne(ctx context.Context, conn *sql.Conn, component string, m Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (component, version, name, checksum) VALUES ($1, $2, $3, $4)`,
		component, m.Version, m.Name, m.Checksum); err != nil {
		return err
	}
	return tx.Commit()
}

// Log says with logf (log.Printf) what Apply did: the migrations it applied, and the
// versions the database has that this binary does not know — a database newer than the
// binary, which starts anyway (ADR-0030 rule 6) but must not go unsaid.
func (r Result) Log(component string, logf func(format string, args ...any)) {
	if len(r.Applied) > 0 {
		logf("%s: schema migrations %v applied, schema now at version %d", component, r.Applied, r.Current)
	}
	if len(r.Unknown) > 0 {
		logf("%s: WARNING the database has schema migrations %v that this binary does not know (it knows up to %d): the database is newer than this binary", component, r.Unknown, r.Current)
	}
}

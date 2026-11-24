// Package migrations embeds the Workflow Service schema migrations.
package migrations

import "embed"

// Files contains immutable, numbered migrations applied by pkg/migrate.
//
//go:embed *.sql
var Files embed.FS

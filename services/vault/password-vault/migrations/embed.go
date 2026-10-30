// Package migrations embeds the schema migrations of the Password Vault, applied at
// startup by pkg/migrate (ADR-0030): each NNN_name.sql once, in order, under a lock.
// A file that has been applied is never edited: a change is a new, numbered file.
package migrations

import "embed"

// Files holds every migration of the Password Vault.
//
//go:embed *.sql
var Files embed.FS

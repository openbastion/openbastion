package migrations

import "embed"

// Files holds every Video Recorder migration, applied at startup by pkg/migrate.
//
//go:embed *.sql
var Files embed.FS

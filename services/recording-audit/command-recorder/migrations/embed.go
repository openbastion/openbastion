// Package migrations embeds the Command Recorder's SQL schema so
// cmd/command-recorder can apply it at startup without a separate
// migration tool — mirrors services/access/session-broker/migrations/embed.go.
package migrations

import _ "embed"

//go:embed 001_init.sql
var InitSQL string

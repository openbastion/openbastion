// Package migrations embeds the Audit Service's SQL schema so
// cmd/audit-service can apply it at startup without a separate migration
// tool — mirrors services/vault/password-vault/migrations/embed.go.
package migrations

import _ "embed"

//go:embed 001_init.sql
var InitSQL string

// Package migrations embeds the Password Vault's SQL schema so
// cmd/password-vault can apply it at startup without a separate
// migration tool.
package migrations

import _ "embed"

//go:embed 001_init.sql
var InitSQL string

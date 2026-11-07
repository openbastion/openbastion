package domain

import "context"

// IssuerBinding is the issuer a provider was bound to (ADR-0078): the first one it was started
// with, or the last change declared and written to the audit.
type IssuerBinding struct {
	Provider string
	Issuer   string
	// Created: there was no row, and the issuer wanted was recorded just now.
	Created bool
}

// IssuerBindingRepository keeps the issuer of each OIDC provider (ADR-0078).
type IssuerBindingRepository interface {
	// BindIssuers holds the row of every provider of want (provider -> issuer configured) while
	// decide runs, creating a missing row with its issuer, all in one transaction: two replicas
	// starting together see the same rows. decide returns the rows to change (provider -> new
	// issuer); an error from decide, or from the store, leaves every row as it was — the created
	// ones included.
	BindIssuers(ctx context.Context, want map[string]string, decide func(bound map[string]IssuerBinding) (replace map[string]string, err error)) error
}

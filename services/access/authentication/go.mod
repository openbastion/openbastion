module github.com/openbastion/openbastion/services/access/authentication

go 1.22

require golang.org/x/crypto v0.24.0

require golang.org/x/sys v0.21.0 // indirect

// Voir /NOTES_SANDBOX.md — golang.org est hors allowlist réseau du sandbox,
// son mirroir GitHub officiel ne l'est pas.
replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

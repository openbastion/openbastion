module github.com/openbastion/openbastion/services/access/authentication

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/lib/pq v1.10.9
	golang.org/x/crypto v0.24.0
)

require golang.org/x/sys v0.21.0 // indirect

// Voir /NOTES_SANDBOX.md — golang.org est hors allowlist réseau du sandbox,
// son mirroir GitHub officiel ne l'est pas.
replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

// Migrations de schéma versionnées (ADR-0030). Un replace local explicite, comme
// pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/migrate v0.0.0

replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate

module github.com/openbastion/openbastion/services/access/authentication

go 1.26.0

require (
	github.com/go-ldap/ldap/v3 v3.4.15
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/lib/pq v1.12.3
	golang.org/x/crypto v0.58.0
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

// Migrations de schéma versionnées (ADR-0030). Un replace local explicite, comme
// pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/migrate v0.0.0

replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate

// The version stamped at build (ADR-0063). A local replace, as for pkg/mtls.
require github.com/openbastion/openbastion/pkg/buildinfo v0.0.0

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

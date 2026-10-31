module github.com/openbastion/openbastion/test/integration

go 1.26.0

require (
	github.com/lib/pq v1.10.9
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
	github.com/pkg/sftp v1.13.7
	golang.org/x/crypto v0.58.0
)

require (
	github.com/kr/fs v0.1.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

// Contournement d'un comportement du mode workspace observé empiriquement
// (voir services/proxy/ssh-proxy/go.mod pour le détail) : un replace local
// explicite lève l'ambiguïté quand des replaces externes sont aussi présents.
replace github.com/openbastion/openbastion/pkg/proxycore => ../../pkg/proxycore

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../pkg/mtls

// Migrations de schéma versionnées (ADR-0030). Un replace local explicite, comme
// pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/migrate v0.0.0

replace github.com/openbastion/openbastion/pkg/migrate => ../../pkg/migrate

// Le client Transit, essayé contre un vrai OpenBao (ADR-0049).
require github.com/openbastion/openbastion/pkg/transit v0.0.0

replace github.com/openbastion/openbastion/pkg/transit => ../../pkg/transit

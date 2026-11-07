module github.com/openbastion/openbastion/services/recording-audit/command-recorder

go 1.26.0

require (
	github.com/lib/pq v1.12.3
	golang.org/x/text v0.43.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

// Budget des refus écrits dans l'audit (ADR-0020, ADR-0024), partagé avec le
// Command Recorder ; bibliothèque standard seulement.
require github.com/openbastion/openbastion/pkg/refusalbudget v0.0.0

replace github.com/openbastion/openbastion/pkg/refusalbudget => ../../../pkg/refusalbudget

// Migrations de schéma versionnées (ADR-0030). Un replace local explicite, comme
// pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/migrate v0.0.0

replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate

// Clé d'enveloppe gardée par Transit (ADR-0049). Un replace local explicite, comme pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/transit v0.0.0

replace github.com/openbastion/openbastion/pkg/transit => ../../../pkg/transit

// The version stamped at build (ADR-0063). A local replace, as for pkg/mtls.
require github.com/openbastion/openbastion/pkg/buildinfo v0.0.0

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

// Racine Cobra et commande version communes (ADR-0072).
require github.com/openbastion/openbastion/pkg/command v0.0.0

replace github.com/openbastion/openbastion/pkg/command => ../../../pkg/command

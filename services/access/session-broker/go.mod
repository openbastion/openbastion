module github.com/openbastion/openbastion/services/access/session-broker

go 1.22

require github.com/lib/pq v1.10.9

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

// Webhook signé sortant (ADR-0012, ADR-0013, ADR-0045). Un replace local explicite,
// comme pour pkg/refusalbudget.
require github.com/openbastion/openbastion/pkg/webhook v0.0.0

replace github.com/openbastion/openbastion/pkg/webhook => ../../../pkg/webhook

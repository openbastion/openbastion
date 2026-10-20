module github.com/openbastion/openbastion/services/recording-audit/audit-service

go 1.22

require github.com/lib/pq v1.10.9

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

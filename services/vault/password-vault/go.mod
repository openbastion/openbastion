module github.com/openbastion/openbastion/services/vault/password-vault

go 1.22

require github.com/lib/pq v1.10.9

require golang.org/x/sys v0.21.0 // indirect

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

// Migrations de schéma versionnées (ADR-0030). Un replace local explicite, comme
// pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/migrate v0.0.0

replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate

// Rotation sur la cible (ADR-0037) : le Vault se connecte en SSH avec le compte de
// réconciliation. Même version et même miroir que le proxy SSH (NOTES_SANDBOX.md).
require golang.org/x/crypto v0.24.0

replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

// Reconnaître une cible : clé épinglée ou autorité de certificats (ADR-0039, ADR-0048).
// Un replace local explicite, comme pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/hostkey v0.0.0

replace github.com/openbastion/openbastion/pkg/hostkey => ../../../pkg/hostkey

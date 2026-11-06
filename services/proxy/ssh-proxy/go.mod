module github.com/openbastion/openbastion/services/proxy/ssh-proxy

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
	golang.org/x/crypto v0.58.0
)

require golang.org/x/sys v0.49.0 // indirect

// Un replace local explicite vers pkg/proxycore : il lève l'ambiguïté du mode
// workspace pour un module qui a aussi des dépendances externes (observé quand
// x/crypto passait par un miroir ; gardé, il ne coûte rien).
replace github.com/openbastion/openbastion/pkg/proxycore => ../../../pkg/proxycore

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

// Reconnaître une cible : clé épinglée ou autorité de certificats (ADR-0039, ADR-0048).
// Un replace local explicite, comme pour pkg/mtls.
require github.com/openbastion/openbastion/pkg/hostkey v0.0.0

replace github.com/openbastion/openbastion/pkg/hostkey => ../../../pkg/hostkey

// The version stamped at build (ADR-0063). A local replace, as for pkg/mtls.
require github.com/openbastion/openbastion/pkg/buildinfo v0.0.0

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

// Racine Cobra et commande version communes (ADR-0072).
require github.com/openbastion/openbastion/pkg/command v0.0.0

replace github.com/openbastion/openbastion/pkg/command => ../../../pkg/command

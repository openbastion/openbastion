module github.com/openbastion/openbastion/services/proxy/ssh-proxy

go 1.22

require (
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
	golang.org/x/crypto v0.24.0
)

require golang.org/x/sys v0.21.0 // indirect

// golang.org's vanity import domain is unreachable in this build sandbox;
// the GitHub mirrors are the actual upstream source for these modules and
// are reachable. See /NOTES_SANDBOX.md.
replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

// Contournement d'un comportement du mode workspace observé empiriquement :
// quand un module a AUSSI des dépendances externes avec replace (x/crypto,
// x/sys), la résolution locale de pkg/proxycore via go.work seul échoue
// ("module lookup disabled by GOPROXY=off") alors qu'elle réussit pour tout
// module qui n'a QUE des dépendances locales. Un replace explicite vers le
// chemin local lève l'ambiguïté, quel que soit le mode.
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

module github.com/openbastion/openbastion/test/integration

go 1.22

require (
	github.com/lib/pq v1.10.9
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
	golang.org/x/crypto v0.24.0
)

require golang.org/x/sys v0.21.0 // indirect

// Voir /NOTES_SANDBOX.md — golang.org est hors allowlist réseau du sandbox,
// son mirroir GitHub officiel ne l'est pas.
replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

// Contournement d'un comportement du mode workspace observé empiriquement
// (voir services/proxy/ssh-proxy/go.mod pour le détail) : un replace local
// explicite lève l'ambiguïté quand des replaces externes sont aussi présents.
replace github.com/openbastion/openbastion/pkg/proxycore => ../../pkg/proxycore

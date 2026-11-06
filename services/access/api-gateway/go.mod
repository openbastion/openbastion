module github.com/openbastion/openbastion/services/access/api-gateway

go 1.25.0

// Transport mTLS interne (ADR-0010). Un replace local explicite, comme pour
// pkg/proxycore : il lève l'ambiguïté du mode workspace quand le module a aussi
// des dépendances externes.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

require (
	github.com/coder/websocket v1.8.14
	github.com/openbastion/openbastion/proto v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

require (
	// The version stamped at build (ADR-0063). A local replace, as for pkg/mtls.
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/openbastion/openbastion/pkg/screenstream v0.0.0
)

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

replace github.com/openbastion/openbastion/proto => ../../../proto

replace github.com/openbastion/openbastion/pkg/screenstream => ../../../pkg/screenstream

// Racine Cobra et commande version communes (ADR-0072).
require github.com/openbastion/openbastion/pkg/command v0.0.0

replace github.com/openbastion/openbastion/pkg/command => ../../../pkg/command

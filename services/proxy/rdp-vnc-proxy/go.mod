module github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/mtls v0.0.0
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
	github.com/openbastion/openbastion/pkg/rdp v0.0.0
	github.com/openbastion/openbastion/pkg/screenstream v0.0.0
	github.com/openbastion/openbastion/pkg/vnc v0.0.0
	github.com/openbastion/openbastion/proto v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.58.0 // indirect
)

require (
	github.com/coder/websocket v1.8.14
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/openbastion/openbastion/pkg/tlspin v0.0.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

replace github.com/openbastion/openbastion/pkg/proxycore => ../../../pkg/proxycore

replace github.com/openbastion/openbastion/pkg/rdp => ../../../pkg/rdp

replace github.com/openbastion/openbastion/pkg/screenstream => ../../../pkg/screenstream

replace github.com/openbastion/openbastion/pkg/tlspin => ../../../pkg/tlspin

replace github.com/openbastion/openbastion/pkg/vnc => ../../../pkg/vnc

replace github.com/openbastion/openbastion/proto => ../../../proto

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

// Racine Cobra et commande version communes (ADR-0072).
require github.com/openbastion/openbastion/pkg/command v0.0.0

replace github.com/openbastion/openbastion/pkg/command => ../../../pkg/command

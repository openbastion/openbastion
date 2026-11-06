module github.com/openbastion/openbastion/cli/openbastion-cli

go 1.22

// Transport mTLS interne (ADR-0010) : le CLI parle aux routes internes sous
// l'identité admin-cli. Un replace local explicite, comme dans les services.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../pkg/mtls

// The version stamped at build (ADR-0063). A local replace, as for pkg/mtls.
require github.com/openbastion/openbastion/pkg/buildinfo v0.0.0 // indirect

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../pkg/buildinfo

// Shared version command and Cobra command tree (ADR-0072).
require (
	github.com/openbastion/openbastion/pkg/command v0.0.0
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

replace github.com/openbastion/openbastion/pkg/command => ../../pkg/command

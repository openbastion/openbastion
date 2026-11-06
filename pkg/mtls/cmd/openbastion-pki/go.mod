module github.com/openbastion/openbastion/pkg/mtls/cmd/openbastion-pki

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/openbastion/openbastion/pkg/command v0.0.0
	github.com/openbastion/openbastion/pkg/mtls v0.0.0
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

replace github.com/openbastion/openbastion/pkg/command => ../../../../pkg/command

replace github.com/openbastion/openbastion/pkg/mtls => ../..

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../../pkg/buildinfo

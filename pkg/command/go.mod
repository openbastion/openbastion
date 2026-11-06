module github.com/openbastion/openbastion/pkg/command

go 1.22

replace github.com/openbastion/openbastion/pkg/buildinfo => ../buildinfo

require (
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

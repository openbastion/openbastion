module github.com/openbastion/openbastion/pkg/rdp

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/tlspin v0.0.0
	golang.org/x/crypto v0.58.0
)

replace github.com/openbastion/openbastion/pkg/tlspin => ../tlspin

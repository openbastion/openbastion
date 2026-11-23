module github.com/openbastion/openbastion/pkg/proxycore

go 1.26.0

require github.com/openbastion/openbastion/pkg/screenstream v0.0.0

require (
	github.com/openbastion/openbastion/pkg/securemem v0.0.0-20261123171932-2a177f4763d3
	golang.org/x/crypto v0.59.0
)

replace github.com/openbastion/openbastion/pkg/screenstream => ../screenstream

module github.com/openbastion/openbastion/services/proxy/database-proxy

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/mtls v0.0.0
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
)

require (
	github.com/openbastion/openbastion/pkg/screenstream v0.0.0 // indirect
	github.com/openbastion/openbastion/pkg/securemem v0.0.0-20261123171932-2a177f4763d3 // indirect
	golang.org/x/crypto v0.59.0 // indirect
)

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

replace github.com/openbastion/openbastion/pkg/proxycore => ../../../pkg/proxycore

replace github.com/openbastion/openbastion/pkg/screenstream => ../../../pkg/screenstream

replace github.com/openbastion/openbastion/pkg/securemem => ../../../pkg/securemem

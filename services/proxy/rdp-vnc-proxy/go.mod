module github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/proxycore v0.0.0
	github.com/openbastion/openbastion/pkg/vnc v0.0.0
)

replace github.com/openbastion/openbastion/pkg/proxycore => ../../../pkg/proxycore
replace github.com/openbastion/openbastion/pkg/vnc => ../../../pkg/vnc

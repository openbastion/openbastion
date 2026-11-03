module github.com/openbastion/openbastion/pkg/vnc

go 1.22

require (
	github.com/openbastion/openbastion/pkg/screenstream v0.0.0
	github.com/openbastion/openbastion/pkg/tlspin v0.0.0
)

replace github.com/openbastion/openbastion/pkg/screenstream => ../screenstream
replace github.com/openbastion/openbastion/pkg/tlspin => ../tlspin

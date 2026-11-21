module github.com/openbastion/openbastion/pkg/proxycore

go 1.26.0

require github.com/openbastion/openbastion/pkg/screenstream v0.0.0

require golang.org/x/crypto v0.58.0 // indirect

replace github.com/openbastion/openbastion/pkg/screenstream => ../screenstream

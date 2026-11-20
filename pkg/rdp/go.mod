module github.com/openbastion/openbastion/pkg/rdp

go 1.26.0

require (
	github.com/go-krb5/krb5 v0.1.0
	github.com/go-krb5/x v0.3.2
	github.com/openbastion/openbastion/pkg/screenstream v0.0.0
	github.com/openbastion/openbastion/pkg/tlspin v0.0.0
	golang.org/x/crypto v0.58.0
)

require (
	github.com/go-crypt/x v0.4.12 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/net v0.60.0 // indirect
)

replace github.com/openbastion/openbastion/pkg/tlspin => ../tlspin

replace github.com/openbastion/openbastion/pkg/screenstream => ../screenstream

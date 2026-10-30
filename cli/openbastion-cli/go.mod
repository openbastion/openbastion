module github.com/openbastion/openbastion/cli/openbastion-cli

go 1.22

// Transport mTLS interne (ADR-0010) : le CLI parle aux routes internes sous
// l'identité admin-cli. Un replace local explicite, comme dans les services.
require github.com/openbastion/openbastion/pkg/mtls v0.0.0

replace github.com/openbastion/openbastion/pkg/mtls => ../../pkg/mtls

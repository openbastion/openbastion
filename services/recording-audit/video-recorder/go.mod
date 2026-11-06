module github.com/openbastion/openbastion/services/recording-audit/video-recorder

go 1.25.0

require (
	github.com/lib/pq v1.12.3
	github.com/minio/minio-go/v7 v7.0.84
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/openbastion/openbastion/pkg/migrate v0.0.0
	github.com/openbastion/openbastion/pkg/mtls v0.0.0
	github.com/openbastion/openbastion/pkg/refusalbudget v0.0.0
	github.com/openbastion/openbastion/pkg/transit v0.0.0
	github.com/openbastion/openbastion/proto v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/goccy/go-json v0.10.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/xid v1.6.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

replace github.com/openbastion/openbastion/pkg/refusalbudget => ../../../pkg/refusalbudget

replace github.com/openbastion/openbastion/pkg/transit => ../../../pkg/transit

replace github.com/openbastion/openbastion/proto => ../../../proto

// Racine Cobra et commande version communes (ADR-0072).
require github.com/openbastion/openbastion/pkg/command v0.0.0

replace github.com/openbastion/openbastion/pkg/command => ../../../pkg/command

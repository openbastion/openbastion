module github.com/openbastion/openbastion/services/recording-audit/video-recorder

go 1.22

require (
	github.com/lib/pq v1.12.3
	github.com/minio/minio-go/v7 v7.0.84
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/openbastion/openbastion/pkg/migrate v0.0.0
	github.com/openbastion/openbastion/pkg/mtls v0.0.0
	github.com/openbastion/openbastion/pkg/refusalbudget v0.0.0
	github.com/openbastion/openbastion/pkg/transit v0.0.0
	github.com/openbastion/openbastion/proto v0.0.0
	google.golang.org/grpc v1.71.3
)

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo

replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate

replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

replace github.com/openbastion/openbastion/pkg/refusalbudget => ../../../pkg/refusalbudget

replace github.com/openbastion/openbastion/pkg/transit => ../../../pkg/transit

replace github.com/openbastion/openbastion/proto => ../../../proto

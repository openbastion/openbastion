module github.com/openbastion/openbastion/services/access/workflow-service

go 1.22

require github.com/lib/pq v1.12.3

require (
	github.com/openbastion/openbastion/pkg/buildinfo v0.0.0
	github.com/openbastion/openbastion/pkg/command v0.0.0
	github.com/openbastion/openbastion/pkg/dbpool v0.0.0
	github.com/openbastion/openbastion/pkg/migrate v0.0.0
	github.com/openbastion/openbastion/pkg/mtls v0.0.0
)

replace github.com/openbastion/openbastion/pkg/buildinfo => ../../../pkg/buildinfo
replace github.com/openbastion/openbastion/pkg/command => ../../../pkg/command
replace github.com/openbastion/openbastion/pkg/dbpool => ../../../pkg/dbpool
replace github.com/openbastion/openbastion/pkg/migrate => ../../../pkg/migrate
replace github.com/openbastion/openbastion/pkg/mtls => ../../../pkg/mtls

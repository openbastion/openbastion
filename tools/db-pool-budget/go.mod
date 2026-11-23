module github.com/openbastion/openbastion/tools/db-pool-budget

go 1.26.0

require (
	github.com/openbastion/openbastion/pkg/dbpool v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/openbastion/openbastion/pkg/dbpool => ../../pkg/dbpool

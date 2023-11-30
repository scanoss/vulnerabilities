module scanoss.com/vulnerabilities

go 1.18

require (
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/golobby/config/v3 v3.4.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/lib/pq v1.10.6
	github.com/mattn/go-sqlite3 v1.14.14
	github.com/package-url/packageurl-go v0.1.0
	github.com/scanoss/papi v0.0.4
	go.uber.org/zap v1.21.0
	google.golang.org/grpc v1.53.0
)

require (
	github.com/BurntSushi/toml v1.2.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golobby/cast v1.3.0 // indirect
	github.com/golobby/dotenv v1.3.1 // indirect
	github.com/golobby/env/v2 v2.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.6.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20230301171018-9ab4bdc49ad5 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Details of how to use the "replace" command for local development
// https://github.com/golang/go/wiki/Modules#when-should-i-use-the-replace-directive
// ie. replace github.com/scanoss/papi => ../papi

replace github.com/scanoss/papi => ../papi

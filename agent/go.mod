module github.com/edr-platform/agent

go 1.26.6

require (
	github.com/0xrawsec/golang-etw v1.6.2
	github.com/BurntSushi/toml v1.6.0
	github.com/edr-platform/proto v0.0.0
	github.com/google/uuid v1.6.0
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.83.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/0xrawsec/golang-utils v1.3.1 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/edr-platform/proto => ../proto/gen/go

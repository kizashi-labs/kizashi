# Proto generation for the EDR agent API (buf-based, no system protoc required).
#
# One-time tool install (versions pinned to match the committed generated code):
#   make proto-tools
# Then:
#   make generate   # regenerate proto/gen/go/agent/v1/*.pb.go
#   make lint        # buf lint
#   make build       # buf build (schema compiles)
#
# buf bundles its own compiler, so a system `protoc` is NOT needed. The plugin
# versions below reproduce the existing generated message code byte-for-byte
# (the embedded descriptor of ingestion.pb.go may differ cosmetically between
# the buf compiler and the original protoc — functionally equivalent).

BUF_VERSION            := v1.47.2
PROTOC_GEN_GO_VERSION  := v1.34.2
PROTOC_GEN_GRPC_VERSION := v1.4.0

.PHONY: proto-tools generate lint build

proto-tools:
	go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GRPC_VERSION)

generate:
	buf generate

lint:
	buf lint

build:
	buf build

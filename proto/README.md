# Agent Proto (`agent.v1`)

Wire schema for agent ↔ server: events, ingestion (gRPC), and config.

## Layout

- `agent/v1/*.proto` — source schema
- `gen/go/agent/v1/*.pb.go` — generated Go (committed)

## Code generation (buf)

Generation uses [buf](https://buf.build), which bundles its own protobuf
compiler — **no system `protoc` is required**.

```sh
cd proto
make proto-tools   # one-time: install buf + pinned plugins
make generate      # regenerate gen/go/agent/v1/*.pb.go
make lint          # buf lint (clean on the current schema)
make build         # buf build (verify the schema compiles)
```

Pinned tool versions (in `Makefile`) reproduce the committed generated code:

| tool | version | note |
|---|---|---|
| buf | v1.47.2 | bundled compiler |
| protoc-gen-go | v1.34.2 | matches committed `.pb.go` header |
| protoc-gen-go-grpc | v1.4.0 | matches committed `_grpc.pb.go` (pre-generics API) |

> The embedded file descriptor of `ingestion.pb.go` may differ by a few bytes
> between the buf compiler and the original `protoc v3.21.12` — this is a
> cosmetic serialization difference; the descriptors are functionally equivalent.
> Adopting buf-generated output as canonical is a one-time, reviewed regen.

## Adding a new event type

1. Add the message + a `oneof payload` entry in `agent/v1/events.proto`
   (and an `EventType` enum value).
2. `make generate`.
3. Wire the new type in the agent collector (emit) and the server
   `normalizeEventData` (ingestion) + detection layer (consume).

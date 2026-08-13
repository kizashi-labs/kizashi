# syntax=docker/dockerfile:1
# EDR Platform — Server multi-stage build
# Build context must be the repo root (parent of server/):
#   docker build -f server/Dockerfile --target api .
# Produces two targets: 'api' and 'ingestion'

FROM golang:1.26.5-alpine AS builder
WORKDIR /build

# GIT_COMMIT is passed via --build-arg or docker-compose args.
# Falls back to "unknown" when building without git context.
ARG GIT_COMMIT=unknown

# VERSION is passed via --build-arg from CI (docker.yml uses metadata-action's
# {{version}} output, which strips the leading "v" from semver tags) or from
# docker-compose. Falls back to the contents of server/VERSION (a checked-in
# file kept in sync with the latest tag) when no build-arg is provided, and
# finally to "dev" if even VERSION is missing. The cascading fallback means
# local `docker compose build` always picks up the right version too.
ARG VERSION=

RUN apk add --no-cache git ca-certificates tzdata

# Copy proto module first (needed for replace directive)
COPY proto/gen/go ./proto/gen/go

# Copy server module and download dependencies
COPY server/go.mod server/go.sum ./server/
WORKDIR /build/server
RUN go mod download

# Copy server source
COPY server/ .

# Build API server
# Version is read from server/VERSION file (update this file to bump the release version).
# BuildDate and Commit are injected at compile time.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X main.Version=${VERSION:-$(cat VERSION 2>/dev/null | tr -d '[:space:]' || echo dev)} \
      -X main.BuildDate=$(date -u +%Y-%m-%d) \
      -X main.Commit=${GIT_COMMIT}" \
    -o /bin/api-server ./cmd/api/

# Build Ingestion server
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /bin/ingestion-server ./cmd/ingestion/

# Build Detection server
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /bin/detection-server ./cmd/detection/

# ── Agent builder ─────────────────────────────
FROM golang:1.26.5-alpine AS agent-builder
WORKDIR /build

# VERSION mirrors the builder stage so the agent reports an accurate version
# (dashboard "agent version" column + update-check comparison). docker.yml
# already passes this build-arg; previously the agent-builder did not declare
# ARG VERSION, so the value was silently dropped and every agent reported 0.1.0.
ARG VERSION=

RUN apk add --no-cache git ca-certificates

# Copy proto module
COPY proto/gen/go ./proto/gen/go

# server/VERSION is the version fallback (kept in sync with the release tag),
# matching the api/ingest/detect builds in the `builder` stage.
COPY server/VERSION /build/VERSION

# Copy agent module and download dependencies
COPY agent/go.mod agent/go.sum ./agent/
WORKDIR /build/agent
RUN go mod download

# Copy agent source
COPY agent/ .

# Cross-compile agent for all major platforms, injecting main.version
# (build-arg VERSION, else server/VERSION file, else "dev").
#
# linux/amd64 は `-tags ebpf` で建てる。これがサーバから配られる Linux エージェントの
# 実体で、タグ無しだと eBPF センサーが丸ごと落ちて /proc ポーリングへの縮退版になる
# (短命プロセスを取りこぼし、eBPF 由来の file / library / LSM テレメトリはゼロになる)。
# ci.yml の配布物は元から `-tags ebpf` 付きなので、ここだけが取り残されていた。
# 生成済みの bpf2go バインディングと .o はリポジトリにあるため、このステージに
# clang も BTF も要らない (CO-RE なのでビルドホストのカーネルにも依存しない)。
# ロードに失敗した端末は runEBPFProcessMonitor が警告を出して /proc 監視へ縮退する
# ので、eBPF の無いカーネルへ配っても安全側に倒れる。
#
# linux/arm64 はタグ無しのまま。バインディングは `-D__TARGET_ARCH_x86` で生成されて
# おり、arm64 向けの .o が無い。ci.yml の配布物も同じ理由で amd64 だけが ebpf 付き。
RUN AGENT_VERSION="${VERSION:-$(cat /build/VERSION 2>/dev/null | tr -d '[:space:]' || echo dev)}"; \
    LDFLAGS="-s -w -X main.version=${AGENT_VERSION}"; \
    CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -tags ebpf -ldflags="$LDFLAGS" -o /downloads/edr-agent-linux-amd64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="$LDFLAGS" -o /downloads/edr-agent-linux-arm64       ./cmd/agent && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o /downloads/edr-agent-windows-amd64.exe ./cmd/agent && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="$LDFLAGS" -o /downloads/edr-agent-darwin-amd64      ./cmd/agent && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="$LDFLAGS" -o /downloads/edr-agent-darwin-arm64      ./cmd/agent

# Cross-compile watchdog for Linux and Windows
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o /downloads/edr-watchdog-linux-amd64       ./cmd/watchdog
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o /downloads/edr-watchdog-windows-amd64.exe ./cmd/watchdog

# Pre-compute SHA-256 sidecars so the download checksum endpoint and update-check
# read them instead of hashing the (~13MB) binaries on every request (busybox
# sha256sum; format "<hex>  <file>" matches computeOrReadSHA256). The glob is
# expanded before any .sha256 exists, so it matches only the binaries.
RUN cd /downloads && for f in edr-agent-* edr-watchdog-*; do sha256sum "$f" > "$f.sha256"; done

# ── API target ──────────────────────────────
FROM alpine:3.21 AS api
RUN apk add --no-cache ca-certificates tzdata wget postgresql-client
COPY --from=builder /bin/api-server /api-server
COPY --from=builder /build/server/migrations /migrations
COPY --from=agent-builder /downloads /downloads
RUN mkdir -p /certs
ENV AGENT_BIN_DIR=/downloads
EXPOSE 8080 9090
ENTRYPOINT ["/api-server"]

# ── Ingestion target ─────────────────────────
FROM alpine:3.21 AS ingestion
RUN apk add --no-cache ca-certificates tzdata wget
COPY --from=builder /bin/ingestion-server /ingestion-server
EXPOSE 9091
USER nobody:nobody
ENTRYPOINT ["/ingestion-server"]

# ── Detection target ──────────────────────────
FROM alpine:3.21 AS detection
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/detection-server /detection-server
EXPOSE 8083
USER nobody:nobody
ENTRYPOINT ["/detection-server"]

# ── Production target (alias for api) ─────────
# Used by docker-compose.prod.yml (target: production)
FROM api AS production

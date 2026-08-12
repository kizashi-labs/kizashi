# Stage 1: Build
FROM golang:1.26.5-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go.mod and go.sum first for layer caching
COPY agent/go.mod agent/go.sum ./
COPY proto/gen/go /proto/gen/go

RUN go mod download

# Copy source
COPY agent/ .

# Version injected at build time (e.g. --build-arg AGENT_VERSION=0.2.0)
ARG AGENT_VERSION=0.1.0

# Build agent and watchdog for Linux and Windows
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 \
    go build -ldflags="-s -w -X main.version=${AGENT_VERSION}" -o /out/edr-agent       ./cmd/agent && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 \
    go build -ldflags="-s -w"                                  -o /out/edr-watchdog    ./cmd/watchdog && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -ldflags="-s -w -X main.version=${AGENT_VERSION}" -o /out/edr-agent.exe   ./cmd/agent && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -ldflags="-s -w"                                  -o /out/edr-watchdog.exe ./cmd/watchdog

# Stage 2: Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S edr && adduser -S -G edr edr

# Binaries
COPY --from=builder /out/edr-agent    /usr/local/bin/edr-agent
COPY --from=builder /out/edr-watchdog /usr/local/bin/edr-watchdog

# Directories
RUN mkdir -p /etc/edr /var/log/edr /var/quarantine/edr /var/lib/edr-agent/buffer && \
    chown -R edr:edr /var/log/edr /var/quarantine/edr /var/lib/edr-agent

# Enrollment entrypoint: reads EDR_SERVER_URL and EDR_ENROLLMENT_TOKEN from environment
COPY agent/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

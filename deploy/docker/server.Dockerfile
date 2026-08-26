# EDR Platform Server - Multi-stage Dockerfile
# Build: docker build --build-arg SERVICE=api -t edr-server-api .
#        docker build --build-arg SERVICE=ingestion -t edr-server-ingest .
#        docker build --build-arg SERVICE=detection -t edr-server-detect .

ARG SERVICE=api
ARG GO_VERSION=1.25

# ─── Build Stage ──────────────────────────────────────────────
FROM golang:${GO_VERSION}-alpine AS builder

ARG SERVICE

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev \
    ca-certificates \
    tzdata

# Copy proto module (replace directive points to ../proto/gen/go)
COPY proto/gen/go /proto/gen/go

# Download dependencies first (layer caching)
COPY server/go.mod server/go.sum ./
RUN go mod download

# Copy source
COPY server/ .

# Build the specific service
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always 2>/dev/null || echo 'dev')" \
    -o /app/server \
    ./cmd/${SERVICE}

# ─── Runtime Stage ────────────────────────────────────────────
FROM alpine:3.20

ARG SERVICE
ENV SERVICE_NAME=${SERVICE}

# Security: run as non-root
RUN addgroup -g 1000 edr && \
    adduser -D -u 1000 -G edr edr

# Runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl

WORKDIR /app

# Copy binary and certs
COPY --from=builder /app/server /app/server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Timezone
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
ENV TZ=Asia/Tokyo

# Create necessary directories
RUN mkdir -p /app/rules && chown -R edr:edr /app

USER edr

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/server"]

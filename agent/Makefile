BINARY_AGENT    := agent
BINARY_WATCHDOG := watchdog
MODULE          := github.com/edr-platform/agent
LDFLAGS         := -s -w

# Version from git tag or commit
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS += -X main.version=$(VERSION)

.PHONY: all build build-linux build-linux-arm64 build-windows build-windows-arm64 build-darwin build-darwin-arm64 build-darwin-esf build-all test clean install-linux

all: build

# ─── Local build (host OS) ────────────────────────────────────
build:
	go build $(if $(LDFLAGS),-ldflags "$(LDFLAGS)") -o $(BINARY_AGENT)    ./cmd/agent
	go build $(if $(LDFLAGS),-ldflags "$(LDFLAGS)") -o $(BINARY_WATCHDOG) ./cmd/watchdog

# ─── Cross-compile Linux amd64 (used in Docker / CI) ─────────
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_AGENT)-linux-amd64    ./cmd/agent
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_WATCHDOG)-linux-amd64 ./cmd/watchdog

# ─── Cross-compile Linux arm64 (Raspberry Pi, AWS Graviton, etc.) ──────────
build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_AGENT)-linux-arm64    ./cmd/agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_WATCHDOG)-linux-arm64 ./cmd/watchdog

# ─── Cross-compile Windows amd64 ─────────────────────────────
build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_AGENT)-windows-amd64.exe    ./cmd/agent
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_WATCHDOG)-windows-amd64.exe ./cmd/watchdog

# ─── Cross-compile Windows arm64 (Surface Pro X, etc.) ───────
build-windows-arm64:
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_AGENT)-windows-arm64.exe    ./cmd/agent
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_WATCHDOG)-windows-arm64.exe ./cmd/watchdog

# ─── Cross-compile macOS Intel (ps polling / no ESF) ─────────
build-darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_AGENT)-darwin-amd64    ./cmd/agent
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_WATCHDOG)-darwin-amd64 ./cmd/watchdog

# ─── Cross-compile macOS Apple Silicon (M1/M2/M3) ────────────
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_AGENT)-darwin-arm64    ./cmd/agent
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags "$(LDFLAGS)" -o $(BINARY_WATCHDOG)-darwin-arm64 ./cmd/watchdog

# ─── Build all platforms ──────────────────────────────────────
build-all: build-linux build-linux-arm64 build-windows build-windows-arm64 build-darwin build-darwin-arm64

# ─── macOS with Endpoint Security Framework (ESF) ────────────
# 前提条件:
#   1. Apple の entitlement 承認取得済み
#   2. Developer ID 証明書でコード署名
#   3. macOS ホスト上でのネイティブビルド (CGO_ENABLED=1)
# 署名:
#   codesign --entitlements deploy/darwin/entitlements.plist \
#            --sign "Developer ID Application: Your Name" \
#            $(BINARY_AGENT)-darwin-esf
build-darwin-esf:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
	  go build -tags esf -ldflags "$(LDFLAGS)" \
	    -o $(BINARY_AGENT)-darwin-esf ./cmd/agent

# ─── Tests ───────────────────────────────────────────────────
test:
	go test ./... -count=1

# ─── Clean ───────────────────────────────────────────────────
clean:
	rm -f $(BINARY_AGENT) $(BINARY_WATCHDOG) \
	      $(BINARY_AGENT)-linux-amd64    $(BINARY_WATCHDOG)-linux-amd64 \
	      $(BINARY_AGENT)-linux-arm64    $(BINARY_WATCHDOG)-linux-arm64 \
	      $(BINARY_AGENT)-windows-amd64.exe $(BINARY_WATCHDOG)-windows-amd64.exe \
	      $(BINARY_AGENT)-windows-arm64.exe $(BINARY_WATCHDOG)-windows-arm64.exe \
	      $(BINARY_AGENT)-darwin-amd64   $(BINARY_WATCHDOG)-darwin-amd64 \
	      $(BINARY_AGENT)-darwin-arm64   $(BINARY_WATCHDOG)-darwin-arm64 \
	      $(BINARY_AGENT)-darwin-esf

# ─── Install on Linux host (requires root) ───────────────────
install-linux: build-linux
	@if [ "$$(id -u)" -ne 0 ]; then \
	  echo "ERROR: make install-linux はrootで実行してください"; exit 1; fi
	bash deploy/linux/install.sh

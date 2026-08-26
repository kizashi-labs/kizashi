.PHONY: build test test-unit test-integration test-race bench vet docs lint clean \
        coverage coverage-html \
        licensegen-build licensegen-keygen \
        agent-binaries agent-binaries-linux agent-binaries-windows agent-binaries-darwin \
        build-updater

# ─── エージェントバイナリのビルド先 ──────────────────────────────
# サーバーの /api/v1/installer/download/:os/:arch が参照するディレクトリ
AGENT_BIN_DIR ?= ../downloads
AGENT_DIR     ?= ../agent

# ─── updater バイナリのビルド先 ────────────────────────────────
# Phase 3: 別 container から実行される自動更新バイナリ
UPDATER_BIN ?= ./bin/updater
UPDATER_VERSION ?= dev

build:
	go build ./...

# Linux 向けに updater をクロスコンパイル (Docker container から実行されるため)
build-updater:
	@mkdir -p $(dir $(UPDATER_BIN))
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -ldflags "-s -w -X main.Version=$(UPDATER_VERSION)" \
	  -o $(UPDATER_BIN) ./cmd/updater
	@echo "[+] updater バイナリをビルドしました: $(UPDATER_BIN) (version=$(UPDATER_VERSION))"

# ─── エージェントバイナリのクロスコンパイルと配置 ─────────────────
# インストーラーエンドポイントが配布するバイナリを生成します。
# 使用例: make agent-binaries
# 特定OS: make agent-binaries-linux
#
# 生成物: $(AGENT_BIN_DIR)/edr-agent-{os}-{arch}[.exe]
#
agent-binaries: agent-binaries-linux agent-binaries-windows agent-binaries-darwin
	@echo "[+] 全プラットフォームのエージェントバイナリをビルドしました: $(AGENT_BIN_DIR)/"

agent-binaries-linux:
	@mkdir -p $(AGENT_BIN_DIR)
	cd $(AGENT_DIR) && \
	  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	    go build -ldflags "-s -w" -o $(abspath $(AGENT_BIN_DIR))/edr-agent-linux-amd64 ./cmd/agent && \
	  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
	    go build -ldflags "-s -w" -o $(abspath $(AGENT_BIN_DIR))/edr-agent-linux-arm64 ./cmd/agent
	@echo "[+] Linux バイナリをビルドしました"

agent-binaries-windows:
	@mkdir -p $(AGENT_BIN_DIR)
	cd $(AGENT_DIR) && \
	  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	    go build -ldflags "-s -w" -o $(abspath $(AGENT_BIN_DIR))/edr-agent-windows-amd64.exe ./cmd/agent
	@echo "[+] Windows バイナリをビルドしました"

agent-binaries-darwin:
	@mkdir -p $(AGENT_BIN_DIR)
	cd $(AGENT_DIR) && \
	  GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	    go build -ldflags "-s -w" -o $(abspath $(AGENT_BIN_DIR))/edr-agent-darwin-amd64 ./cmd/agent && \
	  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
	    go build -ldflags "-s -w" -o $(abspath $(AGENT_BIN_DIR))/edr-agent-darwin-arm64 ./cmd/agent
	@echo "[+] macOS バイナリをビルドしました"

# Default: run unit tests only (no DB required).
test: test-unit

test-unit:
	go test ./internal/ml/... ./internal/api/handlers/... -v -count=1 -timeout 60s

test-integration:
	go test -tags=integration ./... -v -count=1 -timeout 120s

test-race:
	CGO_ENABLED=1 go test -race ./internal/ml/... -count=1 -timeout 120s

bench:
	go test ./internal/ml/... ./internal/api/handlers/... -bench=. -benchmem -run='^$$' -count=3 -timeout 120s

vet:
	go vet ./...

# ─── カバレッジ計測（CIとローカルで同一条件）──────────────────────
# バッジ (badges/coverage.json) と同じ手順で総計・パッケージ別・HTML を出力。
# TEST_DATABASE_URL があればそれを使い、無ければ一時 PostgreSQL を自動起動して
# DB 依存の統合テストまで走らせる（品質改善ロードマップ 柱1 の再現性担保）。
#   make coverage                         # 一時DB自動起動 or 既存TEST_DATABASE_URL
#   COVER_THRESHOLD=15 make coverage      # 閾値を下げて実行（現状ベースライン用）
coverage:
	bash scripts/coverage-local.sh

coverage-html: coverage
	@echo "HTML レポート: server/coverage.html"

clean:
	go clean -testcache

# OpenAPI spec validation (requires vacuum: go install github.com/daveshanley/vacuum@latest)
docs-validate:
	vacuum lint docs/openapi.yaml

# Serve OpenAPI spec with Swagger UI (requires docker)
docs-ui:
	docker run --rm -p 8090:8080 \
	  -e SWAGGER_JSON=/docs/openapi.yaml \
	  -v $(PWD)/docs:/docs \
	  swaggerapi/swagger-ui

# Integration tests (requires running DB + NATS)
test-integration:
	go test -tags=integration ./...

# Tenant isolation RLS integration tests
test-tenant-isolation:
	go test -tags=integration -run TestTenant ./tests/integration/...

# Load tests (requires k6 and running server)
load-smoke:
	cd ../tests/load && make smoke

load-test:
	cd ../tests/load && make load

# ─── ライセンスキー発行ツール ───────────────────────────────────
# ビルド: make licensegen-build
licensegen-build:
	go build -o ../bin/licensegen ./cmd/licensegen/
	@echo "✓ ビルド完了: bin/licensegen"

# 初回: キーペアを生成 (秘密鍵は安全な場所に保管)
# 使用例: make licensegen-keygen PRIV=../priv.pem PUB=../pub.pem
licensegen-keygen: licensegen-build
	../bin/licensegen keygen \
	  --out-priv $(or $(PRIV),../priv.pem) \
	  --out-pub  $(or $(PUB),../pub.pem)

# ライセンスキーを発行 (引数例)
# make licensegen-issue ORG="株式会社サンプル" PLAN=business AGENTS=100 USERS=30 EXPIRES=2027-03-31
licensegen-issue: licensegen-build
	../bin/licensegen issue \
	  --priv    $(or $(PRIV),../priv.pem) \
	  --org     "$(ORG)" \
	  --plan    $(or $(PLAN),starter) \
	  --agents  $(or $(AGENTS),0) \
	  --users   $(or $(USERS),0) \
	  --expires $(EXPIRES)

# ─── エージェントバイナリのコード署名 ────────────────────────────
# 署名前に agent-binaries ターゲットでバイナリをビルドしておくこと。
#
# 設定可能な変数 (環境変数またはコマンドライン引数で渡す):
#   SIGN_CERT_PATH          Windows PFX 証明書ファイルのパス
#   SIGN_CERT_PASSWORD      PFX 証明書のパスワード
#   APPLE_TEAM_ID           Apple Developer Team ID (10文字)
#   APPLE_ID                Apple ID メールアドレス (notarytool 用)
#   APPLE_APP_PASSWORD      notarytool 用 App-specific パスワード
#   APPLE_KEYCHAIN_PROFILE  notarytool キーチェーンプロファイル名
#   GPG_KEY_ID              GPG 署名鍵の fingerprint またはメールアドレス
#   GPG_PASSPHRASE          GPG 鍵のパスフレーズ
#
SIGN_CERT_PATH         ?= $(error SIGN_CERT_PATH is not set)
SIGN_CERT_PASSWORD     ?= $(error SIGN_CERT_PASSWORD is not set)
APPLE_TEAM_ID          ?= $(error APPLE_TEAM_ID is not set)
APPLE_ID               ?= $(error APPLE_ID is not set)
APPLE_APP_PASSWORD     ?= $(error APPLE_APP_PASSWORD is not set)
APPLE_KEYCHAIN_PROFILE ?= kizashi-notarize
GPG_KEY_ID             ?= $(error GPG_KEY_ID is not set)
GPG_PASSPHRASE         ?= $(error GPG_PASSPHRASE is not set)

AGENT_WINDOWS_BIN ?= $(AGENT_BIN_DIR)/edr-agent-windows-amd64.exe
AGENT_DARWIN_BIN  ?= $(AGENT_BIN_DIR)/edr-agent-darwin-universal
AGENT_LINUX_AMD64 ?= $(AGENT_BIN_DIR)/edr-agent-linux-amd64
AGENT_LINUX_ARM64 ?= $(AGENT_BIN_DIR)/edr-agent-linux-arm64

.PHONY: sign-windows sign-macos sign-linux verify-signatures release-agents

# ── Windows: Authenticode 署名 (EV 証明書 + RFC 3161 タイムスタンプ) ──
sign-windows:
	@echo "[+] Windows エージェントに署名中: $(AGENT_WINDOWS_BIN)"
	signtool.exe sign \
	  /fd sha256 \
	  /tr http://timestamp.digicert.com \
	  /td sha256 \
	  /f "$(SIGN_CERT_PATH)" \
	  /p "$(SIGN_CERT_PASSWORD)" \
	  /d "Kizashi Agent" \
	  /du "https://kizashi-edr.example.com" \
	  "$(AGENT_WINDOWS_BIN)"
	signtool.exe sign /as \
	  /fd sha256 \
	  /tr http://timestamp.digicert.com \
	  /td sha256 \
	  /f "$(SIGN_CERT_PATH)" \
	  /p "$(SIGN_CERT_PASSWORD)" \
	  "$(AGENT_WINDOWS_BIN)"
	@echo "[+] Windows 署名完了"

# ── macOS: Developer ID 署名 + Apple 公証 (notarization) + staple ──
sign-macos:
	@echo "[+] macOS エージェントに署名中: $(AGENT_DARWIN_BIN)"
	codesign --sign "Developer ID Application: Kizashi Inc ($(APPLE_TEAM_ID))" \
	  --timestamp \
	  --options runtime \
	  --force \
	  "$(AGENT_DARWIN_BIN)"
	codesign --verify --deep --strict --verbose=2 "$(AGENT_DARWIN_BIN)"
	@echo "[+] macOS 署名完了 — 公証 (notarization) を開始"
	xcrun notarytool store-credentials "$(APPLE_KEYCHAIN_PROFILE)" \
	  --apple-id "$(APPLE_ID)" \
	  --team-id "$(APPLE_TEAM_ID)" \
	  --password "$(APPLE_APP_PASSWORD)"
	xcrun notarytool submit "$(AGENT_DARWIN_BIN)" \
	  --keychain-profile "$(APPLE_KEYCHAIN_PROFILE)" \
	  --wait \
	  --output-format json | tee /tmp/notarization-result.json
	@STATUS=$$(python3 -c "import json,sys; d=json.load(open('/tmp/notarization-result.json')); print(d['status'])"); \
	  if [ "$$STATUS" != "Accepted" ]; then \
	    echo "[-] 公証に失敗しました: $$STATUS"; exit 1; \
	  fi
	xcrun stapler staple "$(AGENT_DARWIN_BIN)"
	xcrun stapler validate "$(AGENT_DARWIN_BIN)"
	@echo "[+] macOS 公証・staple 完了"

# ── Linux: GPG デタッチ署名 + SHA-256 チェックサムファイル ──
sign-linux:
	@echo "[+] Linux エージェントに GPG 署名中"
	@for BIN in "$(AGENT_LINUX_AMD64)" "$(AGENT_LINUX_ARM64)"; do \
	  echo "    署名: $$BIN"; \
	  echo "$(GPG_PASSPHRASE)" | gpg --batch --yes \
	    --pinentry-mode loopback \
	    --passphrase-fd 0 \
	    --local-user "$(GPG_KEY_ID)" \
	    --armor \
	    --detach-sign \
	    "$$BIN"; \
	done
	@echo "[+] SHA-256 チェックサムファイルを生成・署名"
	cd "$(AGENT_BIN_DIR)" && \
	  sha256sum edr-agent-linux-amd64 edr-agent-linux-arm64 > SHA256SUMS && \
	  echo "$(GPG_PASSPHRASE)" | gpg --batch --yes \
	    --pinentry-mode loopback \
	    --passphrase-fd 0 \
	    --local-user "$(GPG_KEY_ID)" \
	    --armor \
	    --detach-sign SHA256SUMS
	@echo "[+] Linux GPG 署名完了"

# ── 署名検証: 全プラットフォームの署名をまとめて確認 ──
verify-signatures:
	@echo "[+] Windows 署名を検証中"
	signtool.exe verify /pa /v "$(AGENT_WINDOWS_BIN)"
	@echo "[+] macOS 署名を検証中"
	codesign --verify --deep --strict --verbose=2 "$(AGENT_DARWIN_BIN)"
	xcrun stapler validate "$(AGENT_DARWIN_BIN)"
	spctl --assess --type exec --verbose "$(AGENT_DARWIN_BIN)"
	@echo "[+] Linux GPG 署名を検証中"
	gpg --verify "$(AGENT_LINUX_AMD64).asc" "$(AGENT_LINUX_AMD64)"
	gpg --verify "$(AGENT_LINUX_ARM64).asc" "$(AGENT_LINUX_ARM64)"
	cd "$(AGENT_BIN_DIR)" && gpg --verify SHA256SUMS.asc SHA256SUMS
	cd "$(AGENT_BIN_DIR)" && sha256sum --check SHA256SUMS
	@echo "[+] 全プラットフォームの署名検証が完了しました"

# ── リリース: ビルド → 署名 (全プラットフォーム一括) ──
# 注意: 各 OS の署名ツールが必要なため、通常は CI/CD のマトリクスジョブで
#       プラットフォームごとに個別に実行する。
release-agents: agent-binaries sign-windows sign-macos sign-linux verify-signatures
	@echo "[+] リリース完了: ビルド + 全プラットフォーム署名済みバイナリ"
	@ls -lh $(AGENT_BIN_DIR)/

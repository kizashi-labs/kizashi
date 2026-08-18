#!/usr/bin/env bash
#
# CI のゲートをローカルで再現する。
#
# 使い方:
#   scripts/verify.sh                  変更のあった領域だけを fast で検証
#   scripts/verify.sh --full           ビルドと脆弱性検査まで含める
#   scripts/verify.sh --all            変更に関係なく全領域
#   scripts/verify.sh server frontend  領域を明示（agent / server / frontend / sdk / rules）
#   scripts/verify.sh --list           何を実行して何を飛ばすかだけ表示する
#
# ── なぜこれが要るか ────────────────────────────────────────────
# CI が唯一の品質ゲートで、手元に同じものを流す手段が無かった。Actions が
# 止まると検証手段そのものが消える。ここが埋まっていれば、CI の可否と
# 関係なく push 前に同じ結論を得られる。
#
# ── 設計上の約束 ────────────────────────────────────────────────
# 前提が足りない検査は **黙って飛ばさない**。必ず SKIP として理由つきで
# 出し、最後のまとめにも残す。ci.yml の changes ジョブが
#
#   「走って通った」と「そもそも走っていない」の区別が付かないため、
#     赤が無期限に隠れる（実際に 8 日間隠れた）
#
# と書いているのと同じ理由で、ここでも「実行しなかった」を成功に見せない。
# 終了コードは FAIL があれば 1、無ければ 0。SKIP だけなら 0 で終わるが、
# まとめの末尾に必ず件数を出す。
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# CI と版を揃える。@latest は「コードが変わっていないのに落ちる」経路で、
# このリポジトリでは実際に踏んでいる（ci.yml の staticcheck の項を参照）。
STATICCHECK_VERSION="v0.7.0"
GOVULNCHECK_VERSION="v1.6.0"
SERVER_COVERAGE_MIN=35
AGENT_COVERAGE_MIN=30

MODE="fast"
FORCE_ALL=false
LIST_ONLY=false
AREAS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --full)  MODE="full" ;;
    --fast)  MODE="fast" ;;
    --all)   FORCE_ALL=true ;;
    --list)  LIST_ONLY=true ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    agent|server|frontend|sdk|rules) AREAS+=("$1") ;;
    *) echo "不明な引数: $1（--help を参照）" >&2; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_BLD=""; C_OFF=""
fi

RESULTS=()
N_PASS=0; N_FAIL=0; N_SKIP=0

record() { RESULTS+=("$1|$2|${3:-}"); }

pass() { N_PASS=$((N_PASS+1)); record PASS "$1"; printf '  %sPASS%s  %s\n' "$C_GRN" "$C_OFF" "$1"; }
fail() { N_FAIL=$((N_FAIL+1)); record FAIL "$1"; printf '  %sFAIL%s  %s\n' "$C_RED" "$C_OFF" "$1"; }
skip() { N_SKIP=$((N_SKIP+1)); record SKIP "$1" "$2"; printf '  %sSKIP%s  %s %s(%s)%s\n' "$C_YEL" "$C_OFF" "$1" "$C_DIM" "$2" "$C_OFF"; }

# run <ラベル> <作業ディレクトリ> <コマンド...>
# 失敗したら出力の末尾だけを見せる。全部出すと本当の失敗が埋もれる。
run() {
  local label="$1" dir="$2"; shift 2
  if $LIST_ONLY; then printf '  %sRUN %s  %s\n' "$C_DIM" "$C_OFF" "$label"; return 0; fi
  local log; log="$(mktemp)"
  if (cd "$dir" && "$@") >"$log" 2>&1; then
    pass "$label"
  else
    fail "$label"
    printf '%s' "$C_DIM"; tail -n 25 "$log" | sed 's/^/        /'; printf '%s' "$C_OFF"
  fi
  rm -f "$log"
}

have() { command -v "$1" >/dev/null 2>&1; }

# モジュールの go ディレクティブを返す。
#
# staticcheck や govulncheck を `go run …@version` で入れると、既定の
# GOTOOLCHAIN 解決ではツール側の要求（staticcheck v0.7.0 なら go>=1.25）に
# 合わせて **古い方** のツールチェーンが選ばれる。その状態で go1.26 の
# コードを解析すると全パッケージが
#   "package requires newer Go version go1.26 (application built with go1.25)"
# で落ちる。CI は actions/setup-go が go-version-file でツールチェーンを
# 固定してから go install するので、この経路を踏まない。
# ここでも go.mod の版に明示的に合わせる。
gotoolchain_of() { awk '/^go /{print "go"$2; exit}' "$1/go.mod"; }

# go 系コマンドをモジュールのツールチェーンで実行する
gorun() {
  local label="$1" dir="$2"; shift 2
  run "$label" "$dir" env "GOTOOLCHAIN=$(gotoolchain_of "$dir")" "$@"
}

section() { printf '\n%s── %s %s\n' "$C_BLD" "$1" "$C_OFF"; }

# ── 対象領域の判定 ───────────────────────────────────────────────
# ci.yml の changes ジョブと同じ考え方。判定できないときは全部走らせる側に
# 倒す（取りこぼして緑になるより、余分に回すほうがまし）。
detect_areas() {
  local files base
  base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
  if [ -z "$base" ]; then echo "agent server frontend sdk rules"; return; fi
  files="$(git diff --name-only "$base"...HEAD 2>/dev/null; git status --porcelain | awk '{print $2}')"
  if [ -z "$files" ]; then echo ""; return; fi
  # CI 定義・proto・共通設定が動いたら全部
  if grep -qE '^\.github/workflows/|^proto/|^docker-compose|^Makefile|^scripts/verify\.sh' <<<"$files"; then
    echo "agent server frontend sdk rules"; return
  fi
  local out=""
  grep -qE '^agent/'                    <<<"$files" && out="$out agent"
  grep -qE '^server/'                   <<<"$files" && out="$out server"
  grep -qE '^frontend/'                 <<<"$files" && out="$out frontend"
  grep -qE '^sdk/'                      <<<"$files" && out="$out sdk"
  grep -qE '^rules/|^server/migrations/' <<<"$files" && out="$out rules"
  echo "$out"
}

if [ ${#AREAS[@]} -eq 0 ]; then
  if $FORCE_ALL; then
    AREAS=(agent server frontend sdk rules)
  else
    read -r -a AREAS <<<"$(detect_areas)"
    if [ ${#AREAS[@]} -eq 0 ]; then
      echo "origin/main との差分がありません。全領域を検証するなら --all を付けてください。"
      exit 0
    fi
  fi
fi

wants() { [[ " ${AREAS[*]} " == *" $1 "* ]]; }

printf '%sCI ローカル再現%s  mode=%s  areas=%s\n' "$C_BLD" "$C_OFF" "$MODE" "${AREAS[*]}"
printf '%s%s%s\n' "$C_DIM" "$(git log --oneline -1)" "$C_OFF"

# ── server ───────────────────────────────────────────────────────
if wants server; then
  section "server (Go)"
  if ! have go; then
    skip "server 一式" "go が PATH にありません"
  else
    run   "gofmt"        server bash -c 'test -z "$(gofmt -l .)" || { gofmt -l .; gofmt -d .; false; }'
    gorun "go vet"       server go vet ./...
    gorun "OpenAPI 同期" server go run ./cmd/openapi-sync -check
    gorun "staticcheck"  server go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" ./...

    # CI は postgres と nats をサービスコンテナで用意する。無い場合、依存する
    # テストは落ちる。落ちた理由が「DB が無いから」なのか実際の退行なのかを
    # 取り違えないよう、事前に到達性を見て切り分ける。
    if [ -n "${DATABASE_URL:-}" ] && have psql && psql "$DATABASE_URL" -c 'select 1' >/dev/null 2>&1; then
      gorun "go test (race, coverage)" server \
        go test -race -timeout 120s -coverprofile=coverage.out -covermode=atomic ./...
      gorun "カバレッジ下限 ${SERVER_COVERAGE_MIN}%" server bash -c "
        pct=\$(go tool cover -func=coverage.out | awk '/^total:/{print \$3}' | tr -d '%')
        echo \"total: \${pct}%\"
        awk \"BEGIN{ exit !(\$pct < $SERVER_COVERAGE_MIN) }\" && { echo '下限割れ'; exit 1; }; exit 0"
    else
      skip "go test (race, coverage)" "DATABASE_URL 未設定 / DB に接続できません"
      skip "カバレッジ下限 ${SERVER_COVERAGE_MIN}%" "テストを実行していないため"
    fi

    gorun "migration/負債台帳の一意性" server \
      go test ./internal/store/ -count=1 -run 'TestMigrationNumbers|TestGrandfatheredMigrationDuplicates|TestDebtLedger'

    if [ "$MODE" = "full" ]; then
      gorun "go build (api/ingestion/detection)" server \
        bash -c 'go build ./cmd/api/... && go build ./cmd/ingestion/... && go build ./cmd/detection/...'
      if $LIST_ONLY || curl -sSf -o /dev/null --max-time 10 https://vuln.go.dev/index/db.json 2>/dev/null; then
        gorun "govulncheck" server go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
      else
        skip "govulncheck" "vuln.go.dev に到達できません"
      fi
    fi
  fi
fi

# ── agent ────────────────────────────────────────────────────────
if wants agent; then
  section "agent (Go)"
  if ! have go; then
    skip "agent 一式" "go が PATH にありません"
  else
    run   "gofmt" agent bash -c 'test -z "$(gofmt -l .)" || { gofmt -l .; gofmt -d .; false; }'
    gorun "staticcheck (既定タグ)" agent go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" ./...

    # NetworkMonitor / FilelessMonitor の bpf2go バインディングはコミット
    # 済みなので、素の `-tags ebpf` はそのまま通る。
    gorun "go test -tags ebpf" agent \
      go test -tags ebpf -race -timeout 120s -coverprofile=coverage.out -covermode=atomic ./...
    gorun "カバレッジ下限 ${AGENT_COVERAGE_MIN}%" agent bash -c "
      pct=\$(go tool cover -func=coverage.out | awk '/^total:/{print \$3}' | tr -d '%')
      echo \"total: \${pct}%\"
      awk \"BEGIN{ exit !(\$pct < $AGENT_COVERAGE_MIN) }\" && { echo '下限割れ'; exit 1; }; exit 0"

    # prevention 系 (PreventionLSM / TamperLSM / CredAccessLSM /
    # HostIntegrityMonitor / TLSMonitor) のバインディングはリポジトリに
    # 入っておらず、CI が毎回その場で生成している。生成には clang と
    # 稼働カーネルの BTF、そして bpftool（vmlinux.h のダンプ用）が要る。
    # 揃っていない環境では、実際に防御を有効化する唯一のビルドである
    # `ebpf prevention` を検証できない。ここを黙って飛ばすと、出荷する
    # 構成だけ未検証のまま緑に見える。
    if have clang && [ -r /sys/kernel/btf/vmlinux ] && have bpftool; then
      gorun "staticcheck (ebpf)" agent \
        go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" -tags ebpf ./...
      gorun "staticcheck (ebpf prevention)" agent \
        go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" -tags "ebpf prevention" ./...
      gorun "enforcing 版のビルドとテスト" agent bash -c '
        set -e
        go build -tags "ebpf prevention" -ldflags="-s -w" -o /tmp/edr-agent-ebpf ./cmd/agent/...
        go build -tags "ebpf prevention" -ldflags="-s -w" -o /tmp/edr-watchdog-ebpf ./cmd/watchdog/...
        go test -tags "ebpf prevention" -timeout 120s ./...'
    else
      local_reason="clang / BTF / bpftool のいずれかがありません（LSM バインディング未生成）"
      skip "staticcheck (ebpf)"             "$local_reason"
      skip "staticcheck (ebpf prevention)"  "$local_reason"
      skip "enforcing 版のビルドとテスト"   "$local_reason"
    fi

    gorun "クロスプラットフォーム vet" agent bash -c '
      set -e
      GOOS=windows GOARCH=amd64 go vet ./...
      GOOS=darwin  GOARCH=arm64 go vet ./...
      GOOS=windows GOARCH=amd64 go vet -tags prevention ./...
      GOOS=darwin  GOARCH=arm64 go vet -tags esf ./...
      GOOS=darwin  GOARCH=arm64 go vet -tags "esf prevention" ./...'

    if [ "$MODE" = "full" ]; then
      if $LIST_ONLY || curl -sSf -o /dev/null --max-time 10 https://vuln.go.dev/index/db.json 2>/dev/null; then
        gorun "govulncheck" agent go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
      else
        skip "govulncheck" "vuln.go.dev に到達できません"
      fi
    fi
  fi
fi

# ── frontend ─────────────────────────────────────────────────────
if wants frontend; then
  section "frontend (Next.js)"
  if ! have npm; then
    skip "frontend 一式" "npm が PATH にありません"
  else
    [ -d frontend/node_modules ] || run "npm install" frontend npm install --prefer-offline
    run "lint"            frontend npm run lint
    run "型チェック"      frontend npx tsc --noEmit
    run "mock guard"      frontend node scripts/check-mock-guards.mjs
    run "vitest (coverage)" frontend npm run test:coverage
    if [ "$MODE" = "full" ]; then
      run "next build" frontend npm run build
    fi
  fi
fi

# ── rules ────────────────────────────────────────────────────────
if wants rules; then
  section "rules (Sigma + YARA)"
  if ! have go; then
    skip "検知ルール検証" "go が PATH にありません"
  elif ! have yara; then
    # validate-rules は YARA ルールのコンパイルに yara CLI を呼ぶ。
    skip "検知ルール検証" "yara CLI がありません（apt install yara）"
  else
    run "検知ルール検証" server go run ./cmd/validate-rules -dir ../rules
  fi
fi

# ── sdk ──────────────────────────────────────────────────────────
if wants sdk; then
  section "sdk (Python + TypeScript)"
  if ! have python3 || [ ! -f sdk/python/requirements-dev.txt ]; then
    skip "Python SDK テスト" "python3 または requirements-dev.txt がありません"
  elif ! python3 -c 'import pytest' 2>/dev/null; then
    # 依存を勝手に入れない。システムの Python 環境を書き換えるのは
    # 検証スクリプトの仕事ではないので、入れ方だけ示して飛ばす。
    skip "Python SDK テスト" "pytest 未導入（pip install -r sdk/python/requirements-dev.txt）"
  else
    run "Python SDK テスト" sdk/python python3 -m pytest -q
  fi
  if have npm && [ -f sdk/typescript/package.json ]; then
    [ -d sdk/typescript/node_modules ] || run "npm install (sdk/ts)" sdk/typescript npm install
    run "TypeScript SDK 型チェック" sdk/typescript npm run typecheck
    run "TypeScript SDK テスト"     sdk/typescript npm test
  else
    skip "TypeScript SDK" "npm または sdk/typescript がありません"
  fi
fi

# ── まとめ ───────────────────────────────────────────────────────
printf '\n%s── まとめ %s\n' "$C_BLD" "$C_OFF"
printf '  %sPASS %d%s   %sFAIL %d%s   %sSKIP %d%s\n' \
  "$C_GRN" "$N_PASS" "$C_OFF" "$C_RED" "$N_FAIL" "$C_OFF" "$C_YEL" "$N_SKIP" "$C_OFF"

if [ "$N_SKIP" -gt 0 ]; then
  printf '\n  %s飛ばした検査（CI では実行される。緑と同じ意味にはならない）:%s\n' "$C_YEL" "$C_OFF"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st label reason <<<"$r"
    [ "$st" = "SKIP" ] && printf '    - %s — %s\n' "$label" "$reason"
  done
fi

cat <<'NOTE'

  そもそもこのスクリプトの対象外（CI 専用。ローカルでは再現しない）:
    - Trivy のファイルシステム / イメージスキャン（trivy と docker が要る）
    - Semgrep SAST（semgrep.dev からルールセットを取得する）
    - Gitleaks（リリースバイナリを取得する）
    - Backup & Restore 整合性テスト（postgres サービスが要る）
    - Open PR collision radar（GitHub API を叩く）
NOTE

[ "$N_FAIL" -eq 0 ]

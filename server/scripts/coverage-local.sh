#!/usr/bin/env bash
#
# coverage-local.sh — CIとローカルで同一条件のカバレッジ計測（品質改善ロードマップ 柱1）
#
# 目的:
#   バッジ (badges/coverage.json) と同じ手順で go test のカバレッジを算出し、
#   総計・パッケージ別・HTML を出力する。DB 依存の統合テストを確実に走らせるため
#   TEST_DATABASE_URL を必須とし、未設定なら一時 PostgreSQL を自動起動して埋める。
#
# 使い方:
#   TEST_DATABASE_URL=postgres://... ./scripts/coverage-local.sh   # 既存DBを使う（CI相当）
#   ./scripts/coverage-local.sh                                    # 一時DBを自動起動（開発機）
#
# 環境変数:
#   TEST_DATABASE_URL   既存の PostgreSQL 接続文字列。設定時はそれを使い自動起動しない。
#   COVER_THRESHOLD     CIゲート閾値（既定 40）。総計がこれ未満なら exit 2。
#   COVER_PKG           計測対象パッケージ（既定 ./...）。
#
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1   # server/ ディレクトリへ

COVER_THRESHOLD="${COVER_THRESHOLD:-40}"
COVER_PKG="${COVER_PKG:-./...}"
OUT="${OUT:-coverage.out}"
PG_PROC=""
PGDATA=""

log()  { printf '\033[36m[coverage]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[coverage]\033[0m %s\n' "$*" >&2; }

cleanup() {
  if [ -n "$PG_PROC" ] && [ -n "$PGDATA" ]; then
    log "一時 PostgreSQL を停止します"
    if [ "$(id -u)" = "0" ] && id postgres >/dev/null 2>&1; then
      su postgres -s /bin/bash -c "'${PGCTL:-pg_ctl}' -D '$PGDATA' stop -m fast" >/dev/null 2>&1 || true
    else
      "${PGCTL:-pg_ctl}" -D "$PGDATA" stop -m fast >/dev/null 2>&1 || true
    fi
    rm -rf "$PGDATA" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ─── DB 準備 ───────────────────────────────────────────────────────────────────
if [ -z "${TEST_DATABASE_URL:-}" ]; then
  warn "TEST_DATABASE_URL 未設定 → 一時 PostgreSQL を起動します（DB統合テストを走らせるため）"

  # initdb/pg_ctl の絶対パスを解決（su postgres は PATH をリセットするため絶対パス必須）
  INITDB="$(command -v initdb 2>/dev/null || true)"
  PGCTL="$(command -v pg_ctl 2>/dev/null || true)"
  if [ -z "$INITDB" ] || [ -z "$PGCTL" ]; then
    PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
    if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then
      warn "initdb が見つかりません。PostgreSQL を導入するか TEST_DATABASE_URL を設定してください。"
      exit 3
    fi
    INITDB="$PGBIN/initdb"
    PGCTL="$PGBIN/pg_ctl"
    export PATH="$PGBIN:$PATH"
  fi

  PGDATA="$(mktemp -d /tmp/edr-cov-pg.XXXXXX)"
  PGSOCK="$(mktemp -d /tmp/edr-cov-sock.XXXXXX)"
  PGPORT="${PGPORT:-55432}"

  # root では initdb を実行できないため postgres システムユーザーに委譲
  RUN=""
  if [ "$(id -u)" = "0" ]; then
    if ! id postgres >/dev/null 2>&1; then
      warn "root 実行かつ postgres ユーザーが存在しません。非 root で実行するか TEST_DATABASE_URL を設定してください。"
      exit 3
    fi
    chown -R postgres:postgres "$PGDATA" "$PGSOCK"
    RUN="su postgres -s /bin/bash -c"
  fi

  init_and_start() {
    local cmd="$1"
    if [ -n "$RUN" ]; then $RUN "$cmd"; else bash -c "$cmd"; fi
  }

  log "initdb 実行中: $PGDATA"
  init_and_start "'$INITDB' -D '$PGDATA' -U edr --auth=trust" >"$PGDATA.initdb.log" 2>&1 || { warn "initdb 失敗:"; cat "$PGDATA.initdb.log" >&2; exit 3; }
  init_and_start "'$PGCTL' -D '$PGDATA' -o '-p $PGPORT -k $PGSOCK' -l '$PGDATA/pg.log' start" >/dev/null 2>&1
  PG_PROC="running"
  sleep 2

  psql -h "$PGSOCK" -p "$PGPORT" -U edr -d postgres -c "CREATE DATABASE edrplatform_test;" >/dev/null 2>&1 || true
  export TEST_DATABASE_URL="postgres://edr@/edrplatform_test?host=$PGSOCK&port=$PGPORT"

  # マイグレーション適用（CI と同じく ON_ERROR_STOP 無し＝timescaledb 不在でも後続 CREATE を継続）
  log "マイグレーション適用中（timescaledb 不在は許容）"
  applied=0
  for f in migrations/*.sql; do
    psql "$TEST_DATABASE_URL" -q -f "$f" >/dev/null 2>&1 || true
    applied=$((applied+1))
  done
  log "マイグレーション $applied ファイルを適用"
else
  log "既存の TEST_DATABASE_URL を使用します"
fi

export DATABASE_URL="${DATABASE_URL:-$TEST_DATABASE_URL}"

# ─── カバレッジ計測 ─────────────────────────────────────────────────────────────
log "go test カバレッジ計測中: $COVER_PKG"
# COVER_PKG は複数パッケージ（空白区切り）を許容するため意図的に非クォート
# shellcheck disable=SC2086
go test $COVER_PKG -coverprofile="$OUT" -covermode=atomic -timeout 300s
test_status=$?

if [ ! -f "$OUT" ]; then
  warn "カバレッジプロファイルが生成されませんでした（テストがビルドできていない可能性）"
  exit 1
fi

TOTAL="$(go tool cover -func="$OUT" | awk '/^total:/ {print $3}')"
go tool cover -html="$OUT" -o coverage.html 2>/dev/null || true

echo
log "───────────────────────────────────────────────"
log "総カバレッジ: ${TOTAL}   (閾値 ${COVER_THRESHOLD}%)"
log "HTML: server/coverage.html / プロファイル: server/$OUT"
if [ "$test_status" -ne 0 ]; then
  warn "一部テストが失敗しています（上記ログ参照）。カバレッジ数値は参考値です。"
fi
log "───────────────────────────────────────────────"

# 閾値判定（数値部分のみ抽出して比較）
PCT="${TOTAL%\%}"
if awk "BEGIN { exit !($PCT < $COVER_THRESHOLD) }"; then
  warn "総カバレッジ ${TOTAL} が閾値 ${COVER_THRESHOLD}% を下回っています。"
  exit 2
fi
log "閾値クリア。"

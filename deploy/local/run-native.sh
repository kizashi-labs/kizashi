#!/usr/bin/env bash
#
# run-native.sh — Docker を使わずに EDR バックエンドをローカル起動する。
#
# 用途: Docker が使えない/イメージ pull が制限された環境(隔離サンドボックス等)で、
#       稼働する API サーバに接続して curate や attack-scorer を実地検証したいとき。
#       通常の永続環境では docker compose 経路(deploy/local/README.md 参照)を推奨。
#
# 構成: ネイティブ postgres(16) + nats-server(JetStream) + go build した api を起動。
#       detection は --with-detection で追加起動できる(検知パイプラインまで動かす場合)。
#
# 前提: PostgreSQL 16 のバイナリ(initdb/pg_ctl/psql)、Go 1.25+、curl、openssl。
#       nats-server は無ければ `go install` で自動取得する。
#
# 使い方:
#   sudo deploy/local/run-native.sh                 # api のみ
#   sudo deploy/local/run-native.sh --with-detection
#   deploy/local/run-native.sh --stop               # 停止・後片付け
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${EDR_RUN_DIR:-/tmp/edr-local}"
PGDATA="$RUN_DIR/pgdata"
PGSOCK="$RUN_DIR/pgsock"
PGPORT="${PGPORT:-5432}"
NATS_PORT="${NATS_PORT:-4222}"
API_PORT="${API_PORT:-8080}"
DB="edrplatform"

log()  { printf '\033[36m[edr-local]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[edr-local]\033[0m %s\n' "$*" >&2; }

pgbin() {
  command -v "$1" 2>/dev/null && return 0
  local d; d="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
  [ -n "$d" ] && echo "$d/$1"
}

stop_all() {
  log "停止中…"
  pkill -f "$RUN_DIR/edr-api" 2>/dev/null || true
  pkill -f "$RUN_DIR/edr-detection" 2>/dev/null || true
  pkill -f "nats-server -p $NATS_PORT" 2>/dev/null || true
  local pgctl; pgctl="$(pgbin pg_ctl)"
  if [ -d "$PGDATA" ] && [ -n "$pgctl" ]; then
    if [ "$(id -u)" = 0 ] && id postgres >/dev/null 2>&1; then
      su postgres -s /bin/bash -c "'$pgctl' -D '$PGDATA' stop -m fast" >/dev/null 2>&1 || true
    else
      "$pgctl" -D "$PGDATA" stop -m fast >/dev/null 2>&1 || true
    fi
  fi
  log "停止しました(データは $RUN_DIR に残ります。完全削除は rm -rf $RUN_DIR)。"
}

if [ "${1:-}" = "--stop" ]; then stop_all; exit 0; fi

WITH_DETECTION=0
[ "${1:-}" = "--with-detection" ] && WITH_DETECTION=1

INITDB="$(pgbin initdb)"; PGCTL="$(pgbin pg_ctl)"; PSQL="$(pgbin psql)"
if [ -z "$INITDB" ] || [ -z "$PGCTL" ] || [ -z "$PSQL" ]; then
  warn "PostgreSQL 16 のバイナリが見つかりません。導入してください。"; exit 3
fi

mkdir -p "$RUN_DIR"

# ── .env(秘密情報)を無ければ生成 ─────────────────────────────
ENVFILE="$ROOT/.env"
if [ ! -f "$ENVFILE" ]; then
  log ".env を生成します(秘密情報はランダム)"
  cat > "$ENVFILE" <<EOF
POSTGRES_PASSWORD=$(openssl rand -base64 18 | tr '/+' '__' | tr -d '\n')
JWT_SECRET=$(openssl rand -base64 48 | tr '/+' '__' | tr -d '\n' | cut -c1-48)
ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '\n')
SIGMAHQ_SYNC_ENABLED=false
DARKWEB_MONITOR_ENABLED=false
EOF
fi
set -a; . "$ENVFILE"; set +a

# ── postgres ──────────────────────────────────────────────────
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  log "initdb: $PGDATA"
  rm -rf "$PGDATA" "$PGSOCK"; mkdir -p "$PGDATA" "$PGSOCK"
  RUNAS=""; [ "$(id -u)" = 0 ] && id postgres >/dev/null 2>&1 && { chown -R postgres:postgres "$PGDATA" "$PGSOCK"; RUNAS="su postgres -s /bin/bash -c"; }
  if [ -n "$RUNAS" ]; then $RUNAS "'$INITDB' -D '$PGDATA' -U edr --auth=trust" >/dev/null 2>&1
  else "$INITDB" -D "$PGDATA" -U edr --auth=trust >/dev/null 2>&1; fi
fi
RUNAS=""; [ "$(id -u)" = 0 ] && id postgres >/dev/null 2>&1 && { chown -R postgres:postgres "$PGDATA" "$PGSOCK" 2>/dev/null; RUNAS="su postgres -s /bin/bash -c"; }
# pg.log は postgres ユーザーが所有する $PGDATA 配下に置く($RUN_DIR は root 所有で
# postgres ユーザーが書けないため)。
START="'$PGCTL' -D '$PGDATA' -o '-p $PGPORT -k $PGSOCK -c listen_addresses=127.0.0.1' -l '$PGDATA/pg.log' start"
if [ -n "$RUNAS" ]; then $RUNAS "$START" >/dev/null 2>&1; else bash -c "$START" >/dev/null 2>&1; fi
sleep 2
DBURL="postgres://edr@127.0.0.1:$PGPORT/$DB?sslmode=disable"
"$PSQL" -h 127.0.0.1 -p "$PGPORT" -U edr -d postgres -c "CREATE DATABASE $DB;" >/dev/null 2>&1 || true

# migrations (CI と同じく ON_ERROR_STOP 無し=timescaledb 不在でも後続 CREATE を継続)
log "マイグレーション適用中…"
for f in "$ROOT"/server/migrations/*.sql; do "$PSQL" "$DBURL" -q -f "$f" >/dev/null 2>&1 || true; done
tables=$("$PSQL" "$DBURL" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
log "テーブル数: $tables"

# ── nats-server ───────────────────────────────────────────────
export PATH="$PATH:$(go env GOPATH)/bin"
if ! command -v nats-server >/dev/null 2>&1; then
  log "nats-server を go install で取得中…"; go install github.com/nats-io/nats-server/v2@latest
fi
pkill -f "nats-server -p $NATS_PORT" 2>/dev/null || true
nats-server -p "$NATS_PORT" -js -sd "$RUN_DIR/nats" >"$RUN_DIR/nats.log" 2>&1 &
sleep 2

# ── build & run api ───────────────────────────────────────────
log "api をビルド中…"
( cd "$ROOT/server" && go build -o "$RUN_DIR/edr-api" ./cmd/api ) || { warn "api ビルド失敗"; exit 1; }

export DATABASE_URL="$DBURL" NATS_URL="nats://127.0.0.1:$NATS_PORT"
export HTTP_PORT="$API_PORT" GRPC_PORT=9090 RUN_MIGRATIONS=false
export CERT_DIR="$RUN_DIR/certs" AGENT_BIN_DIR="$RUN_DIR/downloads"
export SERVER_URL="http://localhost:$API_PORT" EDR_BASE_URL="http://localhost:$API_PORT"
export GIN_MODE=release LOG_LEVEL=info
mkdir -p "$CERT_DIR" "$AGENT_BIN_DIR"
pkill -f "$RUN_DIR/edr-api" 2>/dev/null || true
nohup "$RUN_DIR/edr-api" > "$RUN_DIR/api.log" 2>&1 &
log "api 起動中(port $API_PORT)…"

for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$API_PORT/healthz" 2>/dev/null || true)
  [ "$code" = "200" ] && break; sleep 1
done
[ "${code:-}" = "200" ] || { warn "api が healthy になりません。ログ: $RUN_DIR/api.log"; tail -20 "$RUN_DIR/api.log" >&2; exit 1; }

# ── optional detection ────────────────────────────────────────
if [ "$WITH_DETECTION" = 1 ]; then
  log "detection をビルド・起動中…"
  ( cd "$ROOT/server" && go build -o "$RUN_DIR/edr-detection" ./cmd/detection ) && {
    pkill -f "$RUN_DIR/edr-detection" 2>/dev/null || true
    nohup "$RUN_DIR/edr-detection" > "$RUN_DIR/detection.log" 2>&1 &
    log "detection 起動しました。"
  }
fi

# ── 完了サマリ ────────────────────────────────────────────────
echo
log "───────────────────────────────────────────────"
log "稼働サーバ: http://localhost:$API_PORT  (healthz=200)"
log "  ログイン: admin@localhost / \$ADMIN_PASSWORD (.env)"
log "  DB:   $DBURL"
log "  NATS: nats://127.0.0.1:$NATS_PORT"
log "  ログ: $RUN_DIR/{api,detection,nats}.log, $PGDATA/pg.log"
log ""
log "トークン取得:"
log "  TOKEN=\$(curl -s -X POST http://localhost:$API_PORT/api/v1/auth/login \\"
log "    -H 'Content-Type: application/json' \\"
log "    -d \"{\\\"email\\\":\\\"admin@localhost\\\",\\\"password\\\":\\\"\$ADMIN_PASSWORD\\\"}\" | jq -r .token)"
log "curate 状態:  curl -s -H \"Authorization: Bearer \$TOKEN\" http://localhost:$API_PORT/api/v1/admin/detection/curate/status"
log "停止:         deploy/local/run-native.sh --stop"
log "───────────────────────────────────────────────"

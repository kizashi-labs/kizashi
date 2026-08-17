#!/usr/bin/env bash
# FP ソークを docker 無しで走らせる。
#
# なぜ要るのか:
#
#   - CI の fp-soak.yml は concurrency group が 1 本しかなく、待機列にも 1 本しか
#     入らない。別々のブランチが同時にソークを起こすと後から来た方が待機中の run を
#     置き換えるので、**PR が 2 本走っているだけで自分の計測が流れる**。
#     2026-08-04 に 3 回連続で押し出された。
#   - docs/ops/FPソーク運用.md §3-2 のローカル手順は docker compose 前提で、
#     docker が使えない環境 (CI コンテナ内、権限のないホスト) では動かない。
#
# TimescaleDB は要らない。migration は `|| true` で失敗を許容しており
# (fp-soak.yml も同じ)、素の PostgreSQL 16 で 269 ルールが投入される。
#
# 使い方:
#
#   tests/fpsoak/local-soak.sh setup                 # PG + NATS を立てて migration
#   tests/fpsoak/local-soak.sh run <label> [env...]  # 1 アーム実行して採点
#   tests/fpsoak/local-soak.sh report <label>        # 結果を再表示
#   tests/fpsoak/local-soak.sh teardown
#
# A/B の例 — 検知経路の変更が SOC のキューをどう動かすかを、同一マシン・同一 seed で:
#
#   tests/fpsoak/local-soak.sh setup
#   tests/fpsoak/local-soak.sh run before EDR_SIGMA_DB_RULES=0
#   tests/fpsoak/local-soak.sh run after  EDR_SIGMA_DB_RULES=1
#
# ⚠️ ここで出る絶対値を docs/results/baseline_fp_soak.csv と比べないこと。
# baseline は「CI 自身が出した数字」でなければ意味がない (§5)。ローカルの価値は
# **2 アームの差分**であって、水準ではない。
#
# ⚠️ このスクリプトは長時間 (1 アームあたり約 25 分) 走る。プロセスが回収される
# 環境では前景で待つこと。detach したまま放置すると、ソーク中に PG ごと消える。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${FPSOAK_WORK:-/tmp/fpsoak-local}"
PGDATA="${FPSOAK_PGDATA:-/var/lib/postgresql/fpsoak-local/pgdata}"
PGPORT="${FPSOAK_PGPORT:-55432}"
NATSPORT="${FPSOAK_NATSPORT:-4222}"
PGBIN="${FPSOAK_PGBIN:-/usr/lib/postgresql/16/bin}"
DBURL="postgres://edr@127.0.0.1:${PGPORT}/edr_fpsoak"
TOKEN="fpsoak-local-token"

AGENTS="${FPSOAK_AGENTS:-20}"
DURATION="${FPSOAK_DURATION:-600s}"
SPEED="${FPSOAK_SPEED:-12}"
SEED="${FPSOAK_SEED:-20260728}"
WINDOW="${FPSOAK_WINDOW:-15m}"

die() { echo "ERROR: $*" >&2; exit 1; }

ports_busy() {
  python3 - "$@" <<'EOF'
import socket, sys
for p in sys.argv[1:]:
    s = socket.socket(); s.settimeout(1)
    busy = s.connect_ex(("127.0.0.1", int(p))) == 0
    s.close()
    if busy: sys.exit(0)
sys.exit(1)
EOF
}

cmd_setup() {
  command -v "$PGBIN/initdb" >/dev/null || die "postgres server binaries not at $PGBIN (set FPSOAK_PGBIN)"
  command -v nats-server >/dev/null || [ -x "$HOME/go/bin/nats-server" ] || \
    die "nats-server not found — go install github.com/nats-io/nats-server/v2@v2.10.29"
  NATS_BIN="$(command -v nats-server || echo "$HOME/go/bin/nats-server")"

  mkdir -p "$WORK"/{bin,logs,certs,out,jetstream}
  id postgres >/dev/null 2>&1 || die "no 'postgres' user; postgres refuses to run as root"

  if [ ! -d "$PGDATA" ]; then
    mkdir -p "$(dirname "$PGDATA")"
    chown postgres:postgres "$(dirname "$PGDATA")"
    su postgres -s /bin/bash -c \
      "PATH=$PGBIN:\$PATH initdb -D $PGDATA -U edr --auth=trust" > "$WORK/logs/initdb.log" 2>&1 \
      || die "initdb failed, see $WORK/logs/initdb.log"
  fi
  su postgres -s /bin/bash -c \
    "PATH=$PGBIN:\$PATH pg_ctl -D $PGDATA -l $PGDATA/../pg.log \
     -o '-p $PGPORT -c listen_addresses=127.0.0.1 -c max_connections=200' -w start" || true
  psql "postgres://edr@127.0.0.1:${PGPORT}/postgres" -tAc \
    "SELECT 1 FROM pg_database WHERE datname='edr_fpsoak'" | grep -q 1 || \
    psql "postgres://edr@127.0.0.1:${PGPORT}/postgres" -c "CREATE DATABASE edr_fpsoak" >/dev/null
  psql "$DBURL" -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"' >/dev/null

  # TimescaleDB is absent and that is fine — fp-soak.yml applies migrations with
  # `|| true` too, so both paths tolerate the hypertable statements failing.
  echo "applying migrations (errors are tolerated, as in CI)..."
  for f in "$ROOT"/server/migrations/*.sql; do
    psql -q "$DBURL" -f "$f" >/dev/null 2>&1 || true
  done
  echo "enabled sigma rules: $(psql "$DBURL" -tAc "SELECT count(*) FROM rules WHERE enabled AND type='sigma'")"

  # The enroll RPC reads the CA to sign CSRs even with TLS disabled.
  if [ ! -f "$WORK/certs/ca.crt" ]; then
    openssl genrsa -out "$WORK/certs/ca.key" 2048 2>/dev/null
    openssl req -new -x509 -days 30 -key "$WORK/certs/ca.key" -out "$WORK/certs/ca.crt" \
      -subj "/CN=EDR FP Soak CA/O=LOCAL" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$WORK/certs/ca.key" -out "$WORK/certs/ca.p8" 2>/dev/null
    mv "$WORK/certs/ca.p8" "$WORK/certs/ca.key"
  fi
  psql "$DBURL" -c "INSERT INTO settings(key,value) VALUES('enrollment_token','$TOKEN')
                    ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null

  pgrep -x nats-server >/dev/null || \
    nohup "$NATS_BIN" -js -sd "$WORK/jetstream" -p "$NATSPORT" > "$WORK/logs/nats.log" 2>&1 &
  sleep 3
  pgrep -x nats-server >/dev/null || die "nats-server did not start, see $WORK/logs/nats.log"

  echo "building..."
  ( cd "$ROOT/server" && go build -o "$WORK/bin/ingestion" ./cmd/ingestion \
      && go build -o "$WORK/bin/api" ./cmd/api \
      && go build -o "$WORK/bin/detection" ./cmd/detection \
      && go build -o "$WORK/bin/fpsoak-report" ./cmd/fpsoak-report ) || die "server build failed"
  ( cd "$ROOT/agent" && go build -o "$WORK/bin/fleet-sim" ./cmd/fleet-sim ) || die "agent build failed"
  echo "setup complete: $WORK"
}

cmd_run() {
  local label="${1:-}"; shift || true
  [ -n "$label" ] || die "usage: local-soak.sh run <label> [KEY=VALUE ...]"
  [ -x "$WORK/bin/api" ] || die "run setup first"

  # Any KEY=VALUE arguments become environment for the services — this is how an
  # A/B arm differs from its control.
  for kv in "$@"; do export "${kv?}"; done

  export DATABASE_URL="$DBURL" NATS_URL="nats://127.0.0.1:${NATSPORT}" TLS_ENABLED=false
  export CA_CERT_FILE="$WORK/certs/ca.crt" CA_KEY_FILE="$WORK/certs/ca.key"
  export GRPC_PORT=9091 PORT=8080
  export AI_ANALYSIS_ENABLED=false AUTO_RESPONSE_ENABLED=false DARKWEB_MONITOR_ENABLED=false
  export JWT_SECRET="$(openssl rand -hex 32)"

  local L="$WORK/logs/$label"; mkdir -p "$L"
  ports_busy 8080 9091 && die "ports 8080/9091 still in use — a previous arm has not exited"

  # Each arm starts from an empty alerts table or the scorer counts the previous
  # arm's rows.
  for t in alerts events; do psql "$DBURL" -c "TRUNCATE $t CASCADE" >/dev/null 2>&1; done
  psql "$DBURL" -c "DELETE FROM agents" >/dev/null 2>&1

  # All THREE services. Dropping `detection` removes the stateful rate detectors
  # (discovery / file_burst / lateral_fanout / exfil_volume / auth_attack), which
  # are the noisiest on a benign fleet — the run would look quiet and be wrong.
  # NOT `local`: the EXIT trap fires after this function has returned, so a
  # function-scoped PID is already out of scope by then — under `set -u` that
  # turns a clean finish into "PI: unbound variable" and a non-zero exit.
  "$WORK/bin/ingestion" > "$L/ingestion.log" 2>&1 & PI=$!
  "$WORK/bin/api"       > "$L/api.log"       2>&1 & PA=$!
  "$WORK/bin/detection" > "$L/detection.log" 2>&1 & PD=$!
  # Kill the siblings on any exit path: a service left holding :8080 turns the
  # NEXT arm's startup into "address already in use", which reads like a port
  # conflict rather than "the previous arm never finished".
  trap 'kill -9 ${PI:-} ${PA:-} ${PD:-} 2>/dev/null' EXIT

  local ready=0
  for i in $(seq 1 120); do
    for svc in ingestion:$PI api:$PA detection:$PD; do
      kill -0 "${svc##*:}" 2>/dev/null || { echo "FATAL: ${svc%%:*} died"; tail -25 "$L/${svc%%:*}.log"; exit 1; }
    done
    if grep -q "検知パイプラインを開始しました" "$L/api.log" 2>/dev/null \
       && grep -q "gRPC ingestion server 起動" "$L/ingestion.log" 2>/dev/null \
       && grep -q "検知ルールを読み込みました" "$L/detection.log" 2>/dev/null; then
      ready=1; break
    fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "FATAL: stack not ready"; tail -30 "$L"/*.log; exit 1; }

  echo "── [$label] rules loaded ──"
  grep -E "組み込みSigmaルール|sigma_db|Sigmaルールを読み込みました" "$L/api.log" || true
  grep -E "検知ルールを読み込みました" "$L/detection.log" || true

  ( cd "$ROOT" && "$WORK/bin/fleet-sim" \
      -server 127.0.0.1 -enroll-port 9091 -stream-port 9091 -token "$TOKEN" \
      -agents "$AGENTS" -profiles tests/fpsoak/profiles \
      -duration "$DURATION" -speed "$SPEED" -seed "$SEED" \
      -manifest "$WORK/manifest-$label.json" ) > "$L/fleet-sim.log" 2>&1

  echo "── [$label] soak done, scoring ($WINDOW window) ──"
  "$WORK/bin/fpsoak-report" -db "$DBURL" -manifest "$WORK/manifest-$label.json" \
    -window "$WINDOW" -quiesce 90s \
    -out "$WORK/out/$label.csv" -md "$WORK/out/$label.md" > "$L/report.log" 2>&1

  # Snapshot the analyst-facing numbers BEFORE -label would relabel everything.
  # (This script deliberately omits -label for that reason; see cmd_report.)
  # `harness` は測定リグ自身が出すアラート (ソーク終了でエージェントが黙るため
  # ホストごとに offline + health が 1 件ずつ)。検知内容ではない。
  #
  # ★ これを OPEN から抜くのは体裁の問題ではない。ハーネス由来はソーク終了の
  #   タイミング次第で出たり出なかったりし、20台なら最大 20 件アーム間で振れる。
  #   2026-08-09 の migration 378 の A/B では、検知アラートが 289→271 と 18 件
  #   減っているのに、ハーネス由来が 20→40 と増えたせいで OPEN は 155→175 と
  #   「20 件悪化」に見えた。**改善が悪化に見えた。**
  #   下の ★ 注記は「行数ではなく OPEN で比べろ」と言っているが、その OPEN が
  #   リグ自身のノイズを含んでいては同じ穴に落ちる。
  psql "$DBURL" -tAc "
    SELECT '$label|' || count(*) || '|' ||
           count(*) FILTER (WHERE description LIKE '%二重エンジン%') || '|' ||
           count(*) FILTER (WHERE description LIKE '%[重複排除:%') || '|' ||
           count(*) FILTER (WHERE status = 'open') || '|' ||
           count(*) FILTER (WHERE title LIKE 'エージェントオフライン:%'
                               OR title LIKE '%ヘルス警告') || '|' ||
           count(*) FILTER (WHERE status = 'open'
                              AND title NOT LIKE 'エージェントオフライン:%'
                              AND title NOT LIKE '%ヘルス警告')
    FROM alerts" > "$WORK/out/$label.counts"
  cmd_report "$label"
}

cmd_report() {
  local label="${1:-}"
  [ -f "$WORK/out/$label.counts" ] || die "no result for '$label'"
  IFS='|' read -r _ rows xeng title open harness openDet < "$WORK/out/$label.counts"
  cat <<EOF

── [$label] ────────────────────────────────────
  alert ROWS               $rows      <- what the scorecard counts
    merged (cross-engine)  $xeng
    merged (same title)    $title
  OPEN alerts              $open
    of which harness       $harness      <- rig artifacts, NOT detection content
  OPEN (detection only)    $openDet      <- ★ compare arms on THIS

  scorecard: $WORK/out/$label.csv

  ★ Compare arms on OPEN (detection only), not on rows and not on raw OPEN.
    Deduplication resolves rows and RETAINS
    them, so fpsoak-report — which counts every row in the window regardless of
    status — cannot see it. Measuring a dedup change by the headline number
    reports no effect no matter how well it works (learned the hard way,
    2026-08-04: four runs before anyone checked what the scorer counts).
EOF
}

cmd_teardown() {
  pkill -9 -f "$WORK/bin/" 2>/dev/null
  pkill -x nats-server 2>/dev/null
  su postgres -s /bin/bash -c "PATH=$PGBIN:\$PATH pg_ctl -D $PGDATA stop" 2>/dev/null
  echo "stopped (data kept at $PGDATA; results at $WORK/out)"
}

case "${1:-}" in
  setup)    cmd_setup ;;
  run)      shift; cmd_run "$@" ;;
  report)   shift; cmd_report "$@" ;;
  teardown) cmd_teardown ;;
  *) sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac

#!/usr/bin/env bash
# EC2 検証環境で「データが表示されない」原因を切り分ける読み取り専用スクリプト。
#
# 使い方 (EC2 のリポジトリルートで実行):
#   bash scripts/diagnose-data-display.sh            # DB / コンテナのみ
#   ADMIN_TOKEN=<JWT> bash scripts/diagnose-data-display.sh   # API 応答も確認
#
# 何も変更しない (SELECT と docker logs の grep のみ)。出力をそのまま貼れば
# 「RLS でテナント不一致」「GRANT 漏れ (chunk 含む)」「API/DB は正常でフロント側」の
# いずれかまで切り分けられる。
set -uo pipefail

PG_CONTAINER="${PG_CONTAINER:-kizashi-postgres}"
PG_USER="${PG_USER:-edr}"
PG_DB="${PG_DB:-edrplatform}"
API_BASE="${API_BASE:-http://localhost:8080}"
DEFAULT_TENANT='00000000-0000-0000-0000-000000000001'

psql_q() { docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -X -q "$@"; }
section() { printf '\n═══ %s ═══\n' "$1"; }

section "1. コンテナ稼働状況"
docker compose ps 2>/dev/null || docker ps --format 'table {{.Names}}\t{{.Status}}'

section "2. アプリがどの DB ロールで接続しているか"
# edr_app が並べば RLS 実効モード、edr のみなら切替前 (RLS は素通り)。
psql_q -c "SELECT usename, count(*) AS conns
           FROM pg_stat_activity WHERE datname = '$PG_DB'
           GROUP BY 1 ORDER BY 2 DESC;"

section "3. compose の APP_DATABASE_URL 設定 (パスワードは伏せる)"
grep -h '^APP_DATABASE_URL' .env 2>/dev/null | sed -E 's#//([^:]+):[^@]*@#//\1:***@#' \
  || echo "(.env に APP_DATABASE_URL の行なし = DATABASE_URL にフォールバック中)"

section "4. migration 適用状況 (32x)"
psql_q -c "SELECT version, applied_at FROM schema_migrations
           WHERE version LIKE '32%' ORDER BY version;"

section "5. RLS の有効/FORCE 状態"
psql_q -c "SELECT c.relname, c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public'
             AND c.relname IN ('agents','alerts','incidents','users')
           ORDER BY 1;"

section "6. edr_app ロール属性 (rolbypassrls=t なら RLS は素通り)"
psql_q -c "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls
           FROM pg_roles WHERE rolname IN ('edr','edr_app') ORDER BY 1;"

section "7. テナント一覧"
psql_q -c "SELECT id, name, slug, is_active FROM tenants ORDER BY created_at;"

section "8. 行がどのテナントに属しているか (★ここが分かれていると RLS で消える)"
psql_q -c "SELECT 'agents' AS tbl, COALESCE(tenant_id::text,'(NULL)') AS tenant_id, count(*)
             FROM agents    GROUP BY 2
           UNION ALL SELECT 'alerts',    COALESCE(tenant_id::text,'(NULL)'), count(*) FROM alerts    GROUP BY 2
           UNION ALL SELECT 'incidents', COALESCE(tenant_id::text,'(NULL)'), count(*) FROM incidents GROUP BY 2
           UNION ALL SELECT 'users',     COALESCE(tenant_id::text,'(NULL)'), count(*) FROM users     GROUP BY 2
           ORDER BY 1, 2;"

section "9. ログインユーザの tenant_id (JWT に載る値)"
psql_q -c "SELECT email, role, COALESCE(tenant_id::text,'(NULL)') AS tenant_id, is_active
           FROM users ORDER BY created_at LIMIT 20;"

section "10. edr_app 視点での可視件数 (RLS 実効時に UI が見る件数)"
# SET ROLE は所有者接続から可能。ログイン許可もパスワードも不要。
psql_q <<SQL
SET ROLE edr_app;
SET app.tenant_id = '$DEFAULT_TENANT';
SELECT 'agents' AS tbl, count(*) AS visible_rows FROM agents
UNION ALL SELECT 'alerts',    count(*) FROM alerts
UNION ALL SELECT 'incidents', count(*) FROM incidents
UNION ALL SELECT 'users',     count(*) FROM users
ORDER BY 1;
RESET app.tenant_id;
RESET ROLE;
SQL

section "11. GRANT 漏れ: public スキーマのテーブル/ビュー/マテビュー"
# ランブックのドライランは relkind='r' のみを見ている。'p'(パーティション)
# 'v'(ビュー) 'm'(マテビュー) が漏れていると切替後にその画面だけ 500 になる。
psql_q -c "SELECT c.relkind,
             count(*) AS total,
             count(*) FILTER (WHERE NOT has_table_privilege('edr_app', c.oid, 'SELECT')) AS missing_select
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m')
           GROUP BY 1 ORDER BY 1;"

section "12. ★GRANT 漏れ: TimescaleDB chunk (events / network_connections の実体)"
# hypertable への GRANT は chunk へ伝播するが、chunk は _timescaledb_internal に
# あり public の走査対象外。ここが 0 でないとイベント系の画面だけがデータ 0 件
# / 500 になる。
#
# ★実チャンク (_hyper_N_M_chunk / compress_hyper_N_M_chunk) だけを対象にする。
# _timescaledb_internal には bgw_job_stat 等の TimescaleDB 内部カタログも同居して
# おり、それらは TimescaleDB 自身のバックグラウンドワーカ (所有者権限) だけが
# 書き込む。edr_app に INSERT が無いのは正常なので、含めると誤検知になる。
psql_q -c "SELECT count(*) AS chunks,
             count(*) FILTER (WHERE NOT has_table_privilege('edr_app', c.oid, 'SELECT')) AS missing_select,
             count(*) FILTER (WHERE NOT has_table_privilege('edr_app', c.oid, 'INSERT')) AS missing_insert
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname LIKE '\_timescaledb\_internal%'
             AND c.relkind IN ('r','p')
             AND (c.relname LIKE '\_hyper\_%\_chunk'
                  OR c.relname LIKE 'compress\_hyper\_%\_chunk');"

section "13. edr_app で実データを読めるか (chunk 権限の実地確認)"
psql_q <<'SQL'
SET ROLE edr_app;
SELECT count(*) AS events_last_24h FROM events WHERE time > NOW() - INTERVAL '24 hours';
RESET ROLE;
SQL

section "14. 直近ログの権限エラー / DB エラー"
docker compose logs --since=30m 2>/dev/null \
  | grep -iE "permission denied|must be owner|does not exist|SQLSTATE|panic" \
  | tail -40 \
  || echo "(該当なし)"

section "15. 実データの新しさ (そもそも書き込まれているか)"
psql_q -c "SELECT
             (SELECT count(*) FROM agents) AS agents,
             (SELECT max(last_seen) FROM agents) AS agent_last_seen,
             (SELECT count(*) FROM alerts) AS alerts,
             (SELECT max(created_at) FROM alerts) AS alert_latest,
             (SELECT count(*) FROM events WHERE time > NOW() - INTERVAL '24 hours') AS events_24h;"

if [ -n "${ADMIN_TOKEN:-}" ]; then
  section "16. API 応答 (ADMIN_TOKEN 指定時)"
  for path in /health /api/v1/agents /api/v1/alerts /api/v1/dashboard /api/v1/dashboard/summary; do
    code=$(curl -sS -o /tmp/diag_body -w '%{http_code}' \
             -H "Authorization: Bearer $ADMIN_TOKEN" "$API_BASE$path" 2>/dev/null)
    printf '%-32s %s  %s\n' "$path" "$code" "$(head -c 200 /tmp/diag_body)"
  done
  rm -f /tmp/diag_body
else
  section "16. API 応答"
  echo "(ADMIN_TOKEN 未指定のためスキップ。ADMIN_TOKEN=<JWT> を付けて再実行すると"
  echo " 「DB には有るが API が返していない」のか「API は返すがフロントが表示していない」のか"
  echo " まで切り分けられる)"
fi

printf '\n読み方:\n'
printf '  * 2 で edr_app が居る + 8 でユーザのテナントと行のテナントが違う → RLS で不可視 (最有力)\n'
printf '  * 11/12 の missing_* が 0 でない → GRANT 漏れ。その画面だけ 500 になる\n'
printf '  * 15 が 0 件 → 表示ではなく収集側 (agent / ingestion) の問題\n'
printf '  * 16 が 200 でデータを含むのに UI が空 → フロントエンド側の問題\n'

#!/usr/bin/env bash
# Bring up a migrated PostgreSQL for the store tests, without Docker.
#
#   eval "$(scripts/local-db.sh up)"   # 起動して TEST_DATABASE_URL を出す
#   scripts/local-db.sh down           # 止めて消す
#
# **なぜ要るのか。** internal/store の検査の多くは TEST_DATABASE_URL が
# 無ければ丸ごと飛びます。飛んだ検査と通った検査は、同じ `ok` の行を出します。
# 実際、スキーマ契約のゲート（write_contract_test.go）は、全マイグレーションを
# 当てた DB に対して一度も走っていませんでした —— 直したはずの項目が
# 「まだ壊れている」と書いたまま残っていたのは、そのためです。
#
# testcontainers を使う既存の統合テスト（-tags=integration）は Docker を
# 要ります。この環境には Docker がありませんが、PostgreSQL 16 は入って
# います。こちらはそれを直接使います。
#
# **TimescaleDB は入れられません。** 拡張が無いので、
#   - `CREATE EXTENSION timescaledb` の行は読み飛ばし
#   - `create_hypertable` / `add_*_policy` は何もしない関数で置き換え
#   - `ALTER TABLE ... SET (timescaledb.*)` は読み飛ばし
# ます。**テーブルと列は本物ですが、ハイパーテーブルではありません。**
# 分割・圧縮・保持期間に依存する検査は、ここでは意味を持ちません。
set -euo pipefail

PGBIN=${PGBIN:-/usr/lib/postgresql/16/bin}
PGROOT=${PGROOT:-/var/tmp/edr-localdb}
PGPORT=${PGPORT:-55432}
DBNAME=${DBNAME:-edrplatform_test}
DBUSER=${DBUSER:-edr}
URL="postgres://${DBUSER}@127.0.0.1:${PGPORT}/${DBNAME}?sslmode=disable"

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MIGRATIONS="$REPO/server/migrations"

say() { echo "$*" >&2; }

# initdb と postgres は root では動きません。root なら postgres ユーザーに
# 落とします（コンテナではこちらが普通です）。
as_pg() {
  if [ "$(id -u)" = "0" ]; then su postgres -s /bin/bash -c "$1"; else bash -c "$1"; fi
}

up() {
  # データディレクトリが無いのにポートが応答するなら、消した中身を掴んだ
  # ままの前回のサーバです。そのまま進むと、新しいクラスタを作っても
  # 「起動済み」と見なして飛ばし、`pg_filenode.map が無い` で全部落ちます。
  #
  # ここで pkill は使いません。`pkill -f "postgres.*-p 55432"` は
  # **その文字列を含む呼び出し元のシェル自身に当たります。** 実際に
  # 当たって、スクリプトごと落ちました。
  if [ ! -s "$PGROOT/data/PG_VERSION" ] \
     && "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" -q 2>/dev/null; then
    say "!! ポート $PGPORT に前回のサーバが残っています（データは消えています）。"
    say "   止めてから、もう一度: $0 down && $0 up"
    return 1
  fi

  if [ ! -s "$PGROOT/data/PG_VERSION" ]; then
    say "== クラスタを作ります ($PGROOT/data)"
    rm -rf "$PGROOT"
    mkdir -p "$PGROOT/data" "$PGROOT/run"
    if [ "$(id -u)" = "0" ]; then chown -R postgres:postgres "$PGROOT"; fi
    chmod 700 "$PGROOT/data"
    as_pg "$PGBIN/initdb -D $PGROOT/data -U $DBUSER --auth=trust -E UTF8" >/dev/null
  fi

  if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" -q 2>/dev/null; then
    say "== 起動します (port $PGPORT)"
    as_pg "$PGBIN/pg_ctl -D $PGROOT/data -l $PGROOT/server.log \
      -o '-p $PGPORT -k $PGROOT/run -c listen_addresses=127.0.0.1' -w start" >/dev/null
  fi

  if ! psql "postgres://${DBUSER}@127.0.0.1:${PGPORT}/postgres?sslmode=disable" \
       -tAc "SELECT 1 FROM pg_database WHERE datname='$DBNAME'" | grep -q 1; then
    say "== $DBNAME を作ります"
    psql "postgres://${DBUSER}@127.0.0.1:${PGPORT}/postgres?sslmode=disable" \
      -q -c "CREATE DATABASE $DBNAME OWNER $DBUSER"
    migrate
  fi

  echo "export TEST_DATABASE_URL='$URL'"
}

migrate() {
  say "== マイグレーションを当てます"
  # TimescaleDB の代わり。何もしませんが、呼び出しは通ります。
  psql "$URL" -q <<'SQL'
CREATE OR REPLACE FUNCTION create_hypertable(regclass, name,
  chunk_time_interval interval DEFAULT NULL, if_not_exists boolean DEFAULT false,
  migrate_data boolean DEFAULT false) RETURNS void
  LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$;
CREATE OR REPLACE FUNCTION create_hypertable(text, text) RETURNS void
  LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$;
CREATE OR REPLACE FUNCTION add_retention_policy(regclass, interval,
  if_not_exists boolean DEFAULT false) RETURNS integer
  LANGUAGE plpgsql AS $$ BEGIN RETURN 0; END $$;
CREATE OR REPLACE FUNCTION add_compression_policy(regclass, interval,
  if_not_exists boolean DEFAULT false) RETURNS integer
  LANGUAGE plpgsql AS $$ BEGIN RETURN 0; END $$;
SQL

  local tmp applied=0 failed=0
  tmp=$(mktemp -d)

  for f in "$MIGRATIONS"/*.sql; do
    python3 - "$f" "$tmp/$(basename "$f")" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
src = re.sub(r'CREATE EXTENSION[^;]*timescaledb[^;]*;', 'SELECT 1;', src, flags=re.I)
src = re.sub(r'ALTER TABLE\s+\w+\s+SET\s*\((?:[^()]*timescaledb[^()]*)\)\s*;',
             'SELECT 1;', src, flags=re.I | re.S)
open(sys.argv[2], 'w').write(src)
PY
    # ON_ERROR_STOP は付けません。timescaledb 前提の文が残っている
    # ファイルがあり、その1文だけ落ちて残りは正しく通ります。
    psql "$URL" -q -f "$tmp/$(basename "$f")" >/dev/null 2>&1 \
      && applied=$((applied + 1)) || failed=$((failed + 1))
  done

  rm -rf "$tmp"

  say "== 適用 $applied / 一部失敗 $failed"
  # **ここが肝心です。** スキーマ契約のゲートは、DB がマイグレーションより
  # 遅れていると自分から中断します（差分をコードの欠陥として報告しないため）。
  # 遅れたまま「緑」を受け取らないよう、ここでも数えます。
  local missing
  missing=$(psql "$URL" -tAc "SELECT count(*) FROM (VALUES ('alerts'),('agents'),
    ('rules'),('users'),('tenants'),('tenant_encryption_keys'),('events'),
    ('network_connections')) AS t(n)
    WHERE n NOT IN (SELECT tablename FROM pg_tables WHERE schemaname='public')")
  if [ "$missing" != "0" ]; then
    say "!! 主要テーブルが $missing 件足りません。検査は当てにできません"
    return 1
  fi
}

down() {
  # 先に止めてから消します。順番を逆にすると、消えたデータを掴んだ
  # サーバがポートを握ったまま残ります。
  if [ -f "$PGROOT/data/postmaster.pid" ]; then
    as_pg "$PGBIN/pg_ctl -D $PGROOT/data -w -m fast stop" >/dev/null 2>&1 || true
  fi
  rm -rf "$PGROOT"
  say "== 止めて消しました"
}

case "${1:-up}" in
  up)      up ;;
  migrate) migrate ;;
  down)    down ;;
  url)     echo "$URL" ;;
  *)       say "usage: $0 {up|migrate|down|url}"; exit 2 ;;
esac

#!/usr/bin/env bash
# SSE (/ws/alerts) がどこで壊れているかを切り分ける。
#
#   A. API 直接        — Caddy を通さない
#   B. Caddy 経由 + gzip 要求あり (ブラウザと同じ条件)
#   C. Caddy 経由 + gzip 要求なし
#
# B だけ失敗すれば Caddy の `encode gzip` が text/event-stream を圧縮している
# ことが原因。A も失敗すれば API 側。
#
# 使い方 (EC2 のリポジトリルートで):
#   bash scripts/probe-sse.sh admin@example.com
set -uo pipefail

EMAIL="${1:-}"
PUBLIC_URL="${PUBLIC_URL:-https://203-0-113-10.nip.io}"
DIRECT_URL="${DIRECT_URL:-http://localhost:8080}"
SSE_PATH="${SSE_PATH:-/ws/alerts}"
WAIT_SECS="${WAIT_SECS:-8}"

if [ -z "$EMAIL" ]; then
  echo "usage: bash scripts/probe-sse.sh <email>" >&2
  exit 2
fi

printf 'パスワード (%s): ' "$EMAIL" >&2
read -rs PASSWORD
printf '\n' >&2

payload=$(EMAIL="$EMAIL" PASSWORD="$PASSWORD" python3 -c \
  'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["PASSWORD"]}))')

TOKEN=$(curl -sS -k --max-time 20 -H 'Content-Type: application/json' \
          -d "$payload" "$PUBLIC_URL/api/v1/auth/login" 2>/dev/null \
        | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("token",""))
except Exception:
    print("")')

if [ -z "$TOKEN" ]; then
  echo "★ ログインに失敗しました。パスワードを確認してください。" >&2
  exit 1
fi
echo "トークン取得 OK"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# run <label> <outfile> <curl args...>
run() {
  local label="$1" out="$2"; shift 2
  echo
  echo "═══ $label ═══"
  # -N: バッファリング無効 (SSE をそのまま見る)
  # -D: ヘッダを別ファイルへ。timeout で打ち切るのが正常系。
  timeout "$WAIT_SECS" curl -sS -N -D "$out.hdr" -o "$out.body" "$@" 2>"$out.err"
  local rc=$?

  echo "--- レスポンスヘッダ ---"
  grep -iE "^HTTP/|^content-type:|^content-encoding:|^transfer-encoding:|^via:" "$out.hdr" 2>/dev/null \
    || echo "(ヘッダなし)"

  echo "--- ボディ先頭 ---"
  if [ -s "$out.body" ]; then
    head -c 300 "$out.body" | tr -d '\0'; echo
  else
    echo "(空)"
  fi

  # timeout(124) は SSE が繋がったまま待っていた = 正常。
  if [ "$rc" -eq 124 ]; then
    echo "→ curl 終了: timeout (${WAIT_SECS}s) = ストリーム接続が継続していた"
  else
    echo "→ curl 終了コード: $rc"
    [ -s "$out.err" ] && sed 's/^/   /' "$out.err"
  fi

  # 判定
  if grep -qi '^content-encoding: *gzip' "$out.hdr" 2>/dev/null; then
    echo "★ content-encoding: gzip — SSE が圧縮されている (これが原因)"
  fi
  if grep -q 'data: ' "$out.body" 2>/dev/null; then
    echo "✓ SSE イベントを受信できた"
  else
    echo "✗ SSE イベントを受信できなかった"
  fi
}

run "A. API 直接 (Caddy を通さない)" "$tmp/a" \
    "$DIRECT_URL$SSE_PATH?token=$TOKEN"

run "B. Caddy 経由 + gzip 要求あり (ブラウザと同じ)" "$tmp/b" \
    -k -H 'Accept-Encoding: gzip' "$PUBLIC_URL$SSE_PATH?token=$TOKEN"

run "C. Caddy 経由 + gzip 要求なし" "$tmp/c" \
    -k -H 'Accept-Encoding: identity' "$PUBLIC_URL$SSE_PATH?token=$TOKEN"

cat <<'EOF'

読み方:
  * A と C が ✓ で B だけ ✗  → Caddy の `encode gzip` が text/event-stream を
                                圧縮しているのが原因。encode をサイト全体から外し、
                                /ws* 以外のブロックに個別に付ける
  * A が ✓ で B も C も ✗     → Caddy の別要因 (ルーティング / タイムアウト)
  * A が ✗                    → API 側。docker compose logs --tail=50 api を確認
EOF

#!/usr/bin/env bash
# ログインして主要 API を叩き、「API が返していない」のか「API は返すがフロントが
# 表示していない」のかを切り分ける。読み取り専用 (GET のみ / login を除く)。
#
# 使い方 (EC2 上で実行):
#   bash scripts/probe-api.sh <ログインに使うメールアドレス>
#   例: bash scripts/probe-api.sh admin@example.com
#
# パスワードは対話入力 (エコーなし)。シェル履歴にもログにも残さない。
set -uo pipefail

EMAIL="${1:-}"
PUBLIC_URL="${PUBLIC_URL:-https://203-0-113-10.nip.io}"
DIRECT_URL="${DIRECT_URL:-http://localhost:8080}"

if [ -z "$EMAIL" ]; then
  echo "usage: bash scripts/probe-api.sh <email>" >&2
  echo "  (診断スクリプトのセクション 9 で is_active=t のアカウントを使ってください)" >&2
  exit 2
fi

printf 'パスワード (%s): ' "$EMAIL" >&2
read -rs PASSWORD
printf '\n' >&2

login_payload=$(EMAIL="$EMAIL" PASSWORD="$PASSWORD" python3 -c \
  'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["PASSWORD"]}))')

# ── 1. 公開 URL 経由 (nginx → frontend の rewrite → api) でログイン ────────────
echo "═══ 1. ログイン (公開URL経由: $PUBLIC_URL) ═══"
login_res=$(curl -sS -k --max-time 20 -w '\n%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "$login_payload" \
  "$PUBLIC_URL/api/v1/auth/login" 2>&1)
login_code=$(printf '%s' "$login_res" | tail -n1)
login_body=$(printf '%s' "$login_res" | sed '$d')
echo "HTTP $login_code"
printf '%s\n' "$login_body" | head -c 400; echo

TOKEN=$(printf '%s' "$login_body" | python3 -c \
  'import json,sys
try:
    print(json.load(sys.stdin).get("token",""))
except Exception:
    print("")' 2>/dev/null)

if [ -z "$TOKEN" ]; then
  echo
  echo "★ トークンが取得できませんでした。"
  echo "  - mfa_required:true が返っている → MFA 有効。MFA 無しのアカウントで再実行してください"
  echo "  - HTTP 401 → パスワード誤り、またはアカウントが無効 (診断 SC.9 の is_active)"
  echo "  - HTTP 000/タイムアウト → 公開URL から API へ到達できていない (nginx / frontend rewrite)"
  exit 1
fi
echo "→ トークン取得 OK"

# ── 2. 主要エンドポイントを 2 経路で叩いて比較 ──────────────────────────────
PATHS=(
  /api/v1/agents
  /api/v1/alerts
  /api/v1/dashboard
  /api/v1/dashboard/summary
  /api/v1/incidents
  /api/v1/events
)

probe() {
  local base="$1" label="$2"
  echo
  echo "═══ $label ($base) ═══"
  printf '%-30s %-6s %-10s %s\n' "PATH" "CODE" "BYTES" "BODY (先頭200字)"
  for p in "${PATHS[@]}"; do
    body=$(curl -sS -k --max-time 20 -o /tmp/probe_body -w '%{http_code}' \
             -H "Authorization: Bearer $TOKEN" "$base$p" 2>/dev/null)
    size=$(wc -c < /tmp/probe_body | tr -d ' ')
    head_txt=$(head -c 200 /tmp/probe_body | tr '\n' ' ')
    printf '%-30s %-6s %-10s %s\n' "$p" "$body" "$size" "$head_txt"
  done
  rm -f /tmp/probe_body
}

probe "$DIRECT_URL" "2. API コンテナ直叩き"
probe "$PUBLIC_URL" "3. 公開URL経由 (ブラウザと同じ経路)"

cat <<'EOF'

読み方:
  * 2 も 3 も 200 でデータを含む      → バックエンドは正常。フロントエンド側の問題
  * 2 は 200 でデータ有 / 3 が 000・404・502 → nginx or frontend の rewrite が壊れている
  * 2 が 200 だが件数 0 / 空配列        → バックエンドのクエリ側の問題
  * 2 が 401/403                        → 認証・権限。402 → プランゲート
  * 2 が 500                            → API のエラー。docker compose logs api を確認
EOF

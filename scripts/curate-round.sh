#!/usr/bin/env bash
# curate-round.sh — SigmaHQ 同期ルールを本番で「1ラウンドずつ」安全に有効化する運用ドライバ。
#
# ロードマップ P1「段階 curate」の API 版ループ(status → run → FP 観測)をワンコマンド化する。
# 既定は READ-ONLY(status 表示のみ)。実際に有効化するのは明示的に --run を渡したときだけ。
# 手順の背景・カテゴリ投入順・落とし穴は docs/ops/段階curate運用.md を参照。
#
# 使い方:
#   EDR_SERVER=https://edr.example.com \
#   EDR_ADMIN_EMAIL=admin@example.com EDR_ADMIN_PASSWORD='...' \
#   ./scripts/curate-round.sh                 # status のみ(安全・何も変更しない)
#   ./scripts/curate-round.sh --run           # CATEGORIES を CAP 件だけ1ラウンド有効化
#   CATEGORIES=dns_query,file_event CAP=20 ./scripts/curate-round.sh --run
#   DATABASE_URL=postgres://... ./scripts/curate-round.sh --fp   # 直近24hのFP上位を表示(要 psql)
#
# 認証: EDR_TOKEN を直接渡すか、EDR_ADMIN_EMAIL/EDR_ADMIN_PASSWORD でログインして取得。
#
# 投入順(シグナル/ノイズ比。ブラスト半径の小さい順。docs/ops/段階curate運用.md):
#   1. dns_query,file_event  (件数少・具体的。実機1ラウンドで 0 FP 実績。★推奨の足慣らし)
#   2. registry_set,registry_delete,registry_event
#   3. ps_script             (難読化PS。正規の管理PSにも当たる → 要チューニング)
#   4. process_creation      (最多・FP振れ幅最大 → 最後に丁寧に)
#   ※ image_load は agent の署名検証(WinVerifyTrust)が入るまで対象外(false green源)。
set -euo pipefail

MODE="${1:-status}"

: "${EDR_SERVER:?EDR_SERVER を指定してください (例 https://edr.example.com)}"
CATEGORIES="${CATEGORIES:-dns_query,file_event}"
CAP="${CAP:-20}"
CURL_OPTS="${CURL_OPTS:-}"   # 検証環境の自己署名 TLS 用に -k を渡すなど

command -v curl >/dev/null || { echo "curl が必要です" >&2; exit 1; }

# --- FP 観測モード(DB 直読み。API とは別経路) -------------------------------
if [ "$MODE" = "--fp" ]; then
  : "${DATABASE_URL:?--fp には DATABASE_URL(postgres URL) が必要です}"
  command -v psql >/dev/null || { echo "psql が必要です" >&2; exit 1; }
  echo "[FP] 直近24hのアラート発火上位(ルール識別は title。ノイズ源特定用):"
  psql "$DATABASE_URL" -c \
    "SELECT left(title,46) AS title, count(*), max(created_at)::time AS last
     FROM alerts WHERE created_at > now() - interval '24 hours'
     GROUP BY left(title,46) ORDER BY 2 DESC LIMIT 20;"
  echo
  echo "→ ノイズ源は POST /api/v1/admin/detection/curate/quarantine {\"rule_ids\":[...],\"reason\":\"...\"}"
  echo "  または suppression ルールで抑制(docs/ops/段階curate運用.md ④)。"
  exit 0
fi

command -v jq >/dev/null || { echo "jq が必要です" >&2; exit 1; }

# --- トークン取得 -------------------------------------------------------------
if [ -z "${EDR_TOKEN:-}" ]; then
  : "${EDR_ADMIN_EMAIL:?EDR_TOKEN か EDR_ADMIN_EMAIL/EDR_ADMIN_PASSWORD が必要です}"
  : "${EDR_ADMIN_PASSWORD:?EDR_ADMIN_PASSWORD が必要です}"
  echo "[auth] admin ログインでトークンを取得..."
  EDR_TOKEN="$(curl -fsS $CURL_OPTS -X POST "$EDR_SERVER/api/v1/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$EDR_ADMIN_EMAIL\",\"password\":\"$EDR_ADMIN_PASSWORD\"}" | jq -r '.token')"
  [ -n "$EDR_TOKEN" ] && [ "$EDR_TOKEN" != "null" ] || { echo "ログイン失敗(token 取得できず)" >&2; exit 1; }
fi
AUTH=(-H "Authorization: Bearer $EDR_TOKEN")

# --- status(常に表示) --------------------------------------------------------
echo "[status] GET /api/v1/admin/detection/curate/status"
STATUS_JSON="$(curl -fsS $CURL_OPTS "${AUTH[@]}" "$EDR_SERVER/api/v1/admin/detection/curate/status")"
echo "$STATUS_JSON" | jq -r '
  "category                      total  support  enabled deferred  pending  quarant",
  "-----------------------------------------------------------------------------",
  (.categories[] | [
     (.category|.[0:28]|(. + "                            ")[0:28]),
     (.total|tostring|(("     " + .)[-5:])),
     (.supported|tostring|(("       " + .)[-7:])),
     (.enabled|tostring|(("       " + .)[-7:])),
     (.deferred|tostring|(("        " + .)[-8:])),
     (.pending|tostring|(("       " + .)[-7:])),
     (.quarantined|tostring|(("       " + .)[-7:]))
   ] | join(" ")),
  "-----------------------------------------------------------------------------",
  ("TOTAL                        " +
     (.total.total|tostring|(("     " + .)[-5:])) + " " +
     (.total.supported|tostring|(("       " + .)[-7:])) + " " +
     (.total.enabled|tostring|(("       " + .)[-7:])) + " " +
     (.total.deferred|tostring|(("        " + .)[-8:])) + " " +
     (.total.pending|tostring|(("       " + .)[-7:])) + " " +
     (.total.quarantined|tostring|(("       " + .)[-7:])))
'
echo
echo "凡例: support=field対応(有効化可) / deferred=対応済cap待ち / pending=field非対応(=inert,有効化禁止) / quarant=FP隔離済"

if [ "$MODE" != "--run" ]; then
  echo
  echo "READ-ONLY モードです。実際に1ラウンド有効化するには: $0 --run"
  echo "  対象カテゴリ=$CATEGORIES / cap=$CAP (CATEGORIES / CAP 環境変数で変更可)"
  exit 0
fi

# --- run(--run のときだけ実行) -----------------------------------------------
# CATEGORIES を JSON 配列へ
CATS_JSON="$(printf '%s' "$CATEGORIES" | jq -R 'split(",")|map(select(length>0))')"
echo
echo "[run] POST /api/v1/admin/detection/curate/run  categories=$CATEGORIES cap=$CAP"
echo "      (field-supported を cap 内で enabled=true → rules.invalidate 自動発行)"
RUN_JSON="$(curl -fsS $CURL_OPTS "${AUTH[@]}" -X POST "$EDR_SERVER/api/v1/admin/detection/curate/run" \
  -H 'content-type: application/json' \
  -d "{\"categories\":$CATS_JSON,\"cap\":$CAP}")"
echo "$RUN_JSON" | jq -r '"  結果: enabled=\(.enabled) deferred=\(.deferred) pending=\(.pending)"'
ENABLED_N="$(echo "$RUN_JSON" | jq -r '.enabled')"
echo "$RUN_JSON" | jq -r '.enabled_ids[]? | "    enabled: \(.)"' | head -50

cat <<EOF

次の手順(docs/ops/段階curate運用.md ③〜⑤):
  ③ 24〜72h 観測: ./scripts/curate-round.sh --fp   (DATABASE_URL 必要)
  ④ ノイズ源を quarantine or suppression で抑制
  ⑤ FP 許容内なら次バッチ(この --run を再実行 = 次の cap 分が deferred から昇格)
     または次カテゴリへ(CATEGORIES を投入順どおり進める)
  ※ CURATE_AUTO_ENABLE=true(既定)なら 6h ごとに自動前進 + FP 自動隔離も並行して働く。
     初回観察時は auto OFF 起動 → 本スクリプトで手動前進 → FP 0 確認 → auto ON が安全。
EOF
[ "$ENABLED_N" -gt 0 ] || echo "※ enabled=0: 対象カテゴリに未有効の field-supported ルールが無い(全て enabled/deferred/pending 済み)可能性。"

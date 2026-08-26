#!/usr/bin/env bash
# run-caldera-score.sh — Caldera オペレーションのレポートを取得し attack-scorer で採点する。
# 多段(kill-chain)エミュレーションを ATT&CK Evaluations 形式でスコア化する。
# 詳細手順: docs/ops/Caldera多段エミュレーション採点.md
#
# 使い方:
#   CAL_URL=http://caldera:8888 CAL_KEY=<api_key_red> \
#   EDR_SERVER=https://203-0-113-10.nip.io EDR_TOKEN=<JWT|edr_key> \
#   ./run-caldera-score.sh <operation_id> [window_sec]
#
# 出力: caldera-report-<op>.json と caldera-scorecard-<op>.csv
set -euo pipefail

OP="${1:?usage: run-caldera-score.sh <operation_id> [window_sec]}"
WINDOW="${2:-120}"
: "${CAL_URL:?CAL_URL を指定してください (例 http://caldera:8888)}"
: "${CAL_KEY:?CAL_KEY を指定してください (conf/local.yml の api_key_red)}"
: "${EDR_SERVER:?EDR_SERVER を指定してください}"
: "${EDR_TOKEN:?EDR_TOKEN を指定してください}"

REPORT="caldera-report-${OP}.json"
SCORECARD="caldera-scorecard-${OP}.csv"

echo "[1/2] Caldera レポート取得: ${CAL_URL}/api/v2/operations/${OP}/report"
curl -fsS -H "KEY:${CAL_KEY}" "${CAL_URL}/api/v2/operations/${OP}/report" -o "${REPORT}"

echo "[2/2] attack-scorer で採点 (-caldera, window=${WINDOW}s)"
# agent/ ディレクトリから実行する想定。-insecure は検証環境のみ。
go run ./cmd/attack-scorer \
  -caldera "${REPORT}" \
  -server "${EDR_SERVER}" -token "${EDR_TOKEN}" \
  -window "${WINDOW}" -insecure \
  -out "${SCORECARD}"

echo "完了: ${REPORT} / ${SCORECARD}"

#!/usr/bin/env bash
# run-atomics.sh — Linux 被験 VM で簡易テクニックを実行し runlog CSV を出力する。
#
# pwsh + Invoke-AtomicRedTeam が使える環境なら run-atomics.ps1 を推奨
# (より網羅的)。本スクリプトは pwsh を入れられない環境向けの最小版で、
# テクニックID と実行コマンドの対応表(下記 TECHNIQUES)を直接実行し、
# 開始/終了時刻を RFC3339(UTC) で記録する。
#
#   使い方: ./run-atomics.sh [out.csv] [scenario]
#   採点  : attack-scorer -server <URL> -token <TOKEN> -runlog out.csv
#
# 第2引数 scenario を渡すと全テクニックを1つの多段攻撃チェーンとしてタグ付けし、
# attack-scorer がチェーン採点(段ごと + 連鎖断ち切り率, MITRE Evals 形式)を行う。
#
# ⚠ 隔離された検証用 VM でのみ実行すること。docs/ATT&CK検知率測定計画.md 参照。
set -u

OUT="${1:-runlog.csv}"
SCENARIO="${2:-}"
SETTLE="${SETTLE_SECONDS:-8}"

# "Txxxx|テスト名|実行コマンド" の行を追加すれば測定対象を拡張できる。
# ここでは Linux で安全に再現できるディスカバリ/実行系のサンプルを置く。
TECHNIQUES=(
  "T1059.004|bash one-liner|bash -c 'echo benign-test-$$ >/dev/null'"
  "T1033|whoami|whoami"
  "T1057|process discovery|ps aux"
  "T1082|system info|uname -a"
  "T1016|network config|ip addr"
  "T1018|remote discovery|cat /etc/hosts"
  "T1518.001|software discovery|which gcc python3 2>/dev/null || true"
)

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

printf 'technique,test_name,start_utc,end_utc,exit_code,scenario\n' >"$OUT"

for entry in "${TECHNIQUES[@]}"; do
  IFS='|' read -r tech name cmd <<<"$entry"
  echo "=== $tech ($name) ==="
  start="$(now_utc)"
  bash -c "$cmd" >/dev/null 2>&1
  rc=$?
  sleep "$SETTLE"
  end="$(now_utc)"
  printf '%s,%s,%s,%s,%s,%s\n' "$tech" "$name" "$start" "$end" "$rc" "$SCENARIO" >>"$OUT"
done

echo "runlog 出力: $OUT"
echo "採点: attack-scorer -server <URL> -token <TOKEN> -runlog $OUT"

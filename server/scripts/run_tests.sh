#!/bin/bash
# Run the server test suite, and say what did not run.
#
# Usage:
#   ./scripts/run_tests.sh                  — DB を自動で用意して全部走らせる
#   NO_LOCAL_DB=1 ./scripts/run_tests.sh    — DB を用意しない（飛んだ数は出ます）
#   ALLOW_SKIPS=1 ./scripts/run_tests.sh    — 飛んでも落とさない（数は出ます）
#   NO_ALERTMANAGER=1 ./scripts/run_tests.sh — Alertmanager の確認をしない
#                                             （**しなかったことは出ます**）
#   TEST_DB_URL=... ./scripts/run_tests.sh  — integration タグ付きも走らせる
#
# **以前の最後の行は「All tests passed!」でした。** `TEST_DATABASE_URL` を
# 設定せずに回すと 900 本が飛び、それでもこの行が出ていました。
# このキャンペーンで見つけた欠陥は、ほぼ全部その 900 本の側にありました ——
# 保管時暗号化が一度も動いていなかったこと、アラート一覧が1件の行で
# 0件になること、テナントを名乗らないリクエストが他テナントの端末を
# 隔離できたこと。**どれも DB を当てて初めて出ました。**
#
# 走らなかった検査と通った検査は、同じ行を出します。ここで分けます。
set -e

cd "$(dirname "$0")/.."
REPO=$(cd .. && pwd)

# 上限。DB と NATS を用意した状態で、正当に飛ぶ本数です。
#   4  GeoIP — 外部ネットワーク (ip-api.com) が要ります
#   1  取り込み — NATS_URL が要ります
# **増えても減っても落ちます。** 下げないと、次に増えた分が差に隠れます。
MAX_SKIPS=${MAX_SKIPS:-5}

echo "=== Running ML Unit Tests ==="
go test ./internal/ml/... -v -count=1 -timeout 60s

echo ""
echo "=== Running Benchmarks (ML) ==="
go test ./internal/ml/... -bench=. -benchmem -count=1 -run='^$' -timeout 120s

echo ""
echo "=== Running Handler Benchmarks ==="
go test ./internal/api/handlers/... -bench=BenchmarkHealthHandler -benchmem -count=1 -run='^$' -timeout 60s

echo ""
echo "=== Running Race Detector (ML) ==="
# Race detector requires CGO. Skip gracefully if not available.
if CGO_ENABLED=1 go env CGO_ENABLED >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
  CGO_ENABLED=1 go test -race ./internal/ml/... -count=1 -timeout 120s
else
  echo "(Race detector skipped: CGO/gcc not available — run on Linux/macOS CI)"
fi

# ── DB を用意する ────────────────────────────────────────────────────────────
# 無ければ 900 本が飛びます。用意できないこと自体は失敗ではありませんが、
# **黙って続けるのが失敗です。**
if [ -z "${TEST_DATABASE_URL:-}" ] && [ -z "${NO_LOCAL_DB:-}" ]; then
  echo ""
  echo "=== TEST_DATABASE_URL が未設定です。PostgreSQL を用意します ==="
  # local-db.sh は export 行を stdout に、経過を stderr に出します。
  if [ -x "$REPO/scripts/local-db.sh" ] && db_env=$("$REPO/scripts/local-db.sh" up); then
    eval "$db_env"
    echo "    $TEST_DATABASE_URL"
  else
    echo "    用意できませんでした。DB が要る検査は飛びます"
  fi
fi

echo ""
echo "=== Running the whole suite ==="
# -p 1 で直列に走らせます。パッケージを並列にすると、同じ DB を共有する
# 検査どうしが互いの行を消し、**本物の欠陥と見分けが付かない失敗**が出ます。
set +e
go test -count=1 -p 1 -json -timeout 600s ./... > /tmp/gotest.$$.json
GO_STATUS=$?
set -e

# 失敗そのものは go test の出力で見せます（-json は読みにくいので整形）。
if [ $GO_STATUS -ne 0 ]; then
  echo ""
  echo "--- 失敗したテスト ---"
  python3 - "/tmp/gotest.$$.json" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    if ev.get('Action') == 'fail' and ev.get('Test'):
        print(f"  {ev.get('Package','')}.{ev['Test']}")
PY
fi

SKIP_ARGS=(--max-skips "$MAX_SKIPS")
[ -n "${ALLOW_SKIPS:-}" ] && SKIP_ARGS=()

set +e
python3 "$REPO/scripts/skip_report.py" "${SKIP_ARGS[@]}" < "/tmp/gotest.$$.json"
SKIP_STATUS=$?
set -e
rm -f "/tmp/gotest.$$.json"

# ── Alertmanager ────────────────────────────────────────────────────────────
# **Go の検査だけでは足りません。** `deploy/alertmanager.yml` は Go から
# 読まれないので、`go test ./...` は1行も触りません。フィールド名が
# v0.27 のスキーマに合っているかは**起動して初めて分かります。**
#
# 確かめるのは3つ: 設定が読めること / 通知が receiver まで届くこと /
# inhibit_rules が実際に抑制すること。docker は要らず、秘密はダミーで、
# 宛先はローカルの受け口に差し替わるので**外に出る通信は起きません**
# （Alertmanager のバイナリの取得だけはネットワークが要ります）。
#
# 10秒ほどかかります。**遅い検査は走らせなくなる**ので、届くのを待つ側の
# group_wait だけ 1s に差し替えてあります（出荷値が 30s のままであることは
# スクリプトが確かめます）。
AM_STATUS=0
if [ -n "${NO_ALERTMANAGER:-}" ]; then
  AM_STATUS=2
  echo ""
  echo "(Alertmanager の確認はしていません: NO_ALERTMANAGER=1)"
elif [ ! -x "$REPO/scripts/check-alertmanager.sh" ]; then
  AM_STATUS=2
  echo ""
  echo "(Alertmanager の確認はしていません: scripts/check-alertmanager.sh がありません)"
else
  echo ""
  echo "=== Alertmanager: 設定が読めて、通知が届くこと ==="
  set +e
  "$REPO/scripts/check-alertmanager.sh"
  AM_STATUS=$?
  set -e
fi

if [ -n "$TEST_DB_URL" ]; then
  echo ""
  echo "=== Running API Integration Tests (TEST_DB_URL is set) ==="
  go test -tags=integration ./internal/api/... -v -count=1 -timeout 120s
else
  echo ""
  echo "(Skipping API integration tests: TEST_DB_URL not set)"
fi

echo ""
if [ $GO_STATUS -ne 0 ]; then
  echo "落ちたテストがあります。"
  exit $GO_STATUS
fi
if [ $AM_STATUS -eq 1 ]; then
  echo "Alertmanager の確認で問題が見つかりました（上を見てください）。"
  exit 1
fi
if [ $SKIP_STATUS -ne 0 ]; then
  # **「全部通った」とは言いません。** 走っていない分があります。
  echo "落ちたテストはありませんが、走らなかった分があります（上を見てください）。"
  exit $SKIP_STATUS
fi
if [ $AM_STATUS -ne 0 ]; then
  # **確かめられなかったことを、通ったことと同じ行にしません。**
  # 終了コード 2 は「Alertmanager を取ってこられない」など、検査そのものが
  # 走らなかった場合です。
  echo "Go の検査は全部走って通りました。**Alertmanager の確認は走っていません。**"
  exit 3
fi
echo "全部走って、全部通りました（Alertmanager の確認を含む）。"

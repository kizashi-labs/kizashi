#!/usr/bin/env bash
# Run the two linters CI runs (staticcheck, golangci-lint) against the local tree.
#
# ── なぜスクリプトが要るのか ──────────────────────────────────────────────
# 素直に `go install honnef.co/go/tools/cmd/staticcheck@v0.7.0` すると動かない。
# 入るバイナリは go1.25 でビルドされ、このモジュールは go1.26 を要求するため、
# 解析対象を1パッケージも読めずに全滅する:
#
#   package requires newer Go version go1.26 (application built with go1.25)
#
# 原因はリンタ側の go.mod にある `toolchain go1.25.0` で、これが go のツール
# チェーン選択を 1.25 に固定してしまう。GOTOOLCHAIN=local も効かない（この箱の
# システム go は 1.24.7 で、要求 1.25 を満たさずビルド自体が止まる）。
#
# 効くのは **GOTOOLCHAIN で 1.26.5 を名指しする** こと。バージョンを直接指定した
# 場合はモジュールの toolchain 行より優先されるので、リンタ本体が go1.26 で
# ビルドされ、go1.26 のコードを解析できるようになる。
#
# この件は「ローカルでは動かないリンタ」として台帳(P1-2)に残っていたが、誤りだった。
# 動かす方法があり、それがこのスクリプトである。CI が使えない期間はここが唯一の
# 検証手段になるので、再発見に時間を使わずに済むよう手順ごと残す。
#
# ── 使い方 ────────────────────────────────────────────────────────────────
#   server/scripts/lint-local.sh              # 差分のみ（CI と同じ範囲）
#   server/scripts/lint-local.sh --full       # 全体スキャン（既存バックログも出る）
#
# バージョンは ci.yml と揃える。ここだけ上げると「ローカルは緑、CI は赤」になる。
set -euo pipefail

STATICCHECK_VERSION="v0.7.0"   # ci.yml の staticcheck ステップと一致させること
GOLANGCI_VERSION="v2.12.2"     # ci.yml の golangci-lint-action の version と一致させること
GOTOOLCHAIN_PIN="go1.26.5"     # server/go.mod が要求する go に合わせる

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${EDR_LINT_CACHE:-$HOME/.cache/edr-lint}"
mkdir -p "$CACHE"

FULL=0
[ "${1:-}" = "--full" ] && FULL=1

# build_tool <出力名> <モジュールパス> <バージョン>
#
# 一時モジュールを作ってからビルドする。`go install pkg@version` を使わないのは、
# それだとバージョン付きモードになり GOTOOLCHAIN の指定より go.mod の toolchain 行が
# 勝つため。get してから build すれば、こちらの指定が通る。
build_tool() {
  local out="$CACHE/$1" pkg="$2" ver="$3"
  if [ -x "$out" ]; then
    echo "  → $1 はビルド済み ($out)"
    return
  fi
  echo "  → $1 $ver をビルドします (初回のみ、数分かかります)"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  (
    cd "$tmp"
    go mod init edrlint >/dev/null
    GOTOOLCHAIN="$GOTOOLCHAIN_PIN" go get "${pkg}@${ver}" >/dev/null 2>&1
    GOTOOLCHAIN="$GOTOOLCHAIN_PIN" go build -o "$out" "$pkg"
  )
}

echo "== リンタを用意します =="
build_tool staticcheck honnef.co/go/tools/cmd/staticcheck "$STATICCHECK_VERSION"
build_tool golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint "$GOLANGCI_VERSION"

rc=0

echo
echo "== staticcheck (server) =="
(cd "$REPO_ROOT/server" && "$CACHE/staticcheck" ./...) || rc=1

echo
echo "== staticcheck (agent) =="
(cd "$REPO_ROOT/agent" && "$CACHE/staticcheck" ./...) || rc=1

echo
if [ "$FULL" = "1" ]; then
  echo "== golangci-lint (server, 全体) =="
  (cd "$REPO_ROOT/server" && "$CACHE/golangci-lint" run ./...) || rc=1
else
  # CI と同じ範囲。origin/main が無いと全体スキャンに化けて既存バックログで
  # 落ちるので、比較対象の不在は黙って通さず明示的に止める。
  if ! git -C "$REPO_ROOT" rev-parse --verify origin/main >/dev/null 2>&1; then
    echo "!! origin/main が見つかりません。先に git fetch origin main を実行してください" >&2
    echo "   (--full なら全体スキャンで実行できますが、CI と範囲が変わります)" >&2
    exit 2
  fi
  echo "== golangci-lint (server, origin/main との差分。CI と同じ範囲) =="
  (cd "$REPO_ROOT/server" && "$CACHE/golangci-lint" run --new-from-merge-base=origin/main ./...) || rc=1
fi

echo
if [ "$rc" = "0" ]; then
  echo "✅ 指摘なし"
else
  echo "❌ 指摘あり (上記)"
fi
exit "$rc"

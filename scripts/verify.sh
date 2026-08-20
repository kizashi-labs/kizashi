#!/usr/bin/env bash
#
# CI のゲートをローカルで再現する。
#
# 使い方:
#   scripts/verify.sh                  変更のあった領域だけを fast で検証
#   scripts/verify.sh --full           ビルドと脆弱性検査まで含める
#   scripts/verify.sh --all            変更に関係なく全領域
#   scripts/verify.sh server frontend  領域を明示
#                                      （agent / server / frontend / sdk / rules / security）
#   scripts/verify.sh --list           何を実行して何を飛ばすかだけ表示する
#
# ── なぜこれが要るか ────────────────────────────────────────────
# CI が唯一の品質ゲートで、手元に同じものを流す手段が無かった。Actions が
# 止まると検証手段そのものが消える。ここが埋まっていれば、CI の可否と
# 関係なく push 前に同じ結論を得られる。
#
# ── 追従の義務 ──────────────────────────────────────────────────
# ここは .github/workflows/ の ci.yml・merge-gate.yml・security.yml・
# workflow-lint.yml・sync-guard.yml を 1:1 で写したもの。**あちらのジョブやステップを
# 足し引きしたら、ここも合わせて直すこと。** 片方だけ変わると「ローカルで
# 緑なのに CI で落ちる」、あるいは
# もっと悪い「ローカルで緑だが、CI にしか無い検査を通していない」状態に
# なる。ci.yml 側の changes ジョブにも同じ注意書きを置いてある。
#
# （coverage.yml は ci.yml の server-test に畳んで廃止した。カバレッジの
# 計測と下限判定は server の項に入っている。）
#
# なお scripts/ は ci.yml の「全ジョブを走らせる」条件に入れていない。
# CI はこのディレクトリのものを実行しないので、触るたびに全部回すのは
# 消費の無駄になるため。追従はこのコメントと相互参照で担保する。
#
# ── 設計上の約束 ────────────────────────────────────────────────
# 前提が足りない検査は **黙って飛ばさない**。必ず SKIP として理由つきで
# 出し、最後のまとめにも残す。ci.yml の changes ジョブが
#
#   「走って通った」と「そもそも走っていない」の区別が付かないため、
#     赤が無期限に隠れる（実際に 8 日間隠れた）
#
# と書いているのと同じ理由で、ここでも「実行しなかった」を成功に見せない。
# 終了コードは FAIL があれば 1、無ければ 0。SKIP だけなら 0 で終わるが、
# まとめの末尾に必ず件数を出す。
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# CI と版を揃える。@latest は「コードが変わっていないのに落ちる」経路で、
# このリポジトリでは実際に踏んでいる（ci.yml の staticcheck の項を参照）。
STATICCHECK_VERSION="v0.7.0"
GOVULNCHECK_VERSION="v1.6.0"
GOLANGCI_VERSION="v2.12.2"
SERVER_COVERAGE_MIN=35
AGENT_COVERAGE_MIN=30

MODE="fast"
FORCE_ALL=false
LIST_ONLY=false
AREAS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --full)  MODE="full" ;;
    --fast)  MODE="fast" ;;
    --all)   FORCE_ALL=true ;;
    --list)  LIST_ONLY=true ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    agent|server|frontend|sdk|rules|security) AREAS+=("$1") ;;
    *) echo "不明な引数: $1（--help を参照）" >&2; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_BLD=""; C_OFF=""
fi

RESULTS=()
N_PASS=0; N_FAIL=0; N_SKIP=0

record() { RESULTS+=("$1|$2|${3:-}"); }

pass() { N_PASS=$((N_PASS+1)); record PASS "$1"; printf '  %sPASS%s  %s\n' "$C_GRN" "$C_OFF" "$1"; }
fail() { N_FAIL=$((N_FAIL+1)); record FAIL "$1"; printf '  %sFAIL%s  %s\n' "$C_RED" "$C_OFF" "$1"; }
skip() { N_SKIP=$((N_SKIP+1)); record SKIP "$1" "$2"; printf '  %sSKIP%s  %s %s(%s)%s\n' "$C_YEL" "$C_OFF" "$1" "$C_DIM" "$2" "$C_OFF"; }

# run <ラベル> <作業ディレクトリ> <コマンド...>
# 失敗したら出力の末尾だけを見せる。全部出すと本当の失敗が埋もれる。
run() {
  local label="$1" dir="$2"; shift 2
  if $LIST_ONLY; then printf '  %sRUN %s  %s\n' "$C_DIM" "$C_OFF" "$label"; return 0; fi
  local log; log="$(mktemp)"
  if (cd "$dir" && "$@") >"$log" 2>&1; then
    pass "$label"
  else
    fail "$label"
    printf '%s' "$C_DIM"; tail -n 25 "$log" | sed 's/^/        /'; printf '%s' "$C_OFF"
  fi
  rm -f "$log"
}

# run_show <ラベル> <作業ディレクトリ> <コマンド...>
# run と同じだが、成功時にも出力の末尾を見せる。
#
# 「報告のみでゲートではない」検査（Trivy / Semgrep）用。CI 側もこれらを
# exit-code で落としていないので、ここで落とすと CI より厳しくなり
# 1:1 の写しでなくなる。とはいえ結果を隠したら走らせる意味が無いので、
# 通っても中身を出す。
run_show() {
  local label="$1" dir="$2"; shift 2
  if $LIST_ONLY; then printf '  %sRUN %s  %s\n' "$C_DIM" "$C_OFF" "$label"; return 0; fi
  local log; log="$(mktemp)"
  if (cd "$dir" && "$@") >"$log" 2>&1; then
    pass "$label"
    printf '%s' "$C_DIM"; tail -n 30 "$log" | sed 's/^/        /'; printf '%s' "$C_OFF"
  else
    fail "$label"
    printf '%s' "$C_DIM"; tail -n 30 "$log" | sed 's/^/        /'; printf '%s' "$C_OFF"
  fi
  rm -f "$log"
}

have() { command -v "$1" >/dev/null 2>&1; }

# モジュールの go ディレクティブを返す。
#
# staticcheck や govulncheck を `go run …@version` で入れると、既定の
# GOTOOLCHAIN 解決ではツール側の要求（staticcheck v0.7.0 なら go>=1.25）に
# 合わせて **古い方** のツールチェーンが選ばれる。その状態で go1.26 の
# コードを解析すると全パッケージが
#   "package requires newer Go version go1.26 (application built with go1.25)"
# で落ちる。CI は actions/setup-go が go-version-file でツールチェーンを
# 固定してから go install するので、この経路を踏まない。
# ここでも go.mod の版に明示的に合わせる。
gotoolchain_of() { awk '/^go /{print "go"$2; exit}' "$1/go.mod"; }

# go 系コマンドをモジュールのツールチェーンで実行する
gorun() {
  local label="$1" dir="$2"; shift 2
  run "$label" "$dir" env "GOTOOLCHAIN=$(gotoolchain_of "$dir")" "$@"
}

section() { printf '\n%s── %s %s\n' "$C_BLD" "$1" "$C_OFF"; }

# ── 対象領域の判定 ───────────────────────────────────────────────
# ci.yml の changes ジョブと同じ考え方。判定できないときは全部走らせる側に
# 倒す（取りこぼして緑になるより、余分に回すほうがまし）。
detect_areas() {
  local files base
  base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
  if [ -z "$base" ]; then echo "agent server frontend sdk rules security"; return; fi
  files="$(git diff --name-only "$base"...HEAD 2>/dev/null; git status --porcelain | awk '{print $2}')"
  if [ -z "$files" ]; then echo ""; return; fi
  # CI 定義・proto・共通設定が動いたら全部
  if grep -qE '^\.github/workflows/|^proto/|^docker-compose|^Makefile|^scripts/verify\.sh' <<<"$files"; then
    echo "agent server frontend sdk rules security"; return
  fi
  local out=""
  grep -qE '^agent/'                    <<<"$files" && out="$out agent"
  grep -qE '^server/'                   <<<"$files" && out="$out server"
  grep -qE '^frontend/'                 <<<"$files" && out="$out frontend"
  grep -qE '^sdk/'                      <<<"$files" && out="$out sdk"
  grep -qE '^rules/|^server/migrations/' <<<"$files" && out="$out rules"
  # security.yml の paths-ignore（docs/**, **/*.md, LICENSE, .gitignore）を
  # 裏返したもの。それ以外が 1 つでも動けば security.yml は回る。
  grep -vqE '^docs/|\.md$|^LICENSE$|^\.gitignore$' <<<"$files" && out="$out security"
  echo "$out"
}

if [ ${#AREAS[@]} -eq 0 ]; then
  if $FORCE_ALL; then
    AREAS=(agent server frontend sdk rules security)
  else
    read -r -a AREAS <<<"$(detect_areas)"
    if [ ${#AREAS[@]} -eq 0 ]; then
      echo "origin/main との差分がありません。全領域を検証するなら --all を付けてください。"
      exit 0
    fi
  fi
fi

wants() { [[ " ${AREAS[*]} " == *" $1 "* ]]; }

printf '%sCI ローカル再現%s  mode=%s  areas=%s\n' "$C_BLD" "$C_OFF" "$MODE" "${AREAS[*]}"
printf '%s%s%s\n' "$C_DIM" "$(git log --oneline -1)" "$C_OFF"

# ── workflows ────────────────────────────────────────────────────
# workflow-lint.yml の写し。**領域に関係なく毎回走らせます** ——
# ここが落ちるとジョブが1つも作られず、PR のチェック一覧では「失敗した CI」
# ではなく「CI が無い」状態で並びます。**他が緑のままなので、通っているように
# 読めます。** 速い検査なので毎回でよいものです。
section "workflows"
if ! have python3; then
  skip "workflow-lint" "python3 が PATH にありません"
elif ! python3 -c 'import yaml' 2>/dev/null; then
  skip "workflow-lint" "PyYAML がありません（pip install pyyaml）"
else
  run "workflow-lint" . python3 - <<'WFLINT'
import glob, re, sys, yaml

PIPE_GREP_Q = re.compile(r"\|\s*grep\b[^|&;]*\s-[A-Za-z]*q")
problems = []
job_timeouts = step_timeouts = 0
for path in sorted(glob.glob(".github/workflows/*.yml") +
                   glob.glob(".github/workflows/*.yaml")):
    try:
        doc = yaml.safe_load(open(path, encoding="utf-8"))
    except Exception as e:
        problems.append("%s: YAML として読めません: %s" % (path, e)); continue
    if not isinstance(doc, dict):
        problems.append("%s: トップレベルがマップではありません" % path); continue
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append("%s: jobs がありません" % path); continue
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            problems.append("%s / %s: ジョブがマップではありません" % (path, job_name)); continue
        if "uses" in job:
            continue
        # timeout-minutes が無いジョブは既定の 6 時間まで走ります。実測で
        # 2 回起きています（360.3 分 / 111.2 分、どちらも apt の停止）。
        if "timeout-minutes" not in job:
            problems.append("%s / %s: timeout-minutes がありません（既定は 6 時間）"
                            % (path, job_name))
        else:
            job_timeouts += 1
            if isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] > 60:
                problems.append("%s / %s: timeout-minutes が %d 分です。**ハングを上限の引き上げで直さないでください**"
                                % (path, job_name, job["timeout-minutes"]))
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            problems.append("%s / %s: steps がありません" % (path, job_name)); continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                problems.append("%s / %s / step[%d]: ステップがマップではありません"
                                % (path, job_name, i)); continue
            if "timeout-minutes" in step:
                step_timeouts += 1
            if "run" not in step and "uses" not in step:
                problems.append("%s / %s / step[%d] (%s): run: も uses: もありません"
                                % (path, job_name, i, step.get("name", "名前なし")))
            script = step.get("run")
            if isinstance(script, str) and "pipefail" in script:
                for line in script.splitlines():
                    if line.lstrip().startswith("#"):
                        continue
                    if PIPE_GREP_Q.search(line):
                        problems.append(
                            "%s / %s / step[%d] (%s): pipefail のもとで `grep -q` を"
                            "パイプの右辺に置いています → %s"
                            % (path, job_name, i, step.get("name", "名前なし"),
                               line.strip()))
# 本流へ渡す一覧の数が実物と合っていること。**この数は一度腐りました** ——
# 引き継ぎに「47 件」と書いたあと sync-guard.yml が 2 件足し、メモだけが
# 残りました。渡された側は古い数を写して、その差だけ黙って落とします。
HANDOVER = "docs/ci/本流へ渡す作業一覧.md"
try:
    handover = open(HANDOVER, encoding="utf-8").read()
except FileNotFoundError:
    problems.append("%s がありません。**本流へ何を渡すかが、リポジトリの"
                    "どこにも残っていない状態です**" % HANDOVER)
else:
    want = re.search(r"job (\d+) \+ step (\d+) ＝ (\d+) 件", handover)
    if not want:
        problems.append("%s に「job N + step N ＝ N 件」の行がありません。"
                        "書き方を変えたなら、この検査も一緒に直してください" % HANDOVER)
    else:
        said = tuple(int(g) for g in want.groups())
        got = (job_timeouts, step_timeouts, job_timeouts + step_timeouts)
        if said != got:
            problems.append("%s は job %d + step %d ＝ %d 件と書いていますが、"
                            "実物は job %d + step %d ＝ %d 件です。"
                            "**文書のほうを実物に合わせてください**"
                            % ((HANDOVER,) + said + got))

if problems:
    for p in problems:
        print("  - " + p)
    sys.exit(1)
print("ワークフローファイルはすべて読み込み可能です")
WFLINT
fi

# ── 同期の取りこぼし ─────────────────────────────────────────────
# **消えても CI が緑のままになるもの**を名前で留めます。#67 で入れた
# timeout-minutes 47 件は #70 の同期が全部消し、**同時に欠落を落とす検査
# そのものも消した**ので、PR は 22/22 緑で通りました（#73 で戻した）。
#
# CI では `.github/workflows/sync-guard.yml` が `pull_request_target` で
# 走ります —— **base 側の定義で走るので、PR がこれを消しても止まりません。**
# ここは同じ判定を作業木に当てるだけの写しです。
if ! have python3; then
  skip "sync-guard" "python3 が PATH にありません"
elif ! python3 -c 'import yaml' 2>/dev/null; then
  skip "sync-guard" "PyYAML がありません（pip install pyyaml）"
else
  run "sync-guard" . python3 scripts/sync_guard.py .
  run "sync-guard 自身" . python3 scripts/sync_guard_test.py
fi

# ── ラチェット再較正の道具 ───────────────────────────────────────
# scripts/recalibrate_ratchets.py は固定値を書き換えます。**壊れたまま
# 動くと、劣化を記録して緑にするだけの装置になります。** 道具の判定を
# 単体で留めます（Go も DB も要りません）。
if have python3; then
  run "ratchet-recalibrator" . python3 scripts/recalibrate_ratchets_test.py
else
  skip "ratchet-recalibrator" "python3 が PATH にありません"
fi

# ── server ───────────────────────────────────────────────────────
if wants server; then
  section "server (Go)"
  if ! have go; then
    skip "server 一式" "go が PATH にありません"
  else
    run   "gofmt"        server bash -c 'test -z "$(gofmt -l .)" || { gofmt -l .; gofmt -d .; false; }'
    gorun "go vet"       server go vet ./...
    gorun "OpenAPI 同期" server go run ./cmd/openapi-sync -check
    gorun "staticcheck"  server go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" ./...

    # golangci-lint。errcheck/gosec/bodyclose 等を .golangci.yml で足してある
    # 実際のゲートで、CI では --new-from-merge-base=origin/main で「新規・変更
    # コードだけ」を見ている。既存バックログが大きいので、全体スキャンにすると
    # 通らない。ここも同じ引数にする。
    #
    # ここで `go install` に落とさないこと。ci.yml が公式アクション（ビルド済み
    # バイナリ）を使っているのは、リンタ側の依存解決が 403 になってコード変更
    # ゼロで CI が落ちた事故（2026-08-03, unqueryvet v1.5.4）を構造的に消すため。
    # 同じ穴をローカルに掘り直す意味はない。入っていなければ SKIP。
    if ! have golangci-lint; then
      skip "golangci-lint (--new-from-merge-base)" \
        "golangci-lint がありません（CI は $GOLANGCI_VERSION。リリースバイナリを入れてください）"
    elif ! git rev-parse --verify -q origin/main >/dev/null; then
      skip "golangci-lint (--new-from-merge-base)" "origin/main がありません（git fetch origin main）"
    else
      # 版の確認。golangci-lint は「自分をビルドした Go」より新しい **言語版** を
      # 対象にした module を解析できず、`can't load config` で落ちる。
      # staticcheck の項と同じ故障クラス（ツールが古いだけで、コードは無傷）。
      # これを FAIL として出すと、直せない赤が毎回並ぶ。原因を名指しして
      # SKIP にする — 実行していないことは、まとめに必ず残る。
      #
      # **比べるのは major.minor までにすること。** 初版はパッチまで比べており、
      # CI と同じ v2.12.2（go1.26.2 ビルド）を入れても go1.26.6 対象の module に
      # 対して SKIP になった。実際にはその組み合わせは動く（0 issues を出した）。
      # そして誤 SKIP は、このスクリプトが最も避けたい形そのものだった ——
      # **本物の指摘を 1 件（抑制ヒット数の errcheck）隠したまま「ローカル緑」を
      # 出し、CI で初めて落ちた。**
      gcl_line="$(golangci-lint version 2>&1)"
      gcl_v="$(grep -oE 'version [0-9]+\.[0-9]+\.[0-9]+' <<<"$gcl_line" | awk '{print $2}')"
      gcl_go="$(grep -oE 'built with go[0-9.]+' <<<"$gcl_line" | sed 's/built with go//')"
      mod_go="$(awk '/^go /{print $2; exit}' server/go.mod)"
      # go1.26.2 → go1.26
      gcl_lang="$(cut -d. -f1,2 <<<"${gcl_go:-0}")"
      mod_lang="$(cut -d. -f1,2 <<<"$mod_go")"
      oldest="$(printf '%s\n%s\n' "$gcl_lang" "$mod_lang" | sort -V | head -1)"

      if [ "$gcl_lang" = "$oldest" ] && [ "$gcl_lang" != "$mod_lang" ]; then
        skip "golangci-lint (--new-from-merge-base)" \
          "手元の golangci-lint は go${gcl_go} ビルドで、server は go${mod_go} 対象（解析できません）。CI と同じ $GOLANGCI_VERSION を入れてください"
      else
        [ "v$gcl_v" = "$GOLANGCI_VERSION" ] || \
          printf '  %s※ golangci-lint %s（CI は %s）。版差で結果がずれることがあります。%s\n' \
            "$C_YEL" "${gcl_v:-不明}" "$GOLANGCI_VERSION" "$C_OFF"
        run "golangci-lint (--new-from-merge-base)" server \
          golangci-lint run --new-from-merge-base=origin/main ./...
      fi
    fi

    # CI は postgres と nats をサービスコンテナで用意する。無い場合、依存する
    # テストは落ちる。落ちた理由が「DB が無いから」なのか実際の退行なのかを
    # 取り違えないよう、事前に到達性を見て切り分ける。
    if [ -n "${DATABASE_URL:-}" ] && have psql && psql "$DATABASE_URL" -c 'select 1' >/dev/null 2>&1; then
      # CI は毎回まっさらな postgres に migrations/*.sql を全部流してから
      # テストする。手元の DB が古いスキーマのままだと、CI で通るテストが
      # ここでだけ落ちる（あるいはその逆）。同じ手順で追いつかせる。
      # 適用済みのものは重複エラーになるので、CI と同じく無視する。
      run "migrations の適用" server bash -c '
        for f in migrations/*.sql; do psql "$DATABASE_URL" -f "$f" >/dev/null 2>&1 || true; done
        echo "$(ls migrations/*.sql | wc -l) 本を流しました（既適用分のエラーは無視）。"'

      # TEST_DATABASE_URL は「DB を張るハンドラ統合テスト」を起こすスイッチ。
      # 設定しないと該当テストは t.Skip() で静かに消える。CI は DATABASE_URL と
      # 同じ移行済み DB を指しているので、ここでも揃える。**これを外すと
      # 「ローカルで緑だが CI にしかない検査を通していない」状態そのものになる。**
      TEST_DB_URL="${TEST_DATABASE_URL:-$DATABASE_URL}"

      # NATS も同じ。NATS_URL が無いと ingestion / scheduler の coverage テストが
      # 自分から Skip する。到達できないなら、その事実を SKIP として残す。
      NATS_ENV=()
      nats_hostport="${NATS_URL:-}"; nats_hostport="${nats_hostport#nats://}"
      if [ -n "${NATS_URL:-}" ] \
         && (exec 3<>"/dev/tcp/${nats_hostport%%:*}/${nats_hostport##*:}") 2>/dev/null; then
        NATS_ENV=("NATS_URL=$NATS_URL")
      else
        skip "NATS 依存のテスト（ingestion / scheduler）" \
          "NATS_URL 未設定 / 到達できません（テスト側が自分で Skip します）"
      fi

      gorun "go test (race, coverage)" server \
        env "TEST_DATABASE_URL=$TEST_DB_URL" ${NATS_ENV[@]+"${NATS_ENV[@]}"} \
        go test -race -timeout 120s -coverprofile=coverage.out -covermode=atomic ./...

      # ci.yml の「Synthetic injection E2E」。integration タグで上のユニット実行
      # から外してある別ステップで、作った event を本物の AlertPipeline に流して
      # Postgres に alert 行が落ちることを見る。ルールが不活性になった／INSERT が
      # 失敗した、という純ロジックのテストでは見えない壊れ方を捕まえる担当。
      gorun "Synthetic injection E2E (integration)" server \
        env ${NATS_ENV[@]+"${NATS_ENV[@]}"} \
        go test -tags integration -race -timeout 120s ./internal/detection/...

      # ci.yml の「RLS fail-closed rehearsal」。4 表の RLS には
      # 「app.tenant_id が未設定なら全行」の抜け道がまだ残っている。落とすと、
      # テナントも名乗りも持たない接続は 0 行になる。**壊れる向きが
      # 「静かに 0 行」**なので、落とす前に測る。
      #
      # 方針を厳格版に差し替えて 2 テナントで実測し、必ず戻す。**DB を
      # 専有する**ので上の `go test ./...`（package を並列に走らせる）とは
      # 混ぜられない —— 混ぜると他 package が巻き添えで落ちて不安定になり、
      # 不安定な検査は無視され、無視される検査は消える。別に走らせる。
      gorun "RLS fail-closed rehearsal（DB を専有）" server \
        env "TEST_DATABASE_URL=$TEST_DB_URL" "RLS_FAILCLOSED=1" \
        go test -timeout 180s ./internal/store/ -run 'FailClosed|StrictSwap|AppRoleExists'

      gorun "カバレッジ下限 ${SERVER_COVERAGE_MIN}%" server bash -c "
        pct=\$(go tool cover -func=coverage.out | awk '/^total:/{print \$3}' | tr -d '%')
        echo \"total: \${pct}%\"
        awk \"BEGIN{ exit !(\$pct < $SERVER_COVERAGE_MIN) }\" && { echo '下限割れ'; exit 1; }; exit 0"
    else
      skip "migrations の適用"                  "DATABASE_URL 未設定 / DB に接続できません"
      skip "go test (race, coverage)"           "DATABASE_URL 未設定 / DB に接続できません"
      skip "Synthetic injection E2E (integration)" "DATABASE_URL 未設定 / DB に接続できません"
      skip "RLS fail-closed rehearsal（DB を専有）" "DATABASE_URL 未設定 / DB に接続できません"
      skip "カバレッジ下限 ${SERVER_COVERAGE_MIN}%" "テストを実行していないため"
    fi

    gorun "migration/負債台帳の一意性" server \
      go test ./internal/store/ -count=1 -run 'TestMigrationNumbers|TestGrandfatheredMigrationDuplicates|TestDebtLedger'

    if [ "$MODE" = "full" ]; then
      gorun "go build (api/ingestion/detection)" server \
        bash -c 'go build ./cmd/api/... && go build ./cmd/ingestion/... && go build ./cmd/detection/...'
      if $LIST_ONLY || curl -sSf -o /dev/null --max-time 10 https://vuln.go.dev/index/db.json 2>/dev/null; then
        gorun "govulncheck" server go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
      else
        skip "govulncheck" "vuln.go.dev に到達できません"
      fi
    fi
  fi

  # merge-gate.yml の radar ジョブのうち、**ローカルで意味のある半分**。
  #
  # radar は「開いている PR 全部」を新しい main と突き合わせるので、
  # 全体は GitHub API 無しには再現できない。だがそのうち自分の枝について
  # の判定 —「この枝が追加した migration 番号が、既に main にもあるか」—
  # は git だけで出せる。そして自分が踏む衝突は、事実上そこにしかない。
  #
  # radar は PR 上では落とさない（他人の PR の番号で自分の PR が赤くなる
  # のを避けるため）。ここでは自分の枝の話なので落とす。マージしてから
  # main を赤くするより、push 前に番号を取り直すほうが安い。
  #
  # go を必要としないので、go が無い環境でもこれだけは走る。
  if ! git rev-parse --verify -q origin/main >/dev/null; then
    skip "migration 番号の衝突（origin/main と）" "origin/main がありません（git fetch origin main）"
  else
    run "migration 番号の衝突（origin/main と）" . bash -c '
      set -uo pipefail
      base="$(git merge-base HEAD origin/main)"
      # この枝が追加/リネームした migration
      added="$(git diff --name-only --diff-filter=AR "$base"...HEAD -- "server/migrations/*.sql" 2>/dev/null || true)"
      # 未コミットの新規ファイルも見る。push 前に気づくのが目的なので、
      # まだコミットしていない番号を見逃したら意味が半分になる。
      added="$added
$(git status --porcelain -- "server/migrations/*.sql" | awk "/^\\?\\?|^A/ {print \$2}")"
      added="$(printf "%s\n" "$added" | sed "/^$/d" | sort -u)"
      if [ -z "$added" ]; then echo "追加された migration はありません。"; exit 0; fi

      main_nums="$(git ls-tree --name-only origin/main server/migrations/ \
        | sed "s|.*/||; s|_.*||" | sed "/^$/d" | sort -u)"

      rc=0
      for f in $added; do
        num="$(basename "$f" | sed "s|_.*||")"
        if printf "%s\n" "$main_nums" | grep -qx "$num"; then
          echo "衝突: $(basename "$f") の番号 $num は既に origin/main にあります。"
          rc=1
        fi
      done
      if [ "$rc" -ne 0 ]; then
        echo "番号を取り直してください。冪等でない migration をリネームしない原則は docs/debt/P2.md の P2-6 を参照。"
      else
        echo "追加した番号 ($(printf "%s " $added | sed "s|server/migrations/||g")) に衝突はありません。"
      fi
      exit "$rc"'
  fi

  # ci.yml の backup-test ジョブ。
  #
  # CI は postgres サービスコンテナの使い捨て DB を相手にしているので
  # restore.sh --force（pg_restore --clean --if-exists）を無造作に流せる。
  # 手元で同じことを DATABASE_URL に対してやると、開発中の DB を消す。
  # そこで **その場で使い捨ての DB を作って、そこだけで完結させる**。
  # 触るのは自分で CREATE して自分で DROP するものだけ。
  if [ -z "${DATABASE_URL:-}" ]; then
    skip "バックアップ/リストアの整合性" "DATABASE_URL 未設定"
  elif ! have psql || ! have pg_dump || ! have pg_restore; then
    skip "バックアップ/リストアの整合性" "psql / pg_dump / pg_restore のいずれかがありません"
  elif ! [[ "${DATABASE_URL%%\?*}" =~ ^[a-z+]+://[^/]+/[^/]+$ ]]; then
    skip "バックアップ/リストアの整合性" "DATABASE_URL から DB 名を切り出せません"
  else
    run "バックアップ/リストアの整合性" . bash -c '
      set -euo pipefail
      body="${DATABASE_URL%%\?*}"
      query=""
      case "$DATABASE_URL" in *\?*) query="?${DATABASE_URL#*\?}" ;; esac
      prefix="${body%/*}"
      tmpdb="verify_backup_$$"
      admin_url="$prefix/postgres$query"
      tmp_url="$prefix/$tmpdb$query"

      psql "$admin_url" -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE $tmpdb" >/dev/null
      workdir="$(mktemp -d)"
      cleanup() {
        rm -rf "$workdir"
        psql "$admin_url" -q -c "DROP DATABASE IF EXISTS $tmpdb" >/dev/null 2>&1 || true
      }
      trap cleanup EXIT

      # 以下は ci.yml の backup-test と同じ順序・同じ主張。
      psql "$tmp_url" -v ON_ERROR_STOP=1 -q \
        -c "CREATE TABLE backup_test (id serial, val text); INSERT INTO backup_test VALUES (1, '"'"'hello'"'"');"

      DATABASE_URL="$tmp_url" BACKUP_DIR="$workdir" BACKUP_DEST=local \
        bash deploy/backup/backup.sh --local

      ls -la "$workdir"
      test -f "$workdir"/edr_backup_*.dump.gz
      test -f "$workdir"/edr_backup_*.dump.gz.sha256
      ( cd "$workdir" && sha256sum --check edr_backup_*.dump.gz.sha256 )

      psql "$tmp_url" -v ON_ERROR_STOP=1 -q -c "DROP TABLE backup_test;"
      backup_file="$(ls "$workdir"/edr_backup_*.dump.gz | head -1)"
      DATABASE_URL="$tmp_url" bash deploy/backup/restore.sh --force "$backup_file"

      # restore.sh は pg_restore の非ゼロ終了を warn に落とすので、
      # 実際の主張はここ。データが戻っていなければ落ちる。
      psql "$tmp_url" -t -A -c "SELECT val FROM backup_test WHERE id=1;" | grep -qx hello
      echo "リストア後のデータを確認しました。"'
  fi
fi

# ── agent ────────────────────────────────────────────────────────
if wants agent; then
  section "agent (Go)"
  if ! have go; then
    skip "agent 一式" "go が PATH にありません"
  else
    run   "gofmt" agent bash -c 'test -z "$(gofmt -l .)" || { gofmt -l .; gofmt -d .; false; }'
    gorun "staticcheck (既定タグ)" agent go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" ./...

    # NetworkMonitor / FilelessMonitor の bpf2go バインディングはコミット
    # 済みなので、素の `-tags ebpf` はそのまま通る。
    gorun "go test -tags ebpf" agent \
      go test -tags ebpf -race -timeout 120s -coverprofile=coverage.out -covermode=atomic ./...
    gorun "カバレッジ下限 ${AGENT_COVERAGE_MIN}%" agent bash -c "
      pct=\$(go tool cover -func=coverage.out | awk '/^total:/{print \$3}' | tr -d '%')
      echo \"total: \${pct}%\"
      awk \"BEGIN{ exit !(\$pct < $AGENT_COVERAGE_MIN) }\" && { echo '下限割れ'; exit 1; }; exit 0"

    # prevention 系 (PreventionLSM / TamperLSM / CredAccessLSM /
    # HostIntegrityMonitor / TLSMonitor) のバインディングはリポジトリに
    # 入っておらず、CI が毎回その場で生成している。生成には clang と
    # 稼働カーネルの BTF、そして bpftool（vmlinux.h のダンプ用）が要る。
    # 揃っていない環境では、実際に防御を有効化する唯一のビルドである
    # `ebpf prevention` を検証できない。ここを黙って飛ばすと、出荷する
    # 構成だけ未検証のまま緑に見える。
    if have clang && [ -r /sys/kernel/btf/vmlinux ] && have bpftool; then
      # ci.yml の agent-build にある「コミット済みバインディングのドリフト検査」。
      # NetworkMonitor / FilelessMonitor のバインディングはリポジトリに入って
      # いて、出荷する Linux エージェント（-tags ebpf）はそれを埋め込む。
      # .bpf.c を変えて再生成し忘れると、**ビルドは通るのに古いオブジェクトを
      # 出荷する**。ビルドもテストもこれを見つけられない。
      #
      # .o は BTF 由来のデバッグ情報がホストごとに変わるので、C ソースだけから
      # 決まる .go 側だけを見る（CI と同じ）。生成物はここで書き換えるので、
      # 検査後に必ず元へ戻す。
      gorun "コミット済み eBPF バインディングの鮮度" agent bash -c '
        set -uo pipefail
        # 判定に使うのは .go だけだが、**書き戻すのは .o も含めた全部**。
        # .o はコミットされていて、再生成すると BTF 由来の差分で必ず汚れる。
        # 検査のために作業ツリーを汚したままにしない。
        gen=(internal/platform/linux/networkmonitor_bpf*.go
             internal/platform/linux/filelessmonitor_bpf*.go)
        touched=(internal/platform/linux/networkmonitor_bpf*
                 internal/platform/linux/filelessmonitor_bpf*)
        # vmlinux.h は .gitignore 済み。もともと無ければ、作ったものは消す。
        had_vmlinux=false; [ -f ebpf/vmlinux.h ] && had_vmlinux=true
        restore() {
          git checkout -- "${touched[@]}" 2>/dev/null || true
          $had_vmlinux || rm -f ebpf/vmlinux.h
        }
        trap restore EXIT
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h || exit 1
        ( cd internal/platform/linux
          for pair in "NetworkMonitor network_monitor" "FilelessMonitor fileless_monitor"; do
            set -- $pair
            GOPACKAGE=linux go run github.com/cilium/ebpf/cmd/bpf2go \
              -tags ebpf -cc clang \
              -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" \
              "$1" "../../../ebpf/$2.bpf.c" || exit 1
          done ) || exit 1
        if ! git diff --exit-code -- "${gen[@]}"; then
          echo "コミット済みの bpf2go バインディングが古くなっています。再生成してコミットしてください。"
          exit 1
        fi
        echo "バインディングは .bpf.c と一致しています。"'

      gorun "staticcheck (ebpf)" agent \
        go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" -tags ebpf ./...
      gorun "staticcheck (ebpf prevention)" agent \
        go run "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" -tags "ebpf prevention" ./...
      gorun "enforcing 版のビルドとテスト" agent bash -c '
        set -e
        go build -tags "ebpf prevention" -ldflags="-s -w" -o /tmp/edr-agent-ebpf ./cmd/agent/...
        go build -tags "ebpf prevention" -ldflags="-s -w" -o /tmp/edr-watchdog-ebpf ./cmd/watchdog/...
        go test -tags "ebpf prevention" -timeout 120s ./...'
    else
      local_reason="clang / BTF / bpftool のいずれかがありません（LSM バインディング未生成）"
      skip "staticcheck (ebpf)"             "$local_reason"
      skip "staticcheck (ebpf prevention)"  "$local_reason"
      skip "enforcing 版のビルドとテスト"   "$local_reason"
    fi

    gorun "クロスプラットフォーム vet" agent bash -c '
      set -e
      GOOS=windows GOARCH=amd64 go vet ./...
      GOOS=darwin  GOARCH=arm64 go vet ./...
      GOOS=windows GOARCH=amd64 go vet -tags prevention ./...
      GOOS=darwin  GOARCH=arm64 go vet -tags esf ./...
      GOOS=darwin  GOARCH=arm64 go vet -tags "esf prevention" ./...'

    if [ "$MODE" = "full" ]; then
      # ci.yml の agent-build の matrix。上の vet はコンパイラの型検査までで、
      # リンクは通っていない。出荷する 3 構成が本当にリンクまで通るかは
      # ビルドしないと分からない（tags は matrix と同じ。Linux だけ ebpf）。
      gorun "クロスコンパイル（windows/linux/darwin）" agent bash -c '
        set -e
        out="$(mktemp -d)"; trap "rm -rf $out" EXIT
        build() { # <goos> <goarch> <tags> <suffix>
          GOOS="$1" GOARCH="$2" CGO_ENABLED=0 \
            go build -tags "$3" -ldflags="-s -w" -o "$out/edr-agent-$1-$2$4" ./cmd/agent/...
          GOOS="$1" GOARCH="$2" CGO_ENABLED=0 \
            go build -ldflags="-s -w" -o "$out/edr-watchdog-$1-$2$4" ./cmd/watchdog/...
        }
        build windows amd64 ""     .exe
        build linux   amd64 "ebpf" ""
        build darwin  arm64 ""     ""
        ls -la "$out"'

      if $LIST_ONLY || curl -sSf -o /dev/null --max-time 10 https://vuln.go.dev/index/db.json 2>/dev/null; then
        gorun "govulncheck" agent go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
      else
        skip "govulncheck" "vuln.go.dev に到達できません"
      fi
    fi
  fi
fi

# ── frontend ─────────────────────────────────────────────────────
if wants frontend; then
  section "frontend (Next.js)"
  if ! have npm; then
    skip "frontend 一式" "npm が PATH にありません"
  else
    [ -d frontend/node_modules ] || run "npm install" frontend npm install --prefer-offline
    run "lint"            frontend npm run lint
    run "型チェック"      frontend npx tsc --noEmit
    run "mock guard"      frontend node scripts/check-mock-guards.mjs
    run "vitest (coverage)" frontend npm run test:coverage
    if [ "$MODE" = "full" ]; then
      run "next build" frontend npm run build
    fi
  fi
fi

# ── rules ────────────────────────────────────────────────────────
if wants rules; then
  section "rules (Sigma + YARA)"
  if ! have go; then
    skip "検知ルール検証" "go が PATH にありません"
  elif ! have yara; then
    # validate-rules は YARA ルールのコンパイルに yara CLI を呼ぶ。
    skip "検知ルール検証" "yara CLI がありません（apt install yara）"
  else
    run "検知ルール検証" server go run ./cmd/validate-rules -dir ../rules
  fi
fi

# ── sdk ──────────────────────────────────────────────────────────
if wants sdk; then
  section "sdk (Python + TypeScript)"
  if ! have python3 || [ ! -f sdk/python/requirements-dev.txt ]; then
    skip "Python SDK テスト" "python3 または requirements-dev.txt がありません"
  elif ! python3 -c 'import pytest' 2>/dev/null; then
    # 依存を勝手に入れない。システムの Python 環境を書き換えるのは
    # 検証スクリプトの仕事ではないので、入れ方だけ示して飛ばす。
    skip "Python SDK テスト" "pytest 未導入（pip install -r sdk/python/requirements-dev.txt）"
  else
    run "Python SDK テスト" sdk/python python3 -m pytest -q
  fi
  if have npm && [ -f sdk/typescript/package.json ]; then
    [ -d sdk/typescript/node_modules ] || run "npm install (sdk/ts)" sdk/typescript npm install
    run "TypeScript SDK 型チェック" sdk/typescript npm run typecheck
    run "TypeScript SDK テスト"     sdk/typescript npm test
  else
    skip "TypeScript SDK" "npm または sdk/typescript がありません"
  fi
fi

# ── security ─────────────────────────────────────────────────────
# security.yml の写し。
#
# ここのツールは 1 つも「勝手に入れない」。pytest の項と同じ理由で、
# 検証スクリプトが開発機に何かを常駐させるべきではない。入っていなければ
# 入れ方を添えて SKIP する。CI 側はピン留めしたバイナリ / コンテナを毎回
# 取り直しているので、版が一致するとは限らない点も明示しておく。
if wants security; then
  section "security (secret / dependency scanning)"

  # ── gitleaks ────────────────────────────────────────────────
  # security.yml と同じ引数。--exit-code 1 なので、これは**本物のゲート**。
  if ! have gitleaks; then
    skip "Gitleaks（履歴のシークレット走査）" \
      "gitleaks CLI がありません（CI は v8.30.1 のリリースバイナリを取得して実行）"
  elif [ ! -f .gitleaks.toml ]; then
    skip "Gitleaks（履歴のシークレット走査）" ".gitleaks.toml がありません"
  else
    run "Gitleaks（履歴のシークレット走査）" . \
      gitleaks detect --source . --config .gitleaks.toml --redact --no-banner --exit-code 1
  fi

  # ── Trivy filesystem ────────────────────────────────────────
  # security.yml の trivy-fs は exit-code を渡していない。つまり CI でも
  # **落ちない**（SARIF を Security タブに上げるだけ）。ここで落とすと CI より
  # 厳しくなり写しでなくなるので、同じく報告に留めて中身だけ見せる。
  if ! have trivy; then
    skip "Trivy fs（CRITICAL/HIGH・報告のみ）" \
      "trivy CLI がありません（https://trivy.dev/latest/getting-started/installation/）"
  else
    # --exit-code は渡さない（既定の 0 のまま）。渡すと「指摘があった」と
    # 「trivy 自体が落ちた」がどちらも非ゼロになって区別できない。
    # 非ゼロ = ツールの失敗、と読める状態にしておく。
    run_show "Trivy fs（CRITICAL/HIGH・報告のみ。CI もゲートにしていない）" . bash -c '
      out="$(mktemp)"
      trap "rm -f $out" EXIT
      trivy fs --severity CRITICAL,HIGH --ignore-unfixed \
        --no-progress --quiet --format table --output "$out" . || exit $?
      if [ -s "$out" ]; then
        echo "指摘あり（CI もこれではゲートしません。Security タブへの報告のみ）:"
        cat "$out"
      else
        echo "CRITICAL/HIGH の指摘はありません。"
      fi'
  fi

  # ── Semgrep / Trivy image は --full でだけ ───────────────────
  if [ "$MODE" = "full" ]; then
    # semgrep.yml と同じ 4 ルールセット。--error を外してあるのも CI と同じ
    # （129 件の未トリアージがあるため、まだゲートに戻せていない）。
    if ! have semgrep; then
      skip "Semgrep SAST（報告のみ）" "semgrep CLI がありません（pipx install semgrep）"
    elif ! curl -sSf -o /dev/null --max-time 10 https://semgrep.dev/ 2>/dev/null; then
      skip "Semgrep SAST（報告のみ）" "semgrep.dev に到達できません（ルールセットの取得に要る）"
    else
      run_show "Semgrep SAST（報告のみ。CI もゲートにしていない）" . \
        semgrep scan --config p/golang --config p/security-audit \
                     --config p/secrets --config p/owasp-top-ten \
                     --quiet --metrics off .
    fi

    # trivy-image は CI では main への push でしか走らない（PR では回さない）。
    # ローカルの --full はそれより広いが、ここで見えるほうが「main に入って
    # から初めて赤くなる」より安い。
    if ! have trivy; then
      skip "Trivy image（3 イメージ・報告のみ）" "trivy CLI がありません"
    elif ! have docker || ! docker info >/dev/null 2>&1; then
      skip "Trivy image（3 イメージ・報告のみ）" "docker デーモンに接続できません"
    else
      run_show "Trivy image（3 イメージ・報告のみ。CI は main への push でのみ実行）" . bash -c '
        set -u
        rc=0
        scan() { # <名前> <context> <dockerfile> <target>
          local tag="edr-$1:scan"
          if [ -n "$4" ]; then
            docker build -q --target "$4" -f "$3" -t "$tag" "$2" >/dev/null || return 1
          else
            docker build -q -f "$3" -t "$tag" "$2" >/dev/null || return 1
          fi
          echo "── $1"
          trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 0 \
            --no-progress --quiet --format table "$tag"
        }
        scan server-api    . server/Dockerfile   api       || rc=1
        scan server-ingest . server/Dockerfile   ingestion || rc=1
        scan frontend      frontend frontend/Dockerfile "" || rc=1
        [ "$rc" -eq 0 ] || echo "イメージのビルドに失敗したものがあります。"
        exit "$rc"'
    fi
  else
    skip "Semgrep SAST"  "--full でのみ実行（ルールセットの取得に時間がかかる）"
    skip "Trivy image"   "--full でのみ実行（3 イメージのビルドに時間がかかる）"
  fi
fi

# ── まとめ ───────────────────────────────────────────────────────
printf '\n%s── まとめ %s\n' "$C_BLD" "$C_OFF"
printf '  %sPASS %d%s   %sFAIL %d%s   %sSKIP %d%s\n' \
  "$C_GRN" "$N_PASS" "$C_OFF" "$C_RED" "$N_FAIL" "$C_OFF" "$C_YEL" "$N_SKIP" "$C_OFF"

if [ "$N_SKIP" -gt 0 ]; then
  printf '\n  %s飛ばした検査（CI では実行される。緑と同じ意味にはならない）:%s\n' "$C_YEL" "$C_OFF"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st label reason <<<"$r"
    [ "$st" = "SKIP" ] && printf '    - %s — %s\n' "$label" "$reason"
  done
fi

cat <<'NOTE'

  そもそもこのスクリプトの対象外（ローカルでは原理的に再現しない）:
    - Open PR collision radar の「他人の PR」の部分（GitHub API が要る）
      自分の枝が追加した番号と main の突き合わせは server の項で実行する。
      落ちるのは「マージすると main が赤くなる」経路だけで、それは自分で
      直せる側。他人の開いている PR 同士の衝突は main への push で出る。
    - macOS ESF のネイティブビルド（macOS ホストと EndpointSecurity SDK が要る）
      Linux では verify-prevention-build.yml を手動起動するしかない。
    - Playwright E2E（ci.yml ではなく integration.yml の夜間実行）
    - SARIF の GitHub Security タブへのアップロード、Codecov への送信、
      カバレッジ表の PR コメント（どれもゲートではなく報告経路）
NOTE

[ "$N_FAIL" -eq 0 ]

#!/usr/bin/env python3
"""同期が配布物を削っていないことを、**受け取る側で**確かめる。

    python3 scripts/sync_guard.py                 # 作業木を見る
    python3 scripts/sync_guard.py head.tar.gz     # 書庫の中の木を見る（CI）

## なぜ要るか

このリポジトリは本流のスナップショットで、生成のたびに木がまるごと
差し替わります。生成側が何かを落とすと、**その PR は緑のまま入ります。**

実例が 2 度あります。どちらも同じ形でした。

  #67  ジョブの `timeout-minutes` 47 件と、欠落を落とす検査を入れた
  #70  同期が 47 件を全部消し、**同時に検査そのものも消した**
  #73  戻した
  ？   次の同期

**検査が自分と一緒に消えるので、検査は自分を守れません。** #70 のとき
「timeout-minutes がありません」と怒る側はもういなかったので、PR は
22/22 緑で通りました。

## ここに置くものの規則

**消えても、その PR の CI が緑のままになるものだけ**を、名前で留めます。

消えると CI が落ちるもの（`frontend/tests/lib/route-scan.ts` など、
テストが import しているファイル）は、ここに書きません —— vitest が
落とします。二重に書くと、片方を直したときにもう片方が古くなります。

## どこから走らせるか

`.github/workflows/sync-guard.yml` が `pull_request_target` で呼びます。
**`pull_request_target` は base 側（main）のワークフロー定義で走ります。**
PR がこのファイルごと消しても、走るのは main にある版です。
`push` や `pull_request` で走らせると、PR が定義を消した時点で
一緒に消えます —— #70 で起きたのがそれです。

## PR の木は、ディスクに置きません

`pull_request_target` は base の権限で走るので、**PR のコードを1行でも
実行したら、そのまま乗っ取られます。** ここは PR head を
`actions/checkout` せず、書庫（tarball）のまま渡します。

  - 展開しません。**PR のファイルは1つもディスクに落ちません。**
  - `tarfile` で読むだけなので、実行される経路がありません
  - 木として存在しないので、あとから足した action が
    （`setup-node` の cache のように）勝手に見つけて触ることもありません

「実行していないことを監査してください」という約束ではなく、
**実行できる形にそもそもしない**、という置き方です。第1引数が
`.tar.gz` ならその中を、ディレクトリならその下を見ます。

## 終了コード

    0  すべて残っている
    1  消えているものがある
"""
from __future__ import annotations

import os
import re
import sys
import tarfile

import yaml

# ── 1. ジョブの上限 ───────────────────────────────────────────────
# workflow-lint.yml と同じ規則を、**base 側から**当てます。あちらが
# 消されていても、ここは main の版で走ります。
#
# 実測（直近 200 runs）で 2 回、既定の 6 時間まで走りました:
#   agent-build (linux/amd64/ebpf)  中央 1.7 分 → 一度 360.3 分（上限に当たって停止）
#   rules-validate                  中央 1.2 分 → 一度 111.2 分
# どちらも apt-get の取得で止まっていました。**落ちないので誰も
# 気づかず、予算だけが減ります。**
JOB_CEILING_MINUTES = 60

# ネットワークを踏む step に付けた 10 分の上限。**ジョブの上限だけでは
# 遅いです** —— apt が止まったジョブは、job の上限（20〜45 分）まで
# 待ってから落ちます。step 側で切ると 10 分で落ちます。
#
# **数で留めています。名前ではありません。** 本流は step の名前を
# 変えるので、名前で留めると改名のたびに鳴ります。**鳴る検査は
# 消されます。** ここが捕まえるのは #70 で実際に起きた形
# （まとめて全部消える）で、1 本ずつの改名や追加は捕まえません。
STEP_TIMEOUT_FLOOR = {
    '.github/workflows/agent-ebpf.yml': 1,
    '.github/workflows/sync-guard.yml': 1,
    '.github/workflows/ci.yml': 10,
    '.github/workflows/integration.yml': 1,
    '.github/workflows/package.yml': 2,
    '.github/workflows/security.yml': 2,
    '.github/workflows/verify-prevention-build.yml': 1,
}

# ── 2. 検査そのもの ───────────────────────────────────────────────
# ファイルがあることと、判定が残っていることは別です。#70 は
# workflow-lint.yml を残したまま、中の 28 行だけを消しました。
WORKFLOW_LINT = '.github/workflows/workflow-lint.yml'
WORKFLOW_LINT_MARKERS = [
    ('"timeout-minutes" not in job', 'timeout-minutes の欠落を落とす枝'),
    ('t > 60', '上限が 60 分を超えていたら落とす枝'),
]

# ── 3. ローカルの写し ─────────────────────────────────────────────
VERIFY = 'scripts/verify.sh'
VERIFY_MARKERS = [
    ('section "workflows"', 'workflow-lint の写しを領域に関係なく毎回走らせる節'),
    ('"timeout-minutes" not in job', 'timeout-minutes の欠落を落とす枝'),
    ('job["timeout-minutes"] > 60', '上限が 60 分を超えていたら落とす枝'),
]

# ── 4. ラチェット 16 本 ───────────────────────────────────────────
# #70 が「生成のたびに約 50 個の固定値を測り直す負担」を理由に配布から
# 外し、#75 が較正の道具を作って戻したもの。**消えても何も落ちません**
# —— 走らなくなるだけで、走らない検査は何も報告しません。
RATCHETS = [
    'frontend/tests/lib/backend-pending-coverage.test.ts',
    'frontend/tests/lib/login-clients.test.ts',
    'frontend/tests/lib/mutation-failure-surface.test.ts',
    'frontend/tests/lib/no-test-imports.test.ts',
    'frontend/tests/lib/raw-fetch.test.ts',
    'frontend/tests/lib/server-routes.test.ts',
    'frontend/tests/lib/silent-writes.test.ts',
    'server/internal/api/handlers/answered_with_a_value_test.go',
    'server/internal/api/handlers/discarded_read_test.go',
    'server/internal/api/handlers/discarded_write_reasons_test.go',
    'server/internal/api/handlers/discarded_write_test.go',
    'server/internal/api/handlers/skipped_row_test.go',
    'server/internal/scheduler/bare_log_and_return_test.go',
    'server/internal/store/reachable_test.go',
    'server/internal/tick/background_failed_test.go',
    'server/internal/tick/tracked_workers_test.go',
]

# ── 4-b. ラチェットの固定値が緩んでいないか ───────────────────────
#
# **ファイルが残っていても、中の数が緩めば同じことです。**
#
# 引き継ぎには「生成器が較正の道具を呼んでいるかは受け側から見えない」と
# 書いてありました。呼んだかどうかは確かに見えませんが、**呼ばれなかった
# 結果は見えます** —— 固定値が main と違う値で戻ってきます。
#
# ## 3 種類あって、守るのは 2 つだけ
#
# 実物の判定を読んで分けました。
#
#	ceiling  `if got > N` の形。**N が増えると緩みます**
#	floor    `if got < N` の形。**N が減ると緩みます**
#	exact    `if got != N` の形。**緩む向きがありません** ——
#	         ずれた瞬間にその検査自身が落ちるので、ここでは見ません
#	local    ラチェットではない局所変数（`n` や `want`）
#
# **exact を守らないのは手抜きではありません。** 静かに壊れないものを
# ここで鳴らすと、正当な更新のたびに赤くなります。**鳴る検査は消されます。**
#
# ## 知らない名前は落とします
#
# 表に無い固定値が出てきたら「分類してください」で落とします。既定を
# 「見逃す」にすると、**新しいラチェットは黙って守られないまま**になり、
# それは表を作った意味を消します。
RATCHET_LIMITS = {
    # ── frontend ──
    ('frontend/tests/lib/backend-pending-coverage.test.ts', 'ANNOUNCED_BUT_ALIVE_CEILING'): 'ceiling',
    ('frontend/tests/lib/backend-pending-coverage.test.ts', 'PARTLY_DEAD_CEILING'): 'ceiling',
    ('frontend/tests/lib/backend-pending-coverage.test.ts', 'NAV_PENDING'): 'ceiling',
    ('frontend/tests/lib/login-clients.test.ts', 'LOGIN_CLIENT_FLOOR'): 'floor',
    ('frontend/tests/lib/mutation-failure-surface.test.ts', 'NAKED_MUTATION_CEILING'): 'ceiling',
    ('frontend/tests/lib/server-routes.test.ts', 'UNROUTED_READ_CEILING'): 'ceiling',
    ('frontend/tests/lib/server-routes.test.ts', 'UNROUTED_WRITE_CEILING'): 'ceiling',
    ('frontend/tests/lib/silent-writes.test.ts', 'SILENT_WRITE_CEILING'): 'ceiling',

    # ── server: handlers ──
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'answerNilErrCeiling'): 'ceiling',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'answerAssignCeiling'): 'ceiling',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'answerReturnCeiling'): 'ceiling',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'answerContinueCeiling'): 'ceiling',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'answerBreakCeiling'): 'ceiling',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'continueOutsideRowsErr'): 'exact',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'n'): 'local',
    ('server/internal/api/handlers/answered_with_a_value_test.go', 'want'): 'local',
    ('server/internal/api/handlers/discarded_read_test.go', 'discardedHandlerReads'): 'exact',
    ('server/internal/api/handlers/discarded_read_test.go', 'discardedHandlerReadsShown'): 'exact',
    ('server/internal/api/handlers/discarded_read_test.go', 'discardedHandlerReadsAggregate'): 'exact',
    ('server/internal/api/handlers/discarded_write_reasons_test.go', 'discardedWriteFuncs'): 'exact',
    ('server/internal/api/handlers/discarded_write_test.go', 'discardedWritesThatClaimSuccess'): 'exact',
    # `> N` と `< N` の両方で落とすので、緩む向きがありません。
    ('server/internal/api/handlers/discarded_write_test.go', 'discardedWritesTotal'): 'exact',
    ('server/internal/api/handlers/discarded_write_test.go', 'floor'): 'floor',
    ('server/internal/api/handlers/skipped_row_test.go', 'silentSkipCeiling'): 'ceiling',

    # ── server: scheduler / store / tick ──
    ('server/internal/scheduler/bare_log_and_return_test.go', 'minBareLogAndReturnSites'): 'floor',
    ('server/internal/scheduler/bare_log_and_return_test.go', 'bareLogAndReturnSiteCount'): 'exact',
    ('server/internal/store/reachable_test.go', 'testOnlyCeiling'): 'ceiling',
    ('server/internal/tick/background_failed_test.go', 'backgroundFailedCount'): 'exact',
    ('server/internal/tick/background_failed_test.go', 'backgroundFailedFuncs'): 'exact',
    ('server/internal/tick/tracked_workers_test.go', 'minUntrackedCandidates'): 'floor',
    ('server/internal/tick/tracked_workers_test.go', 'minTrackedWorkerNames'): 'floor',
    ('server/internal/tick/tracked_workers_test.go', 'minMatchedWorkerDecls'): 'floor',
    # 探索の深さ。**下げると走査が狭まります** —— 見つかる名前が減るので
    # 上の floor 3 本が受け止めますが、狭まったこと自体をここで言います。
    ('server/internal/tick/tracked_workers_test.go', 'trackedCallDepth'): 'floor',
    ('server/internal/tick/tracked_workers_test.go', 'reachableSlogErrorSites'): 'exact',
    ('server/internal/tick/tracked_workers_test.go', 'reachableSlogWarnSites'): 'exact',
    ('server/internal/tick/tracked_workers_test.go', 'silentErrorBranchSites'): 'exact',
    ('server/internal/tick/tracked_workers_test.go', 'reachableDiscardedWriteSites'): 'exact',
}

# `const X = 12` / `export const X: number = 12` / Go の `X = 12`。
RATCHET_DECL = re.compile(
    r'^\s*(?:(?:export\s+)?const\s+)?([A-Za-z_][A-Za-z0-9_]*)'
    r'(?:\s*:\s*number)?\s*=\s*(\d+)\s*(?://.*)?$', re.M)

# ── 5. 較正の道具 ─────────────────────────────────────────────────
# これが無いと、ラチェット 16 本を戻しておく理由（負担を自動で消せる）
# が無くなります。**道具が消えると、次の同期でラチェットがまた外れます。**
RECALIBRATORS = [
    'scripts/recalibrate_ratchets.py',
    'scripts/reanchor_mutations.py',
    'scripts/recalibrate_ratchets_test.py',
]

# ── 6. この検査そのもの ───────────────────────────────────────────
# **消されても、この実行は止まりません** —— base 側の定義で走るので、
# いま動いているのは main にある版です。止まるのは**次の PR**で、
# そのときにはもう誰も見ていません。
#
# だからここで名前を挙げます。「消えた」ことが、消えた回の PR の
# 画面に出ている必要があります。
SELF = [
    'scripts/sync_guard.py',
    'scripts/sync_guard_test.py',
    '.github/workflows/sync-guard.yml',
]

# ── 7. この検査が PR のコードを実行しないこと ─────────────────────
# `pull_request_target` は base の権限で走ります。**PR のコードを1行でも
# 実行したら、そのまま乗っ取られます。**
#
# Semgrep の `pull-request-target-code-checkout` は、head を checkout する
# pull_request_target を必ず指摘します。指摘の本文は「実行していないことを
# 監査してください」で、監査そのものは正しい —— **ただし監査は約束で、
# 約束は腐ります。** 半年後に誰かが `npm ci` を足したときに気づく仕組みが
# 無ければ、抑止コメントは「昔は安全でした」の記録になります。
#
# なので抑止せず、**形のほうを変えました。** PR の木は checkout せず、
# 書庫のまま落として `tarfile` で読みます。展開もしないので、
# **PR のファイルは1つもディスクに落ちません** —— 実行される経路が
# そもそも存在しません。
#
# 残る約束（`run:` を増やさない、permissions を広げない）は、下の
# 一覧が文字列そのままで留めます。1文字でも変わったら落ちるので、
# 増やす手はここを通ります＝そこが読み直す機会になります。
GUARD_WORKFLOW = '.github/workflows/sync-guard.yml'
GUARD_HEAD_ARCHIVE = 'head.tar.gz'
GUARD_ALLOWED_RUNS = {
    'pip install pyyaml',
    'python3 scripts/sync_guard_test.py',
    'python3 scripts/sync_guard.py head.tar.gz',
    # PR head を書庫のまま取る。**展開しません。** 宛先は base 側が決めた
    # 固定名で、PR 側の値は URL の SHA にしか入りません。
    'curl --fail --silent --show-error --location'
    ' --header "Authorization: Bearer $GH_TOKEN"'
    ' --header "Accept: application/vnd.github+json"'
    ' "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/tarball/$HEAD_SHA"'
    ' --output head.tar.gz',

    # ── 移行中。**上の形は次の PR で消します** ────────────────────
    #
    # `workflow_dispatch` では `github.event.pull_request.head.sha` が空に
    # なり、ref の無い tarball は既定ブランチを返します —— この検査が
    # main を見て「配布物はすべて残っています」と緑を返す、いちばん質の
    # 悪い形です。空 SHA を弾く枝を足して塞ぎます。
    #
    # **ガード自身の `run:` は 1 つの PR では変えられません。** この検査は
    # base（main）の版で走るので、main の一覧に無い形は「許していない
    # run:」で落ちます。**それは正しい挙動です** —— この workflow は base
    # の権限で走るので、書き換えが黙って入るほうが危ない。
    #
    # なので 2 段で入れます:
    #
    #	1. （この PR）新しい形を**先に**一覧へ足す。workflow は触らない
    #	2. （次の PR）workflow を新しい形にし、**古い形を一覧から消す**
    #
    # **2 を必ず行ってください。** 両方許したままだと、空 SHA を弾く枝を
    # 消しても落ちません —— 塞いだはずの穴が、静かに開いたままになります。
    'if [ -z "$HEAD_SHA" ]; then'
    ' echo "HEAD_SHA が空です。**workflow_dispatch では PR の木を取れません。**"'
    ' echo "ref の無い tarball は既定ブランチを返すので、この検査は main を見て"'
    ' echo "「配布物はすべて残っています」と緑を返します —— **それは嘘です。**"'
    ' echo "PR で確かめたいなら、その PR を閉じて開き直してください（reopened で走ります）。"'
    ' exit 1'
    ' fi'
    ' curl --fail --silent --show-error --location'
    ' --header "Authorization: Bearer $GH_TOKEN"'
    ' --header "Accept: application/vnd.github+json"'
    ' "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/tarball/$HEAD_SHA"'
    ' --output head.tar.gz',
}

# ── 8. agent-ebpf の mkdir ────────────────────────────────────────
# downloads/ は .gitignore に入っているので、クローン直後には存在しません。
# 再試行の間に挟まる `git reset --hard` が消すので、**ループの中**に
# 無いと 2 回目以降の cp が落ちます。この step は PR では走らない
# （`if: github.ref == 'refs/heads/main'`）ので、**消えても PR は緑です。**
EBPF = '.github/workflows/agent-ebpf.yml'
EBPF_STEP = 'Commit binary to downloads/'


def canon(script: str) -> str:
    """`run:` を突き合わせる形にそろえる。

    行継続と字下げだけを落とします —— **語は落としません。**
    空白の入れ方が変わっただけで落ちると、鳴る検査になります。
    """
    return ' '.join(script.replace('\\\n', ' ').split())


class DirTree:
    """ディレクトリの中の木。作業木を見るときはこちら。"""

    def __init__(self, root: str) -> None:
        self.label = root
        self.root = root

    def read(self, rel: str) -> str | None:
        try:
            with open(os.path.join(self.root, rel), encoding='utf-8') as fh:
                return fh.read()
        except (OSError, UnicodeDecodeError):
            return None

    def exists(self, rel: str) -> bool:
        return os.path.exists(os.path.join(self.root, rel))

    def workflows(self) -> list[str] | None:
        wf = os.path.join(self.root, '.github', 'workflows')
        if not os.path.isdir(wf):
            return None
        return sorted('.github/workflows/' + fn for fn in os.listdir(wf)
                      if fn.endswith(('.yml', '.yaml')))


class TarTree:
    """書庫の中の木。**展開しません。**

    GitHub の tarball は `owner-repo-sha/` を頭に付けるので、
    先頭の1段だけ落として索引を作ります。
    """

    def __init__(self, path: str) -> None:
        self.label = path
        self._tf = tarfile.open(path)
        self._names: dict[str, str] = {}
        for m in self._tf.getmembers():
            if not m.isfile():
                continue
            parts = m.name.split('/', 1)
            if len(parts) == 2:
                self._names[parts[1]] = m.name

    def read(self, rel: str) -> str | None:
        name = self._names.get(rel)
        if name is None:
            return None
        fh = self._tf.extractfile(name)
        if fh is None:
            return None
        try:
            return fh.read().decode('utf-8')
        except UnicodeDecodeError:
            return None

    def exists(self, rel: str) -> bool:
        return rel in self._names

    def workflows(self) -> list[str] | None:
        found = sorted(rel for rel in self._names
                       if rel.startswith('.github/workflows/')
                       and rel.endswith(('.yml', '.yaml'))
                       and '/' not in rel[len('.github/workflows/'):])
        return found or None


def open_tree(arg: str) -> DirTree | TarTree | None:
    if arg.endswith(('.tar.gz', '.tgz', '.tar')):
        try:
            return TarTree(arg)
        except (OSError, tarfile.TarError):
            return None
    return DirTree(arg) if os.path.isdir(arg) else None


def job_timeouts(tree) -> list[str]:
    """すべてのジョブが上限を持っていること。"""
    problems: list[str] = []
    names = tree.workflows()
    if not names:
        return ['.github/workflows/ がありません（または空です）。'
                '**ワークフローが1つも無い木は、CI が「全部緑」に見えます。**']

    for rel in names:
        src = tree.read(rel)
        if src is None:
            problems.append(f'{rel}: 読めません')
            continue
        try:
            doc = yaml.safe_load(src)
        except yaml.YAMLError as e:
            problems.append(f'{rel}: YAML として読めません: {e}')
            continue
        if not isinstance(doc, dict):
            continue
        jobs = doc.get('jobs')
        if not isinstance(jobs, dict):
            problems.append(f'{rel}: jobs がありません')
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict) or 'uses' in job:
                continue
            if 'timeout-minutes' not in job:
                problems.append(
                    f'{rel} / {job_name}: timeout-minutes が消えています。'
                    '**GitHub の既定は 6 時間です。** 取得で止まったジョブは'
                    '落ちも進みもせず、予算だけを使い切ります'
                    '（実測で 2 回起きています）')
                continue
            t = job['timeout-minutes']
            if isinstance(t, int) and t > JOB_CEILING_MINUTES:
                problems.append(
                    f'{rel} / {job_name}: timeout-minutes が {t} 分です。'
                    'ここに 1 時間を超えるジョブはありません。'
                    '**ハングを上限の引き上げで直さないでください**')
    return problems


def step_timeouts(tree) -> list[str]:
    """ネットワークを踏む step の 10 分が、まとめて消えていないこと。"""
    problems: list[str] = []
    for rel, floor in sorted(STEP_TIMEOUT_FLOOR.items()):
        src = tree.read(rel)
        if src is None:
            problems.append(f'{rel} が消えています')
            continue
        try:
            doc = yaml.safe_load(src)
        except yaml.YAMLError:
            continue  # ジョブ側の検査が YAML の壊れを報告します
        if not isinstance(doc, dict):
            continue
        got = 0
        for job in (doc.get('jobs') or {}).values():
            if not isinstance(job, dict):
                continue
            for step in (job.get('steps') or []):
                if isinstance(step, dict) and 'timeout-minutes' in step:
                    got += 1
        if got < floor:
            problems.append(
                f'{rel}: step の timeout-minutes が {floor} 本から {got} 本に'
                '減っています。**apt が止まった step は、ここが無いと'
                'ジョブの上限まで（20〜45 分）待ってから落ちます。**'
                '意図して減らしたなら scripts/sync_guard.py の '
                'STEP_TIMEOUT_FLOOR を直してください')
    return problems


def markers(tree, rel: str, wanted: list[tuple[str, str]],
            why: str) -> list[str]:
    """その判定が本文に残っていること。**ファイルの有無だけでは足りません。**"""
    src = tree.read(rel)
    if src is None:
        return [f'{rel} が消えています。{why}']
    return [f'{rel}: 「{label}」が消えています（探した文字列: {needle!r}）。{why}'
            for needle, label in wanted if needle not in src]


def files_exist(tree, rels: list[str], why: str) -> list[str]:
    return [f'{rel} が消えています。{why}'
            for rel in rels if not tree.exists(rel)]


def ratchet_decls(src: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2)) for m in RATCHET_DECL.finditer(src)}


def ratchet_limits(tree, base) -> list[str]:
    """ラチェットの固定値が、base より緩んでいないこと。

    **比べる相手は main（base 側）です。** この検査は base の定義で走って
    いるので、main の木はそこにあります。head は書庫のまま読みます。

    緩む向きだけを見ます（上限は増える、下限は減る）。実数一致のものは
    ずれた瞬間に検査自身が落ちるので、**ここで鳴らすと正当な更新のたびに
    赤くなります。鳴る検査は消されます。**
    """
    problems: list[str] = []
    for rel in RATCHETS:
        head_src = tree.read(rel)
        base_src = base.read(rel)
        if base_src is None:
            # main に無いなら比べる相手がいません。**消えたことは
            # files_exist が言うので、ここでは黙ります。**
            continue
        if head_src is None:
            continue
        head = ratchet_decls(head_src)
        old = ratchet_decls(base_src)

        for name in sorted(set(old) | set(head)):
            kind = RATCHET_LIMITS.get((rel, name))
            if kind is None:
                problems.append(
                    f'{rel}: {name} を RATCHET_LIMITS に分類してください'
                    f'（ceiling / floor / exact / local）。**分類が無い固定値は'
                    f'守られません。**')
                continue
            if kind in ('exact', 'local'):
                continue
            if name not in head:
                problems.append(
                    f'{rel}: {name} が消えています（main では {old[name]}）。'
                    f'**ファイルは残っていますが、この固定値は無くなりました。**')
                continue
            if name not in old:
                continue
            was, now = old[name], head[name]
            if kind == 'ceiling' and now > was:
                problems.append(
                    f'{rel}: {name} が {was} → {now} に**上がっています**（上限）。'
                    f'上限が上がると、増えた分は黙って通ります。'
                    f'較正なら scripts/recalibrate_ratchets.py --apply が'
                    f'下げる側にしか動かしません —— **上げたのは較正では'
                    f'ありません。**')
            if kind == 'floor' and now < was:
                problems.append(
                    f'{rel}: {name} が {was} → {now} に**下がっています**（下限）。'
                    f'下限が下がると、減った分は黙って通ります。')
    return problems


def ebpf_mkdir(tree) -> list[str]:
    """`mkdir -p downloads` が、再試行ループの中にあること。"""
    src = tree.read(EBPF)
    if src is None:
        return [f'{EBPF} が消えています']
    try:
        doc = yaml.safe_load(src)
    except yaml.YAMLError as e:
        return [f'{EBPF}: YAML として読めません: {e}']

    for job in (doc.get('jobs') or {}).values():
        if not isinstance(job, dict):
            continue
        for step in (job.get('steps') or []):
            if not isinstance(step, dict) or step.get('name') != EBPF_STEP:
                continue
            script = step.get('run') or ''
            lines = script.splitlines()

            # **注釈行は飛ばします。** ループの中に置いた理由を書いた
            # 注釈が `git reset --hard` に触れているので、拾うと
            # 「reset のほうが先にある」と読めてしまいます。
            # workflow-lint.yml の `grep -q` 検査が同じ理由で注釈を
            # 飛ばしているのと同じ形です —— **直した場所ほど怒られます。**
            def where(pat: str) -> int:
                for i, ln in enumerate(lines):
                    if ln.lstrip().startswith('#'):
                        continue
                    if re.search(pat, ln):
                        return i
                return -1

            mk, loop, reset = (where(r'mkdir\s+-p\s+downloads'),
                               where(r'^\s*for\s+i\s+in\b'),
                               where(r'git\s+reset\s+--hard'))
            if mk < 0:
                return [f'{EBPF} / {EBPF_STEP}: `mkdir -p downloads` が消えています。'
                        '**downloads/ は .gitignore に入っていて、クローン直後には'
                        '存在しません。** この step は PR では走らないので、'
                        '消えても PR は緑のままです']
            if loop < 0 or reset < 0:
                return [f'{EBPF} / {EBPF_STEP}: 再試行ループの形が変わりました。'
                        '`mkdir -p downloads` がループの中にあるかを確かめられません']
            if not loop < mk < reset:
                return [f'{EBPF} / {EBPF_STEP}: `mkdir -p downloads` が'
                        '再試行ループの外にあります。**間に挟まる '
                        '`git reset --hard` が downloads/ を消すので、'
                        '2 回目以降の cp が落ちます**']
            return []
    return [f'{EBPF}: 「{EBPF_STEP}」の step がありません']


def guard_is_inert(tree) -> list[str]:
    """この検査自身が、PR のコードを実行しうる形になっていないこと。"""
    src = tree.read(GUARD_WORKFLOW)
    if src is None:
        return []  # 消えたことは SELF が報告します
    try:
        doc = yaml.safe_load(src)
    except yaml.YAMLError as e:
        return [f'{GUARD_WORKFLOW}: YAML として読めません: {e}']
    if not isinstance(doc, dict):
        return [f'{GUARD_WORKFLOW}: トップレベルがマップではありません']

    problems: list[str] = []
    perms = doc.get('permissions')
    if perms != {'contents': 'read'}:
        problems.append(
            f'{GUARD_WORKFLOW}: permissions が {perms!r} です。'
            '`contents: read` だけにしてください。**base の権限で走るので、'
            'ここを広げると盗まれるものが増えます**')

    reads_the_head = False
    for job in (doc.get('jobs') or {}).values():
        if not isinstance(job, dict):
            continue
        for step in (job.get('steps') or []):
            if not isinstance(step, dict):
                continue
            name = step.get('name') or step.get('uses') or '名前なし'
            if 'working-directory' in step:
                problems.append(
                    f'{GUARD_WORKFLOW} / {name}: working-directory があります。'
                    '**PR の木の中で走る step を作らないでください**')
            uses = step.get('uses')
            if isinstance(uses, str):
                if uses.startswith('./') or uses.startswith('.\\'):
                    problems.append(
                        f'{GUARD_WORKFLOW} / {name}: uses が木の中を指しています'
                        f'（{uses}）。**PR が置いたアクションを実行します**')
                if uses.startswith('actions/checkout@'):
                    with_ = step.get('with') or {}
                    if with_.get('persist-credentials') is not False:
                        problems.append(
                            f'{GUARD_WORKFLOW} / {name}: checkout に '
                            'persist-credentials: false がありません。'
                            '**token が .git/config に残ります**')
                    # **PR の木を checkout しないこと。** これがこの節の要で、
                    # Semgrep の pull-request-target-code-checkout が指す形
                    # そのもの。書庫のまま読めば、実行される経路が無くなる。
                    if 'pull_request' in str(with_.get('ref', '')):
                        problems.append(
                            f'{GUARD_WORKFLOW} / {name}: PR の木を checkout'
                            'しています。**base の権限で走るので、木として'
                            '置いた時点で、あとから足した step や action が'
                            '触れるようになります。** 書庫のまま '
                            f'{GUARD_HEAD_ARCHIVE} に落として、'
                            'sync_guard.py に読ませてください')
            run = step.get('run')
            if isinstance(run, str):
                body = canon(run)
                if body not in GUARD_ALLOWED_RUNS:
                    problems.append(
                        f'{GUARD_WORKFLOW} / {name}: 許していない run: があります'
                        f' → {body[:80]!r}\n'
                        '      **この workflow は base の権限で走ります。**'
                        'ここに PR の木を触る命令（npm ci / make / '
                        'tar -x など）を足すと、そのまま乗っ取られます。'
                        '増やすなら scripts/sync_guard.py の '
                        'GUARD_ALLOWED_RUNS に、**なぜ安全かを確かめてから**'
                        '足してください')
                if GUARD_HEAD_ARCHIVE in body and 'sync_guard.py' in body:
                    reads_the_head = True

    if not reads_the_head:
        problems.append(
            f'{GUARD_WORKFLOW}: {GUARD_HEAD_ARCHIVE} を読む step が'
            'ありません。**PR の木を読まない検査は、何も見ていません**')
    return problems


def main() -> int:
    arg = sys.argv[1] if len(sys.argv) > 1 else '.'
    tree = open_tree(arg)
    if tree is None:
        # **ここで 0 を返すと、CI は毎回緑になります。**
        print(f'{arg} を開けません（ディレクトリでも書庫でもありません）')
        return 1
    root = tree.label

    # 比べる相手は **この道具が置かれている木**です。`pull_request_target`
    # で走るので、それは main（base 側）になります。**引数を増やしません**
    # —— ワークフローの `run:` は GUARD_ALLOWED_RUNS が語そのままで留めて
    # いるので、呼び方を変えると、この検査は自分の変更で落ちます。
    base = DirTree(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    sections = [
        ('ジョブの上限', job_timeouts(tree)),
        ('取得する step の上限', step_timeouts(tree)),
        ('欠落を落とす検査そのもの', markers(
            tree, WORKFLOW_LINT, WORKFLOW_LINT_MARKERS,
            '**この検査は自分を守れません** —— 消えた回（#70）は'
            '「timeout-minutes がありません」と怒る側もいなくなっていたので、'
            'PR は 22/22 緑で通りました')),
        ('ローカルの写し', markers(
            tree, VERIFY, VERIFY_MARKERS,
            'CI と手元がずれると「手元で緑なのに CI で落ちる」、'
            'あるいはもっと悪い「手元で緑だが、CI にしか無い検査を'
            '通していない」状態になります')),
        ('ラチェット 16 本', files_exist(
            tree, RATCHETS,
            '**消えても何も落ちません** —— 走らなくなるだけで、'
            '走らない検査は何も報告しません。'
            '較正が要るなら scripts/recalibrate_ratchets.py を'
            '呼んでください（外す理由にはなりません）')),
        ('ラチェットの固定値', ratchet_limits(tree, base)),
        ('この検査が PR のコードを実行しないこと', guard_is_inert(tree)),
        ('この検査そのもの', files_exist(
            tree, SELF,
            '**この実行は止まりません**（base 側の定義で走っています）。'
            '止まるのは次の PR で、そのときにはもう誰も見ていません。'
            '外すなら main 側で外してください')),
        ('較正の道具', files_exist(
            tree, RECALIBRATORS,
            'これが無いと、ラチェットを戻しておく理由（測り直す負担を'
            '自動で消せる）が無くなります')),
        ('agent-ebpf の downloads/', ebpf_mkdir(tree)),
    ]

    total = sum(len(p) for _, p in sections)
    if not total:
        print(f'{root}: 配布物はすべて残っています')
        return 0

    print(f'{root}: 同期が配布物を削っています（{total} 件）\n')
    for title, problems in sections:
        if not problems:
            continue
        print(f'── {title}  ({len(problems)} 件)')
        for p in problems:
            print(f'  - {p}')
        print()
    print('この検査は base 側（main）の定義で走っています。'
          'PR がこのファイルを消しても、走るのは main にある版です。\n'
          '落とすべきでないものが混ざっているなら、**main 側で外して**'
          'ください —— PR 側で消しても、この検査は止まりません。')
    return 1


if __name__ == '__main__':
    sys.exit(main())

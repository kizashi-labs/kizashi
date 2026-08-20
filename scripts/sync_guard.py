#!/usr/bin/env python3
"""同期が配布物を削っていないことを、**受け取る側で**確かめる。

    python3 scripts/sync_guard.py            # 作業木を見る
    python3 scripts/sync_guard.py head       # head/ 以下の木を見る（CI）

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

第1引数は「検査する木の根」で、CI では PR head を置いた `head/` を
渡します。**このスクリプト自身は base 側の版が動きます。**

## 終了コード

    0  すべて残っている
    1  消えているものがある
"""
from __future__ import annotations

import os
import re
import sys

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

# ── 6. agent-ebpf の mkdir ────────────────────────────────────────
# downloads/ は .gitignore に入っているので、クローン直後には存在しません。
# 再試行の間に挟まる `git reset --hard` が消すので、**ループの中**に
# 無いと 2 回目以降の cp が落ちます。この step は PR では走らない
# （`if: github.ref == 'refs/heads/main'`）ので、**消えても PR は緑です。**
EBPF = '.github/workflows/agent-ebpf.yml'
EBPF_STEP = 'Commit binary to downloads/'


def read(root: str, rel: str) -> str | None:
    try:
        with open(os.path.join(root, rel), encoding='utf-8') as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def job_timeouts(root: str) -> list[str]:
    """すべてのジョブが上限を持っていること。"""
    problems: list[str] = []
    wf_dir = os.path.join(root, '.github', 'workflows')
    if not os.path.isdir(wf_dir):
        return ['.github/workflows/ がありません。'
                '**ワークフローが1つも無い木は、CI が「全部緑」に見えます。**']

    names = sorted(fn for fn in os.listdir(wf_dir)
                   if fn.endswith(('.yml', '.yaml')))
    if not names:
        return ['.github/workflows/ が空です。'
                '**ワークフローが1つも無い木は、CI が「全部緑」に見えます。**']

    for fn in names:
        rel = os.path.join('.github/workflows', fn)
        src = read(root, rel)
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


def step_timeouts(root: str) -> list[str]:
    """ネットワークを踏む step の 10 分が、まとめて消えていないこと。"""
    problems: list[str] = []
    for rel, floor in sorted(STEP_TIMEOUT_FLOOR.items()):
        src = read(root, rel)
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


def markers(root: str, rel: str, wanted: list[tuple[str, str]],
            why: str) -> list[str]:
    """その判定が本文に残っていること。**ファイルの有無だけでは足りません。**"""
    src = read(root, rel)
    if src is None:
        return [f'{rel} が消えています。{why}']
    return [f'{rel}: 「{label}」が消えています（探した文字列: {needle!r}）。{why}'
            for needle, label in wanted if needle not in src]


def files_exist(root: str, rels: list[str], why: str) -> list[str]:
    return [f'{rel} が消えています。{why}'
            for rel in rels if not os.path.exists(os.path.join(root, rel))]


def ebpf_mkdir(root: str) -> list[str]:
    """`mkdir -p downloads` が、再試行ループの中にあること。"""
    src = read(root, EBPF)
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


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    if not os.path.isdir(root):
        print(f'{root} がありません')
        return 1

    sections = [
        ('ジョブの上限', job_timeouts(root)),
        ('取得する step の上限', step_timeouts(root)),
        ('欠落を落とす検査そのもの', markers(
            root, WORKFLOW_LINT, WORKFLOW_LINT_MARKERS,
            '**この検査は自分を守れません** —— 消えた回（#70）は'
            '「timeout-minutes がありません」と怒る側もいなくなっていたので、'
            'PR は 22/22 緑で通りました')),
        ('ローカルの写し', markers(
            root, VERIFY, VERIFY_MARKERS,
            'CI と手元がずれると「手元で緑なのに CI で落ちる」、'
            'あるいはもっと悪い「手元で緑だが、CI にしか無い検査を'
            '通していない」状態になります')),
        ('ラチェット 16 本', files_exist(
            root, RATCHETS,
            '**消えても何も落ちません** —— 走らなくなるだけで、'
            '走らない検査は何も報告しません。'
            '較正が要るなら scripts/recalibrate_ratchets.py を'
            '呼んでください（外す理由にはなりません）')),
        ('この検査そのもの', files_exist(
            root, SELF,
            '**この実行は止まりません**（base 側の定義で走っています）。'
            '止まるのは次の PR で、そのときにはもう誰も見ていません。'
            '外すなら main 側で外してください')),
        ('較正の道具', files_exist(
            root, RECALIBRATORS,
            'これが無いと、ラチェットを戻しておく理由（測り直す負担を'
            '自動で消せる）が無くなります')),
        ('agent-ebpf の downloads/', ebpf_mkdir(root)),
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

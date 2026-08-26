#!/usr/bin/env python3
"""`timeout-minutes` の現物を、**書き写さずに渡せる形**にする。

    python3 scripts/handover_timeouts.py             # 表と実物が合っているか
    python3 scripts/handover_timeouts.py --print     # 実物から表を出す
    python3 scripts/handover_timeouts.py --apply     # 表を実物に合わせて書き直す
    python3 scripts/handover_timeouts.py --restore [木]  # 表から実物へ戻す

## なぜ要るか

このリポジトリは本流のスナップショットで、生成のたびに木がまるごと
差し替わります。`timeout-minutes` は **3 度**まとめて消えました
（#67 で入れ、#70 で消え、#73 で戻し、#74 でまた消えた）。

受け側の検査（`workflow-lint.yml` / `sync_guard.py`）は「**無い**」ことは
言えますが、「**いくつだったか**」は言えません。値が書いてあるのは
`docs/ci/本流へ渡す作業一覧.md` の表だけで、それは**手で書いた散文**です。

手で書いた表は腐ります。**実際に腐りました** —— 「47 件」と書いたあと
`sync-guard.yml` が job 1 + step 1 を足し、表だけが 47 のまま残りました。
渡された側は 47 を写して 2 件落とします。合計だけは
`workflow-lint.yml` が留めていますが、**行の中身（どのジョブが何分か）は
誰も留めていません。** 値が 1 つ書き換わっても、合計は動きません。

なので表を**生成物**にします。

    実物 --print/--apply--> 表（文書）
    実物 <---- --restore ---- 表（文書）

`--restore` があると、生成器側の作業は「表を 49 か所に書き写す」から
**「1 つ道具を呼ぶ」**に変わります —— 較正の道具（§1-3）と同じ形です。

## 生成器側での使い方

この 2 つを生成器の木に置いて、生成のあと 1 回呼んでください。

    scripts/handover_timeouts.py
    docs/ci/本流へ渡す作業一覧.md

    python3 scripts/handover_timeouts.py --restore .

**冪等です。** すでに入っている値は触りません。表に無いジョブや、
表にあるのに木で見つからない step は、**黙って飛ばさずに名指しで
報告して 1 を返します** —— 飛ばすと「戻した」と「戻せなかった」が
見分けられなくなります。

## 終了コード

    0  合っている（`--restore` なら、表のとおりに入った）
    1  違いがある。**何がどう違うかを列挙します**
"""
from __future__ import annotations

import glob
import os
import re
import sys

import yaml

HANDOVER = 'docs/ci/本流へ渡す作業一覧.md'
WORKFLOW_DIR = '.github/workflows'

# 文書の中の位置。**見出しの数も表と一緒に書き換えます** ——
# 見出しだけが古いままだと、渡された側は見出しを信じます。
TOTAL_LINE = re.compile(r'job \d+ \+ step \d+ ＝ \d+ 件')
JOB_HEADING = re.compile(r'^### ジョブ\b.*$')
STEP_HEADING = re.compile(r'^### step\b.*$')


# ── 実物を読む ────────────────────────────────────────────────────

def read_tree(root: str) -> tuple[list, list, list]:
    """木から (ジョブ行, step 行, 上限の無いジョブ) を返す。

    ジョブ行は `(ファイル, ジョブ, 分)`、step 行は
    `(ファイル, ジョブ, 見出し, 分)`。**上限を持っているものだけ**を
    行にします。欠落そのものを落とすのは `workflow-lint.yml` の仕事で、
    ここは「入っている値」を表と突き合わせます。
    """
    jobs: list[tuple[str, str, int]] = []
    steps: list[tuple[str, str, str, int]] = []
    missing: list[tuple[str, str]] = []

    pattern = os.path.join(root, WORKFLOW_DIR, '*.y*ml')
    for path in sorted(glob.glob(pattern)):
        rel = os.path.basename(path)
        with open(path, encoding='utf-8') as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError:
                # **読めないファイルは、ここでは黙って飛ばします。**
                # 壊れた YAML を名指しするのは `workflow-lint.yml` の
                # 仕事で、あちらのほうが症状（ジョブが1つも作られない）
                # まで説明します。ここで例外を投げると、その説明の前に
                # traceback が出て、読む人は表の話だと思ってしまいます。
                continue
        if not isinstance(doc, dict):
            continue
        for job_name, job in (doc.get('jobs') or {}).items():
            if not isinstance(job, dict) or 'uses' in job:
                continue
            t = job.get('timeout-minutes')
            if isinstance(t, int):
                jobs.append((rel, job_name, t))
            else:
                missing.append((rel, job_name))
            for step in (job.get('steps') or []):
                if not isinstance(step, dict) or 'timeout-minutes' not in step:
                    continue
                steps.append((rel, job_name, step_ident(step),
                              step['timeout-minutes']))
    return jobs, steps, missing


def unreadable(root: str) -> list[str]:
    """YAML として読めないワークフロー。

    読めないファイルは表と突き合わせられないので、**そのファイルの行が
    まるごと「実物に無い」として並びます。** 49 行の指摘に埋もれると、
    本当の原因（1 ファイルが壊れている）が見えません。先に名指しします。
    """
    out = []
    for path in sorted(glob.glob(os.path.join(root, WORKFLOW_DIR, '*.y*ml'))):
        try:
            with open(path, encoding='utf-8') as fh:
                yaml.safe_load(fh)
        except (yaml.YAMLError, UnicodeDecodeError):
            out.append(os.path.basename(path))
    return out


def step_ident(step: dict) -> str:
    """step の見出し。名前が無ければ `uses:` で名指しします。

    **索引（step[3]）にはしません。** 生成器は step を足したり並べ替えたり
    するので、索引で書くと**別の step に上限が入ります** —— 一致しない
    ことにも気づけません。
    """
    name = step.get('name')
    if isinstance(name, str) and name:
        return name
    uses = step.get('uses')
    return f'uses: {uses}' if uses else '（名前も uses もありません）'


# ── 表を作る・読む ────────────────────────────────────────────────

def cell(text: str) -> str:
    return str(text).replace('|', r'\|')


def uncell(text: str) -> str:
    return text.replace(r'\|', '|')


def split_row(row: str) -> list[str]:
    r"""表の 1 行をセルに割る。**`\|` では割りません。**

    step の見出しに `|` が入ると、素朴な `split('|')` はその行だけ列数を
    間違えます —— **落ちずに、その 1 件だけが表から消えます。**
    """
    row = row.strip().strip('|')
    return [uncell(c.strip()) for c in re.split(r'(?<!\\)\|', row)]


def render_jobs(jobs: list) -> list[str]:
    out = ['| ファイル | ジョブ | 分 |', '| --- | --- | --- |']
    out += [f'| {cell(f)} | {cell(j)} | {m} |' for f, j, m in jobs]
    return out


def render_steps(steps: list) -> list[str]:
    out = ['| ファイル | ジョブ | step | 分 |', '| --- | --- | --- | --- |']
    out += [f'| {cell(f)} | {cell(j)} | {cell(s)} | {m} |'
            for f, j, s, m in steps]
    return out


def table_at(lines: list[str], start: int) -> tuple[int, int]:
    """`start` 以降で最初に現れる表の [開始, 終了) を返す。無ければ (-1, -1)。"""
    i = start
    while i < len(lines) and not lines[i].startswith('|'):
        if lines[i].startswith('#') and i > start:
            return -1, -1     # 次の見出しまで来た＝表が無い
        i += 1
    if i >= len(lines):
        return -1, -1
    j = i
    while j < len(lines) and lines[j].startswith('|'):
        j += 1
    return i, j


def find_heading(lines: list[str], pattern: re.Pattern) -> int:
    for i, line in enumerate(lines):
        if pattern.match(line):
            return i
    return -1


def parse_doc(text: str) -> tuple[list, list, tuple | None]:
    """文書から (ジョブ行, step 行, 見出しの数) を読み出す。

    見出しの数は `(job, step, 合計)`。行が読めなければ空の一覧を返します
    —— **例外にはしません。** 呼び出し側が「表が無い」も違いとして
    列挙できるようにします。
    """
    lines = text.split('\n')
    jobs: list[tuple[str, str, int]] = []
    steps: list[tuple[str, str, str, int]] = []

    h = find_heading(lines, JOB_HEADING)
    if h >= 0:
        s, e = table_at(lines, h + 1)
        for row in lines[s + 2:e] if s >= 0 else []:
            c = split_row(row)
            if len(c) >= 3 and c[2].isdigit():
                jobs.append((c[0], c[1], int(c[2])))

    h = find_heading(lines, STEP_HEADING)
    if h >= 0:
        s, e = table_at(lines, h + 1)
        for row in lines[s + 2:e] if s >= 0 else []:
            c = split_row(row)
            # 4 列（分あり）と、旧い 3 列（見出しに「すべて 10 分」と
            # 書いてあった形）の両方を読みます。**古い形も読めないと、
            # 一度目の `--apply` が走りません。**
            if len(c) >= 4 and c[3].isdigit():
                steps.append((c[0], c[1], c[2], int(c[3])))
            elif len(c) == 3:
                steps.append((c[0], c[1], c[2], 10))

    m = TOTAL_LINE.search(text)
    said = tuple(int(x) for x in re.findall(r'\d+', m.group(0))) if m else None
    return jobs, steps, said


def apply_doc(text: str, jobs: list, steps: list) -> str:
    """文書の 2 つの表と、3 か所の数を、実物に合わせて書き直す。"""
    lines = text.split('\n')

    for pattern, rows, render, label in (
            (STEP_HEADING, steps, render_steps, 'step'),
            (JOB_HEADING, jobs, render_jobs, 'ジョブ')):
        # **後ろから直します。** 前から入れ替えると、行数が変わって
        # 次の見出しの位置がずれます。
        h = find_heading(lines, pattern)
        if h < 0:
            continue
        s, e = table_at(lines, h + 1)
        if s >= 0:
            lines[s:e] = render(rows)
        lines[h] = f'### {label} {len(rows)} 件'

    text = '\n'.join(lines)
    return TOTAL_LINE.sub(
        f'job {len(jobs)} + step {len(steps)} ＝ {len(jobs) + len(steps)} 件',
        text)


# ── 実物へ戻す ────────────────────────────────────────────────────

def job_blocks(lines: list[str]) -> dict:
    """`jobs:` の下のジョブについて、鍵の行番号と本体の字下げを拾う。

    YAML として読み直さずに**行で**見ます。`yaml.safe_load` は
    コメントを落とすので、書き戻すと**なぜその値なのかの説明が全部
    消えます** —— 消えた説明は、次の同期で値が消される理由になります。
    """
    out: dict[str, dict] = {}
    top = -1
    for i, line in enumerate(lines):
        if re.match(r'^jobs:\s*$', line):
            top = i
            break
    if top < 0:
        return out

    indent = None
    key = None
    for i in range(top + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        cur = len(line) - len(line.lstrip())
        if cur == 0:
            break                      # `jobs:` の外へ出た
        if indent is None:
            indent = cur
        if cur == indent:
            m = re.match(r'^\s*([A-Za-z0-9_.\-]+):\s*(#.*)?$', line)
            if m:
                key = m.group(1)
                out[key] = {'line': i, 'indent': cur, 'end': len(lines)}
                for prev in list(out.values())[:-1]:
                    prev['end'] = min(prev['end'], i)
    return out


def step_lines(lines: list[str], start: int, end: int) -> list[int]:
    """ジョブの本体から、step の先頭行（`- ` の行）を順に拾う。

    **字下げが step の一覧とちょうど同じ行だけ**を数えます。`run: |` の
    中にある `- ` で始まる行は、必ずこれより深いところにあります。
    """
    steps_at = None
    found: list[int] = []
    inside = False
    for i in range(start, end):
        line = lines[i]
        if not line.strip():
            continue
        cur = len(line) - len(line.lstrip())
        if re.match(r'^\s*steps:\s*$', line):
            inside = True
            steps_at = None
            continue
        if not inside:
            continue
        if line.lstrip().startswith('- '):
            if steps_at is None:
                steps_at = cur
            if cur == steps_at:
                found.append(i)
        elif steps_at is not None and cur <= steps_at and not line.lstrip().startswith('#'):
            break                      # step の一覧を抜けた
    return found


def restore(root: str, jobs: list, steps: list) -> list[str]:
    """表のとおりに `timeout-minutes` を入れる。冪等。"""
    problems: list[str] = []
    by_file: dict[str, list] = {}
    for f, j, m in jobs:
        by_file.setdefault(f, []).append(('job', j, None, m))
    for f, j, s, m in steps:
        by_file.setdefault(f, []).append(('step', j, s, m))

    for rel, rows in sorted(by_file.items()):
        path = os.path.join(root, WORKFLOW_DIR, rel)
        if not os.path.exists(path):
            problems.append(f'{rel}: この木にありません。'
                            f'**表の {len(rows)} 件は入れられません**')
            continue
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
        lines = text.split('\n')
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            problems.append(f'{rel}: YAML として読めません（{e.__class__.__name__}）。'
                            '**壊れた木には入れられません。**先に直してください')
            continue
        parsed = (doc or {}).get('jobs') or {}
        blocks = job_blocks(lines)

        inserts: list[tuple[int, str]] = []
        for kind, job_name, ident, minutes in rows:
            job = parsed.get(job_name)
            block = blocks.get(job_name)
            if not isinstance(job, dict) or block is None:
                problems.append(f'{rel} / {job_name}: このジョブがありません。'
                                '**改名か削除です。表を直してください**')
                continue

            if kind == 'job':
                got = job.get('timeout-minutes')
                if got == minutes:
                    continue
                if got is not None:
                    problems.append(
                        f'{rel} / {job_name}: 表は {minutes} 分ですが '
                        f'{got} 分が入っています。**上書きしません** —— '
                        'どちらが正しいかは、ここでは決められません')
                    continue
                inserts.append((anchor(lines, block), 
                                ' ' * (block['indent'] + 2)
                                + f'timeout-minutes: {minutes}'))
                continue

            at = step_lines(lines, block['line'] + 1, block['end'])
            found = [i for i, st in enumerate(job.get('steps') or [])
                     if isinstance(st, dict) and step_ident(st) == ident]
            if not found:
                problems.append(
                    f'{rel} / {job_name} / {ident}: この step がありません。'
                    '**改名です** —— 名前で入れる以上、ここは静かに'
                    '飛ばせません（飛ばすと上限だけが消えます）')
                continue
            if len(found) > 1:
                problems.append(
                    f'{rel} / {job_name} / {ident}: 同じ見出しの step が '
                    f'{len(found)} 件あります。**どれに入れるか決められません**')
                continue
            idx = found[0]
            if idx >= len(at):
                problems.append(f'{rel} / {job_name} / {ident}: '
                                'step の行を見つけられませんでした')
                continue
            step = job['steps'][idx]
            if step.get('timeout-minutes') == minutes:
                continue
            if 'timeout-minutes' in step:
                problems.append(
                    f'{rel} / {job_name} / {ident}: 表は {minutes} 分ですが '
                    f"{step['timeout-minutes']} 分が入っています。**上書きしません**")
                continue
            head = at[idx]
            pad = len(lines[head]) - len(lines[head].lstrip()) + 2
            inserts.append((head, ' ' * pad + f'timeout-minutes: {minutes}'))

        if not inserts:
            continue
        # **後ろから入れます。** 前から入れると、あとの行番号がずれます。
        for at_line, new in sorted(inserts, reverse=True):
            lines.insert(at_line + 1, new)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines))
        print(f'  {rel}: {len(inserts)} 件入れました')

    return problems


def anchor(lines: list[str], block: dict) -> int:
    """ジョブの上限を入れる行。`runs-on:` の直後にそろえます。

    木のどこに置いても YAML としては同じですが、**差分の読みやすさは
    同じではありません。** 既存 31 件のうち 30 件が `runs-on:` の次の行に
    あります（`integration.yml / e2e` だけは、そこに続く説明の後ろ）。
    多数派にそろえます —— 戻した木は 49 件中 48 件が元と行単位で一致し、
    e2e の 1 件だけが説明の前に入ります。**中身は同じです。**
    """
    for i in range(block['line'] + 1, block['end']):
        if re.match(r'^\s*runs-on:', lines[i]):
            return i
    return block['line']


# ── 突き合わせ ────────────────────────────────────────────────────

def differences(tree_jobs, tree_steps, doc_jobs, doc_steps, said) -> list[str]:
    out: list[str] = []
    for label, tree, doc in (('ジョブ', tree_jobs, doc_jobs),
                             ('step', tree_steps, doc_steps)):
        t, d = set(tree), set(doc)
        for row in sorted(t - d):
            out.append(f'{label}: 実物にあって表に無い → {" / ".join(map(str, row))}')
        for row in sorted(d - t):
            out.append(f'{label}: 表にあって実物に無い → {" / ".join(map(str, row))}')
    got = (len(tree_jobs), len(tree_steps), len(tree_jobs) + len(tree_steps))
    if said is None:
        out.append('文書に「job N + step N ＝ N 件」の行がありません')
    elif tuple(said) != got:
        out.append('文書の見出しは job %d + step %d ＝ %d 件、'
                   '実物は job %d + step %d ＝ %d 件' % (tuple(said) + got))
    return out


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else '--check'
    root = argv[2] if len(argv) > 2 else '.'

    if mode == '--restore':
        # 表が正、木が従。**この向きのときだけ**、木を書き換えます。
        doc_path = os.path.join(root, HANDOVER)
        if not os.path.exists(doc_path):
            doc_path = HANDOVER
        try:
            with open(doc_path, encoding='utf-8') as fh:
                doc_jobs, doc_steps, _ = parse_doc(fh.read())
        except FileNotFoundError:
            print(f'{HANDOVER} がありません。**値がどこにも無いので、'
                  '戻せません。** 受け側から一緒に持ってきてください')
            return 1
        if not doc_jobs:
            print(f'{doc_path} にジョブの表がありません')
            return 1
        print(f'{doc_path} の job {len(doc_jobs)} + step {len(doc_steps)} 件を '
              f'{root} に当てます')
        problems = restore(root, doc_jobs, doc_steps)
        if problems:
            print('\n入れられなかったものがあります:\n')
            for p in problems:
                print('  - ' + p)
            return 1
        print('表のとおりに入っています')
        return 0

    tree_jobs, tree_steps, missing = read_tree(root)
    if mode == '--print':
        print('\n'.join(render_jobs(tree_jobs)))
        print()
        print('\n'.join(render_steps(tree_steps)))
        return 0

    path = os.path.join(root, HANDOVER)
    try:
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
    except FileNotFoundError:
        print(f'{path} がありません。**本流へ渡す値が、リポジトリのどこにも'
              '残っていない状態です**')
        return 1

    if mode == '--apply':
        new = apply_doc(text, tree_jobs, tree_steps)
        if new == text:
            print('表は実物と合っています（書き換えなし）')
            return 0
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(new)
        print(f'{HANDOVER} を実物に合わせました '
              f'（job {len(tree_jobs)} + step {len(tree_steps)}）')
        return 0

    if mode != '--check':
        print(__doc__)
        return 1

    doc_jobs, doc_steps, said = parse_doc(text)
    problems = differences(tree_jobs, tree_steps, doc_jobs, doc_steps, said)
    broken = unreadable(root)
    if broken:
        print('YAML として読めないワークフローがあります。**下の指摘は、'
              'その分だけ「実物に無い」に見えます** —— 先にこちらです:')
        for rel in broken:
            print(f'  - {rel}')
        print()
    if missing:
        # ここでは落としません（`workflow-lint.yml` の仕事です）。**ただし
        # 黙ってもいません** —— 表に載らないジョブがあることは、渡す側が
        # 知っておくべきことです。
        print('上限を持たないジョブがあります（workflow-lint が落とします）:')
        for rel, job in missing:
            print(f'  - {rel} / {job}')
        print()
    if problems:
        print(f'{HANDOVER} の表が実物と違います:\n')
        for p in problems:
            print('  - ' + p)
        print('\n**表のほうを実物に合わせてください。** 1 つ呼べば済みます:\n'
              '    python3 scripts/handover_timeouts.py --apply\n\n'
              '本流はこの表を写します。古い行を写すと、'
              'その差だけ黙って落ちます。')
        return 1
    print(f'{HANDOVER} の表は実物と合っています '
          f'（job {len(tree_jobs)} + step {len(tree_steps)} '
          f'＝ {len(tree_jobs) + len(tree_steps)} 件）')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

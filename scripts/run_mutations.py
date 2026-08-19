#!/usr/bin/env python3
"""Run the mutation specs under scripts/mutations/.

    python3 scripts/run_mutations.py                 # 全部
    python3 scripts/run_mutations.py server_answer   # 1つ
    python3 scripts/run_mutations.py --check         # 当たるかだけ見る（検査は走らせない）
    python3 scripts/run_mutations.py --isolated      # 使い捨ての worktree で走らせる

## --isolated

ハーネスは測っているあいだ、**わざと壊した状態を作業ツリーに置きます。**
1件あたり数分かかるので、その最中に木を見た人・道具は、壊れたコードが
コミットされていない変更として見えます。実際に「未コミットの変更がある」
という指摘を受けて、走行中の変異をコミットしかけました。**それを
コミットしていたら、押し込まれるのは検査の穴そのものです。**

`--isolated` は使い捨ての git worktree を作り、**その中の仕様書を実行
します**。仕様書は自分の場所からリポジトリの位置を決めるので、コピーを
走らせれば対象もコピー側になります。元の木は最初から最後まで無傷です。

作業ツリーに未コミットの変更があるときは、それも worktree に写します。
写さないと HEAD を測ることになり、**手元で直したはずのものを「まだ壊れて
いる」と報告するか、その逆をします。** どちらも、この一連の作業が
扱っている取り違えです。

`--check` は、各仕様書の pattern がまだ木に当たることだけを確かめます。
テストを1つも走らせないので数秒で終わり、CI に置けます。当たらなくなった
仕様書は、走らせても全 SKIP で緑を返すだけの文書になります —
**「壊せない検査」と「壊してみていない検査」は同じ形をしています。**

**順番に走らせます。並列にはできません。** 各ハーネスは復元手順を
リポジトリ直下の同じ `.mutate-journal.json` に書くので、2本同時に走ると
片方の journal がもう片方を上書きし、殺されたときに戻せなくなります。
journal は「壊す前に、戻し方をディスクに置く」ためのものなので、
そこが競合すると、あるために作った保証がそのまま無くなります。

どれか1本でも失敗したら、最後にまとめて落とします。最初の失敗で止めると、
残りが「走らせていない」のか「通った」のか分からなくなります。
"""
from __future__ import annotations

import atexit
import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPECS = os.path.join(HERE, 'mutations')

# worktree に持って行かないもの。node_modules だけは symlink で渡します
# （700MB あり、コピーすると1回の実行より時間がかかります）。
LINKED = ['frontend/node_modules', 'node_modules']


def git(*args, cwd=ROOT) -> str:
    return subprocess.run(['git', *args], cwd=cwd, capture_output=True,
                          text=True, check=True).stdout


def make_worktree() -> str:
    """A throwaway checkout that carries the working tree's uncommitted state."""
    path = tempfile.mkdtemp(prefix='mutate-worktree-')
    os.rmdir(path)  # git worktree add wants to create it
    git('worktree', 'add', '--detach', path, 'HEAD')

    dirty = [f for f in git('diff', 'HEAD', '--name-only').split('\n') if f]
    untracked = [f for f in git('ls-files', '--others', '--exclude-standard').split('\n') if f]
    for rel in dirty + untracked:
        src, dst = os.path.join(ROOT, rel), os.path.join(path, rel)
        if not os.path.exists(src):
            # HEAD にあって手元で消したもの。worktree 側も消します。
            if os.path.exists(dst):
                os.remove(dst)
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
    if dirty or untracked:
        print(f'  未コミットの変更 {len(dirty) + len(untracked)} 件を写しました')

    for rel in LINKED:
        src = os.path.join(ROOT, rel)
        if os.path.isdir(src):
            dst = os.path.join(path, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                os.symlink(src, dst)
    return path


def drop_worktree(path: str) -> None:
    subprocess.run(['git', 'worktree', 'remove', '--force', path],
                   cwd=ROOT, capture_output=True)
    shutil.rmtree(path, ignore_errors=True)


def cleanup_on_exit(path: str) -> None:
    """Remove the worktree even when this process is killed.

    `finally` は SIGTERM では走りません。実際に timeout(1) が 90分で
    落としたとき、worktree が /tmp に残りました — ハーネス自身が journal で
    直したのと同じ穴を、その外側で作っていたわけです。**片方を直しても、
    もう片方は直りません。**
    """
    atexit.register(drop_worktree, path)

    def on_signal(signum, _frame):
        drop_worktree(path)
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(s, on_signal)
        except (ValueError, OSError):
            pass


def specs() -> list[str]:
    return sorted(
        f[:-3] for f in os.listdir(SPECS)
        if f.endswith('.py') and not f.startswith('_')
    )


def load(name):
    """Import a spec module without running it."""
    spec = importlib.util.spec_from_file_location(
        f'_mutspec_{name}', os.path.join(SPECS, name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check(want: list[str]) -> int:
    """Do the specs still describe the tree they were written against?"""
    stale = 0
    for name in want:
        cases = load(name).CASES
        misses = []
        for rel, old, _new, label in cases:
            path = os.path.join(ROOT, rel)
            try:
                with open(path, encoding='utf-8') as f:
                    src = f.read()
            except FileNotFoundError:
                misses.append(f'{label} — {rel} がありません')
                continue
            if old not in src:
                misses.append(f'{label} — {rel} に当たりません')
        print(f'  {"ok  " if not misses else "NG  "}{name} '
              f'({len(cases)} 件中 {len(misses)} 件が当たりません)')
        for m in misses:
            print(f'        {m}')
        stale += len(misses)
    if stale:
        print(f'\n{stale} 件の pattern が当たりません。対象が動いています。'
              '放っておくと、走らせるたびに全 SKIP で緑を返します')
        return 1
    print('\nすべての pattern が当たります')
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    only_check = '--check' in args
    isolated = '--isolated' in args
    want = [a for a in args if not a.startswith('-')] or specs()
    unknown = [w for w in want if w not in specs()]
    if unknown:
        print(f'そんな仕様書はありません: {", ".join(unknown)}')
        print(f'あるのは: {", ".join(specs())}')
        return 2

    if only_check:
        return check(want)

    specs_dir, worktree = SPECS, None
    if isolated:
        worktree = make_worktree()
        cleanup_on_exit(worktree)
        specs_dir = os.path.join(worktree, 'scripts', 'mutations')
        print(f'使い捨ての worktree: {worktree}')
        print('元の作業ツリーには触れません\n')

    results: list[tuple[str, int]] = []
    try:
        for name in want:
            print(f'\n{"=" * 70}\n{name}\n{"=" * 70}')
            r = subprocess.run([sys.executable, os.path.join(specs_dir, name + '.py')])
            results.append((name, r.returncode))
    finally:
        if worktree:
            drop_worktree(worktree)

    print(f'\n{"=" * 70}')
    for name, code in results:
        print(f'  {"ok  " if code == 0 else "NG  "}{name}')
    failed = [n for n, c in results if c != 0]
    if failed:
        print(f'\n{len(failed)} 本が失敗しました: {", ".join(failed)}')
        return 1
    print(f'\n{len(results)} 本すべて通りました')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

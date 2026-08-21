#!/usr/bin/env python3
"""Mutation harness that survives being killed.

このキャンペーンで検査を書くたびに、その検査自身を変異させて「落ちること」
を確かめてきました。手順は毎回同じです — 元の内容を控える、1箇所だけ壊す、
検査を走らせる、戻す。

戻すのを try/finally に置いていました。**SIGKILL では finally は走りません。**
実際に2回、削られた行がソースに残ったまま次の作業に進み、次のベースラインが
赤くなって初めて気づきました。気づけたのは運で、赤くならない壊し方だったら
気づきません。**検査を壊したまま気づかない状態が、いちばん高くつきます** —
以後どの実行も「違反0件」と報告し、それは正しく見えます。

ここでの答えは journal です。壊す前に「何をどう戻すか」をディスクに書いて
fsync します。次回の起動時にそれが残っていれば、何よりも先に戻します。
プロセスが消えても、ファイルは残ります。

守れない窓は、journal を書いてから最初のバイトを書き換えるまでの一瞬だけ
です。捕まえられるシグナル (SIGINT / SIGTERM) と正常終了は、そのうえで
今まで通り処理します。

使い方:

    from mutate import Harness

    h = Harness(root='/path/to/repo', cmd=['go', 'test', './...'], cwd='server')
    h.run([
        ('internal/foo.go', 'old text', 'new text', 'what this breaks'),
    ])
"""
from __future__ import annotations

import atexit
import json
import os
import signal
import subprocess
import sys
import tempfile

JOURNAL = '.mutate-journal.json'

# ビルドが壊れただけの変異。検査が落ちたのではないので、kill には数えません。
BUILD_MARKERS = (
    'syntax error', 'declared and not used', 'undefined:', '[build failed]',
    'not enough return values', 'too many return values', 'assignment mismatch',
    'cannot use', 'imported and not used', 'missing return',
    'Transform failed', 'Failed to load', 'SyntaxError',
)


def _read(path: str) -> str:
    with open(path, encoding='utf-8') as f:
        return f.read()


def _write(path: str, text: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def _drop_pyc(path: str) -> None:
    """Delete the compiled copy of a restored .py file.

    ソースを戻しても、**変異から作られた .pyc が残ります。** Python は
    mtime と size で古さを判定しますが、mtime の分解能は1秒で、
    ハーネスは1秒のあいだに「壊す → 走らせる → 戻す」を終えることが
    あります。そうなると次の実行は、戻したはずのソースではなく、
    壊れたままの .pyc を読みます。

    実際に起きました。19件すべて kill と出た直後の baseline が赤く、
    ソースを diff しても何も無く、__pycache__ を消したら通りました。
    **戻したのはソースだけで、動くものは戻っていませんでした。**
    """
    if not path.endswith('.py'):
        return
    d, name = os.path.split(path)
    cache = os.path.join(d, '__pycache__')
    if not os.path.isdir(cache):
        return
    stem = name[:-3]
    for f in os.listdir(cache):
        if f.startswith(stem + '.') and f.endswith('.pyc'):
            try:
                os.unlink(os.path.join(cache, f))
            except OSError:
                pass


class Harness:
    def __init__(self, root: str, cmd: list[str], cwd: str = '.',
                 build_markers: tuple[str, ...] = BUILD_MARKERS,
                 strict: bool = True):
        self.root = os.path.abspath(root)
        self.cmd = cmd
        # この配置に無いファイル（NOT_SHIPPED）。飛ばした理由を出すため。
        self._absent: set[str] = set()
        self.cwd = os.path.join(self.root, cwd)
        self.build_markers = build_markers
        # strict: 生き残った変異と、当たらなくなった変異を失敗として扱います。
        #
        # 当たらない変異 (SKIP) を「問題なし」にしておくと、対象が動いた
        # 仕様書は静かに全 SKIP になり、走らせるたびに緑を返します。
        # 「この検査は壊せない」と「この検査を壊してみていない」が同じ形に
        # なるのは、このキャンペーンが扱っている失敗そのものです。
        self.strict = strict
        self.journal_path = os.path.join(self.root, JOURNAL)
        self._pending: dict[str, str] = {}
        self._installed = False

    # ── journal ──────────────────────────────────────────────────────────────

    def _write_journal(self, entries: dict[str, str]) -> None:
        """Write the restore instructions and make sure they are on disk.

        一時ファイルに書いて fsync し、os.replace で差し替えます。途中で
        落ちても、journal は「前の完全な内容」か「新しい完全な内容」の
        どちらかで、半端な状態になりません。
        """
        d = os.path.dirname(self.journal_path)
        fd, tmp = tempfile.mkstemp(dir=d, prefix='.mutate-', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(entries, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.journal_path)
            dirfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def _clear_journal(self) -> None:
        self._pending = {}
        if os.path.exists(self.journal_path):
            os.unlink(self.journal_path)

    def recover(self) -> list[str]:
        """Undo anything a previous run left behind. Returns what it restored."""
        if not os.path.exists(self.journal_path):
            return []
        with open(self.journal_path, encoding='utf-8') as f:
            entries = json.load(f)
        restored = []
        for rel, original in entries.items():
            path = os.path.join(self.root, rel)
            try:
                current = _read(path)
            except FileNotFoundError:
                current = None
            if current != original:
                _write(path, original)
                _drop_pyc(path)
                restored.append(rel)
        self._clear_journal()
        return restored

    # ── one mutation ─────────────────────────────────────────────────────────

    def _apply(self, rel: str, old: str, new: str) -> bool:
        path = os.path.join(self.root, rel)
        # **同梱されないファイルは、落ちるのではなく飛ばします。**
        # 生成器はこのリポジトリに配らないファイルを決めており
        # (scripts/mutations/NOT_SHIPPED.txt)、`--check` は前からそれを
        # 許していました。**実行側だけが FileNotFoundError で止まって
        # いました** —— 同じものを、片方は許し片方は落とす形でした。
        # 飛ばしたことは呼び出し側が「なぜ」まで出します。
        if not os.path.exists(path):
            self._absent.add(rel)
            return False
        src = _read(path)
        if old not in src:
            return False
        # journal が先。壊すのは、戻し方がディスクに乗ってからです。
        self._pending = {rel: src}
        self._write_journal(self._pending)
        _write(path, src.replace(old, new, 1))
        return True

    def _restore(self) -> None:
        for rel, original in self._pending.items():
            path = os.path.join(self.root, rel)
            _write(path, original)
            _drop_pyc(path)
        self._clear_journal()

    # ── signals ──────────────────────────────────────────────────────────────

    def _install_handlers(self) -> None:
        if self._installed:
            return
        self._installed = True
        atexit.register(self._restore)

        def on_signal(signum, _frame):
            self._restore()
            # 既定の動作で終わります。ここで sys.exit すると、呼び出し側の
            # シェルには「正常終了」に見えます。
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(s, on_signal)
            except (ValueError, OSError):
                pass

    # ── running ──────────────────────────────────────────────────────────────

    def _run_tests(self) -> tuple[bool, str]:
        r = subprocess.run(self.cmd, cwd=self.cwd, capture_output=True)
        out = (r.stdout + r.stderr).decode('utf-8', 'replace')
        return r.returncode == 0, out

    def run(self, cases: list[tuple[str, str, str, str]]) -> int:
        recovered = self.recover()
        if recovered:
            print('前回の実行が戻し切れていませんでした。先に復元しました:')
            for r in recovered:
                print(f'    {r}')
            print()
        self._install_handlers()

        ok, out = self._run_tests()
        if not ok:
            print('baseline is already red; aborting')
            print(out[-3000:])
            return 1
        print('baseline green\n')

        killed = survived = notakill = skipped = notshipped = 0
        for rel, old, new, label in cases:
            if not self._apply(rel, old, new):
                if rel in self._absent:
                    # **この配置に無いだけです。仕様書は壊れていません。**
                    notshipped += 1
                    print(f'  SKIP (この配置に同梱されていません)  {label}')
                else:
                    skipped += 1
                    print(f'  SKIP (pattern absent)  {label}')
                continue
            try:
                green, out = self._run_tests()
                build = any(m in out for m in self.build_markers)
                if not green and build:
                    notakill += 1
                    print(f'  NOT-A-KILL (build)     {label}')
                elif green:
                    survived += 1
                    print(f'  SURVIVED               {label}')
                else:
                    killed += 1
                    print(f'  killed                 {label}')
            finally:
                self._restore()

        print(f'\nkilled={killed} survived={survived} '
              f'not-a-kill={notakill} skipped={skipped} '
              f'not-shipped={notshipped}')
        ok, _ = self._run_tests()
        print('restored green' if ok else 'RESTORE FAILED')

        # 生き残りは失敗です。以前はここで 0 を返していたので、変異が
        # 素通りしても呼び出し側は成功として扱えました。仕様書を CI に
        # 載せるなら、そこが逆だと意味がありません。
        bad = []
        if not ok:
            bad.append('復元後のベースラインが赤いままです')
        if survived:
            bad.append(f'{survived} 件の変異が生き残りました')
        # **同梱されていないぶんは失敗にしません。** 仕様書が壊れて
        # いるのではなく、この配置にそのファイルが配られていないだけです
        # （scripts/mutations/NOT_SHIPPED.txt）。`--check` は前からこの 2 つを
        # 区別していて、実行側だけが一緒くたにしていました。
        #
        # **数は出します。** 黙って飛ばすと、配られなくなったゲートが
        # 「通った」と見分けが付かなくなります。
        if self.strict and skipped:
            bad.append(f'{skipped} 件の変異が当たりませんでした'
                       '（対象が動いています。仕様書を直してください）')
        if bad:
            print('NG: ' + ' / '.join(bad))
            return 1
        return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == '--recover':
        root = argv[2] if len(argv) > 2 else '.'
        h = Harness(root=root, cmd=['true'])
        restored = h.recover()
        if restored:
            print('復元しました:')
            for r in restored:
                print(f'    {r}')
        else:
            print('残っている変異はありません')
        return 0
    print(__doc__)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

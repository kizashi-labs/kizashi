#!/usr/bin/env python3
"""Does the harness actually survive being killed?

`python3 scripts/mutate_test.py` で走ります。CI からは
`.github/workflows/ci.yml` の scripts ジョブが呼びます。

いちばん大事なのは TestSurvivesSigkill です。journal を使う理由がそれで、
使えているかどうかは、本当に SIGKILL してみないと分かりません。
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from mutate import JOURNAL, Harness, _read, _write  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.target = os.path.join(self.dir, 'subject.txt')
        _write(self.target, 'ORIGINAL\n')

    def journal(self):
        return os.path.join(self.dir, JOURNAL)

    def read(self):
        return _read(self.target)


class TestNormalRun(Base):
    def test_restores_after_each_case(self):
        h = Harness(root=self.dir, cmd=['false'])  # 常に赤 = 常に killed
        rc = h.run([('subject.txt', 'ORIGINAL', 'BROKEN', 'x')])
        # baseline が赤なので中断します。それでも元のままであること。
        self.assertEqual(self.read(), 'ORIGINAL\n')
        self.assertEqual(rc, 1)

    def test_a_case_that_kills_leaves_the_file_alone(self):
        # 変異したときだけ赤くなるテストを用意します。
        checker = os.path.join(self.dir, 'check.sh')
        open(checker, 'w', encoding='utf-8').write(
            '#!/bin/sh\ngrep -q ORIGINAL "$1"\n')
        os.chmod(checker, 0o755)
        h = Harness(root=self.dir, cmd=[checker, self.target])
        rc = h.run([('subject.txt', 'ORIGINAL', 'BROKEN', 'x')])
        self.assertEqual(self.read(), 'ORIGINAL\n')
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.journal()))


class TestRecovery(Base):
    def test_recovers_a_leftover_mutation(self):
        # 前回の実行が残した状態を手で作ります。
        _write(self.target, 'BROKEN\n')
        with open(self.journal(), 'w', encoding='utf-8') as f:
            json.dump({'subject.txt': 'ORIGINAL\n'}, f)

        h = Harness(root=self.dir, cmd=['true'])
        restored = h.recover()

        self.assertEqual(restored, ['subject.txt'])
        self.assertEqual(self.read(), 'ORIGINAL\n')
        self.assertFalse(os.path.exists(self.journal()))

    def test_recovery_runs_before_the_baseline(self):
        """残った変異を先に戻さないと、baseline がその変異を「元の姿」にします。

        これが journal の要点です。戻し損ねた実行のあと、次の実行は壊れた
        コードを基準として受け入れ、以後どの変異も「元から赤い」ことに
        なります。
        """
        _write(self.target, 'BROKEN\n')
        with open(self.journal(), 'w', encoding='utf-8') as f:
            json.dump({'subject.txt': 'ORIGINAL\n'}, f)

        checker = os.path.join(self.dir, 'check.sh')
        open(checker, 'w', encoding='utf-8').write(
            '#!/bin/sh\ngrep -q ORIGINAL "$1"\n')
        os.chmod(checker, 0o755)

        h = Harness(root=self.dir, cmd=[checker, self.target])
        rc = h.run([])
        self.assertEqual(rc, 0)          # baseline は緑に戻っている
        self.assertEqual(self.read(), 'ORIGINAL\n')

    def test_recovery_leaves_an_untouched_file_alone(self):
        with open(self.journal(), 'w', encoding='utf-8') as f:
            json.dump({'subject.txt': 'ORIGINAL\n'}, f)
        mtime = os.stat(self.target).st_mtime_ns
        time.sleep(0.01)

        h = Harness(root=self.dir, cmd=['true'])
        self.assertEqual(h.recover(), [])  # 中身が同じなら書き戻さない
        self.assertEqual(os.stat(self.target).st_mtime_ns, mtime)


class TestSurvivesSigkill(Base):
    """本題。finally が走らない殺され方をしても、次回に戻せること。"""

    def test_journal_is_on_disk_before_the_file_is_touched(self):
        script = textwrap.dedent(f'''
            import sys, os, time
            sys.path.insert(0, {HERE!r})
            from mutate import Harness
            h = Harness(root={self.dir!r}, cmd=['sleep', '30'])
            h._apply('subject.txt', 'ORIGINAL', 'BROKEN')
            # ここで殺されます。finally も atexit も走りません。
            time.sleep(30)
        ''')
        p = subprocess.Popen([sys.executable, '-c', script])
        try:
            # 変異が当たるまで待ちます。
            for _ in range(500):
                if self.read() == 'BROKEN\n':
                    break
                time.sleep(0.01)
            self.assertEqual(self.read(), 'BROKEN\n', '変異が当たっていません')
            os.kill(p.pid, signal.SIGKILL)
            p.wait(timeout=10)
        finally:
            if p.poll() is None:
                p.kill()

        # SIGKILL の直後: ファイルは壊れたまま、journal は残っている。
        self.assertEqual(self.read(), 'BROKEN\n')
        self.assertTrue(os.path.exists(self.journal()),
                        'journal がありません。次回の復元が効きません')

        # 次の実行が、何よりも先に戻すこと。
        h = Harness(root=self.dir, cmd=['true'])
        self.assertEqual(h.recover(), ['subject.txt'])
        self.assertEqual(self.read(), 'ORIGINAL\n')

    def test_sigterm_restores_immediately(self):
        """捕まえられるシグナルは、次回を待たずにその場で戻すこと。"""
        script = textwrap.dedent(f'''
            import sys, time
            sys.path.insert(0, {HERE!r})
            from mutate import Harness
            h = Harness(root={self.dir!r}, cmd=['sleep', '30'])
            h._install_handlers()
            h._apply('subject.txt', 'ORIGINAL', 'BROKEN')
            time.sleep(30)
        ''')
        p = subprocess.Popen([sys.executable, '-c', script])
        try:
            for _ in range(500):
                if self.read() == 'BROKEN\n':
                    break
                time.sleep(0.01)
            self.assertEqual(self.read(), 'BROKEN\n')
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=10)
        finally:
            if p.poll() is None:
                p.kill()

        self.assertEqual(self.read(), 'ORIGINAL\n')
        self.assertFalse(os.path.exists(self.journal()))


class TestOrdering(Base):
    """journal はファイルを壊す前に、ディスクに乗っていること。

    SIGKILL を投げる検査だけでは、この順序は確かめられません。_apply が
    戻ったあとに殺すので、どちらの順序でも journal は存在します。捕まえたい
    のは、その間で死んだ場合です。競争で当てるのではなく、ファイル書き込みを
    失敗させて確かめます。
    """

    def test_the_journal_exists_even_if_the_file_write_fails(self):
        import mutate

        real_write = mutate._write

        def failing_write(path, text):
            if path == self.target:
                raise OSError('disk full')
            real_write(path, text)

        mutate._write = failing_write
        try:
            h = Harness(root=self.dir, cmd=['true'])
            with self.assertRaises(OSError):
                h._apply('subject.txt', 'ORIGINAL', 'BROKEN')
        finally:
            mutate._write = real_write

        self.assertTrue(
            os.path.exists(self.journal()),
            'ファイルを壊す前に journal が書かれていません。'
            'この順序が逆だと、その一瞬で死んだときに戻す手がかりが残りません')
        with open(self.journal(), encoding='utf-8') as f:
            self.assertEqual(json.load(f), {'subject.txt': 'ORIGINAL\n'})


class TestCompiledCopyIsDropped(unittest.TestCase):
    """ソースを戻したら、そこから作られた .pyc も消えていること。

    Python は mtime(1秒精度) と size で .pyc の古さを見ます。ハーネスは
    1秒のうちに「壊す → 走らせる → 戻す」を終えることがあり、そのとき
    次の実行は戻したソースではなく壊れたままの .pyc を読みます。

    実際に起きました。19件すべて kill と出た直後の baseline が赤く、
    ソースの diff は空で、__pycache__ を消したら通りました。
    **戻したのはソースだけで、動くものは戻っていませんでした。**
    """

    def test_restore_removes_the_pyc(self):
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, 'subject.py')
            open(src, 'w', encoding='utf-8').write('VALUE = 1\n')
            cache = os.path.join(root, '__pycache__')
            os.makedirs(cache)
            pyc = os.path.join(cache, 'subject.cpython-311.pyc')
            open(pyc, 'wb').write(b'stale')

            h = Harness(root=root, cmd=['true'])
            self.assertTrue(h._apply('subject.py', 'VALUE = 1', 'VALUE = 2'))
            h._restore()

            self.assertEqual(open(src, encoding='utf-8').read(), 'VALUE = 1\n')
            self.assertFalse(os.path.exists(pyc),
                             'ソースは戻ったのに .pyc が残っています')

    def test_it_leaves_other_files_alone(self):
        """同じ __pycache__ にある別モジュールまで消さないこと。"""
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, 'subject.py')
            open(src, 'w', encoding='utf-8').write('VALUE = 1\n')
            cache = os.path.join(root, '__pycache__')
            os.makedirs(cache)
            mine = os.path.join(cache, 'subject.cpython-311.pyc')
            theirs = os.path.join(cache, 'other.cpython-311.pyc')
            # 前方一致だけで消すと subject_helper まで巻き添えになります。
            neighbour = os.path.join(cache, 'subject_helper.cpython-311.pyc')
            for p in (mine, theirs, neighbour):
                open(p, 'wb').write(b'x')

            h = Harness(root=root, cmd=['true'])
            h._apply('subject.py', 'VALUE = 1', 'VALUE = 2')
            h._restore()

            self.assertFalse(os.path.exists(mine))
            self.assertTrue(os.path.exists(theirs), 'other.pyc まで消しています')
            self.assertTrue(os.path.exists(neighbour),
                            'subject_helper.pyc まで消しています')

    def test_a_non_python_file_is_not_a_problem(self):
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, 'subject.go')
            open(src, 'w', encoding='utf-8').write('x\n')
            h = Harness(root=root, cmd=['true'])
            h._apply('subject.go', 'x', 'y')
            h._restore()
            self.assertEqual(open(src, encoding='utf-8').read(), 'x\n')


class TestDurability(unittest.TestCase):
    """journal を fsync していること。

    これはプロセス内では確かめられません。fsync を外しても、同じプロセス
    からも次のプロセスからもファイルは読めます。差が出るのは電源が落ちた
    ときだけで、それは単体テストの外です。

    実測できないので、代わりに実装を読みます。弱い検査であることは承知の
    うえで、変異が素通りするよりはましだという判断です。逆向きの対照を
    付けて、判定そのものが骨抜きにならないようにしてあります。
    """

    def _body(self):
        src = _read(os.path.join(HERE, 'mutate.py'))
        at = src.index('def _write_journal(')
        end = src.index('\n    def ', at)
        return src[at:end]

    def test_the_journal_write_is_fsynced(self):
        body = self._body()
        for needle in ('os.fsync(f.fileno())', 'os.replace(', 'os.fsync(dirfd)'):
            self.assertIn(needle, body,
                          f'{needle} がありません。journal がディスクに残る保証が消えます')

    def test_the_check_would_notice_a_write_without_fsync(self):
        naive = "def _write_journal(self, entries):\n    _write(self.journal_path, json.dumps(entries))\n"
        missing = [n for n in ('os.fsync(f.fileno())', 'os.replace(', 'os.fsync(dirfd)')
                   if n not in naive]
        self.assertEqual(len(missing), 3, '判定が実装を見ていません')


class TestExitCode(Base):
    """生き残りと空振りは失敗であること。

    以前はどちらも 0 を返していました。仕様書を CI に載せるなら、変異が
    素通りしても緑になるのでは意味がありません。空振り (SKIP) はもっと
    静かで、対象が動いた仕様書は全 SKIP のまま毎回緑を返します —
    「壊せない検査」と「壊してみていない検査」が同じ形になります。
    """

    def _always_green(self):
        return Harness(root=self.dir, cmd=['true'])

    def test_a_survivor_fails_the_run(self):
        h = self._always_green()
        rc = h.run([('subject.txt', 'ORIGINAL', 'BROKEN', 'x')])
        self.assertEqual(rc, 1)
        self.assertEqual(self.read(), 'ORIGINAL\n')

    def test_a_pattern_that_no_longer_matches_fails_the_run(self):
        h = self._always_green()
        rc = h.run([('subject.txt', 'NOT PRESENT', 'x', 'stale case')])
        self.assertEqual(rc, 1)

    def test_a_stale_pattern_passes_when_strict_is_off(self):
        h = Harness(root=self.dir, cmd=['true'], strict=False)
        self.assertEqual(h.run([('subject.txt', 'NOT PRESENT', 'x', 'x')]), 0)

    def test_all_killed_passes(self):
        checker = os.path.join(self.dir, 'check.sh')
        _write(checker, '#!/bin/sh\ngrep -q ORIGINAL "$1"\n')
        os.chmod(checker, 0o755)
        h = Harness(root=self.dir, cmd=[checker, self.target])
        self.assertEqual(h.run([('subject.txt', 'ORIGINAL', 'BROKEN', 'x')]), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

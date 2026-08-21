#!/usr/bin/env python3
"""after_snapshot.py の**順番と、落ちたときの振る舞い**を留める。

この道具が守っているのは順番そのものです。**順番が入れ替わっても、
3 本とも 0 を返すので、出力は成功と見分けが付きません。** 実際に壊れる
のは次の同期で、そのときには変異仕様書が全 SKIP で緑を返しています。

`python3 scripts/after_snapshot_test.py` で走ります。
"""
from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import after_snapshot as A  # noqa: E402


class Recorder:
    """呼ばれたものを順に記録する `run_step` の替え玉。"""

    def __init__(self, codes: dict[str, int] | None = None) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.codes = codes or {}

    def __call__(self, script: str, args: list[str]) -> int:
        self.calls.append((script, tuple(args)))
        return self.codes.get(script, 0)

    @property
    def scripts(self) -> list[str]:
        return [s for s, _ in self.calls]


class Case(unittest.TestCase):
    def run_main(self, rec: Recorder, *argv: str) -> int:
        real, A.run_step = A.run_step, rec
        try:
            with redirect_stdout(io.StringIO()) as out:
                code = A.main(['after_snapshot.py', *argv])
        finally:
            A.run_step = real
        self.out = out.getvalue()
        return code


class TestTheOrder(Case):
    def test_the_three_run_in_the_documented_order(self):
        """**2 → 3 が逆だと、下げた瞬間に変異仕様書が死にます。**"""
        rec = Recorder()
        self.assertEqual(self.run_main(rec, '--apply'), 0)
        self.assertEqual(rec.scripts, [
            'handover_timeouts.py',
            'recalibrate_ratchets.py',
            'reanchor_mutations.py',
        ])

    def test_apply_passes_the_writing_arguments(self):
        rec = Recorder()
        self.run_main(rec, '--apply')
        self.assertEqual(dict(rec.calls), {
            'handover_timeouts.py': ('--restore',),
            'recalibrate_ratchets.py': ('--apply',),
            'reanchor_mutations.py': ('--apply',),
        })

    def test_without_apply_nothing_is_written(self):
        """**見るだけの経路に `--apply` が混ざったら、確かめる手段が消えます。**"""
        rec = Recorder()
        self.run_main(rec)
        for script, args in rec.calls:
            self.assertNotIn('--apply', args, script)
            self.assertNotIn('--restore', args, script)
        self.assertEqual(dict(rec.calls)['handover_timeouts.py'], ('--check',))


class TestWhenAStepFails(Case):
    def test_a_failure_is_reported_and_the_exit_code_is_not_zero(self):
        rec = Recorder({'handover_timeouts.py': 1})
        self.assertEqual(self.run_main(rec, '--apply'), 1)
        self.assertIn('timeout-minutes を戻す', self.out)

    def test_a_failure_in_step_one_does_not_stop_the_others(self):
        """1 は 2 と 3 の前提ではありません。**まとめて報告します。**"""
        rec = Recorder({'handover_timeouts.py': 1})
        self.run_main(rec, '--apply')
        self.assertEqual(rec.scripts, [
            'handover_timeouts.py',
            'recalibrate_ratchets.py',
            'reanchor_mutations.py',
        ])

    def test_reanchor_does_not_run_when_recalibrate_fails(self):
        """**下がっていない値に pattern を合わせても意味がありません。**

        合わせた記録だけが残るほうが悪い —— 次の生成で、誰も
        「まだ下がっていない」ことに気づけません。
        """
        rec = Recorder({'recalibrate_ratchets.py': 2})
        self.assertEqual(self.run_main(rec, '--apply'), 1)
        self.assertEqual(rec.scripts,
                         ['handover_timeouts.py', 'recalibrate_ratchets.py'])
        self.assertIn('走らせません', self.out)

    def test_every_failure_is_named(self):
        rec = Recorder({'handover_timeouts.py': 1, 'recalibrate_ratchets.py': 1})
        self.run_main(rec, '--apply')
        self.assertIn('timeout-minutes を戻す', self.out)
        self.assertIn('ラチェットの固定値を下げる', self.out)
        self.assertIn('変異仕様書の pattern を追随させる', self.out)


class TestTheArguments(Case):
    def test_an_unknown_argument_prints_the_usage_and_fails(self):
        """**黙って既定の動作にしません。** `--dry-run` のつもりが
        `--apply` 相当で走るのが、いちばん高くつく取り違えです。
        """
        rec = Recorder()
        self.assertEqual(self.run_main(rec, '--dry-run'), 1)
        self.assertEqual(rec.calls, [])


class TestTheStepsMatchTheRepository(unittest.TestCase):
    def test_every_script_it_calls_exists(self):
        """**呼ぶ先が消えたら、この道具は次の生成で初めて落ちます。**"""
        for _, script, _, _ in A.STEPS:
            self.assertTrue(os.path.exists(os.path.join(HERE, script)), script)

    def test_the_dependency_points_at_recalibrate_and_reanchor(self):
        """依存の向きを、番号ではなく**名前**で確かめます。"""
        self.assertEqual(A.DEPENDS_ON, {2: 1})
        self.assertEqual(A.STEPS[1][1], 'recalibrate_ratchets.py')
        self.assertEqual(A.STEPS[2][1], 'reanchor_mutations.py')


if __name__ == '__main__':
    unittest.main(verbosity=2)

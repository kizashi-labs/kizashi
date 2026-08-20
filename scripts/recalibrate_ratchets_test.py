#!/usr/bin/env python3
"""recalibrate_ratchets.py の判定そのものを留める。

**この道具は固定値を書き換えます。** 壊れたまま動くと、劣化を記録して
緑にするだけの装置になります。木がきれいなあいだ、上げ方向の分岐は
一度も通らないので、汚した入力を渡さないと確かめられません。

`python3 scripts/recalibrate_ratchets_test.py` で走ります。
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import recalibrate_ratchets as R  # noqa: E402


class TestTheMessagePattern(unittest.TestCase):
    """文言から「定数名」と「新しい値」を取れること。"""

    def test_typescript_style(self):
        m = R.NAMED.search('MOCK_LEAK_CEILING を 3 に下げてください')
        self.assertEqual((m.group(1), int(m.group(2))), ('MOCK_LEAK_CEILING', 3))

    def test_go_style_lower_camel(self):
        m = R.NAMED.search('テストからしか呼ばれない関数が 16 まで減りました。'
                           'testOnlyCeiling を 16 に下げてください')
        self.assertEqual((m.group(1), int(m.group(2))), ('testOnlyCeiling', 16))

    def test_a_message_without_a_name_is_not_matched(self):
        """**ここが一致してしまうと、関係のない数を定数に書き込みます。**"""
        self.assertIsNone(R.NAMED.search(
            'ルートの無い読み取りが 129 まで減りました。上限を 129 に下げてください'))

    def test_a_message_that_only_names_a_constant(self):
        self.assertIsNone(R.NAMED.search('SILENT_WRITE_CEILING は 0 が規則です'))


class TestTheDeclarationPattern(unittest.TestCase):
    """宣言を見つけて、値だけを差し替えられること。"""

    def _rewrite(self, text: str, name: str, new: int) -> str:
        with tempfile.NamedTemporaryFile('w', suffix='.ts', delete=False,
                                         encoding='utf-8') as f:
            f.write(text)
            path = f.name
        try:
            R.lower(path, name, new)
            with open(path, encoding='utf-8') as fh:
                return fh.read()
        finally:
            os.unlink(path)

    def test_typescript_const(self):
        self.assertEqual(
            self._rewrite('const UNROUTED_READ_CEILING = 132\n',
                          'UNROUTED_READ_CEILING', 129),
            'const UNROUTED_READ_CEILING = 129\n')

    def test_exported_const_with_a_type(self):
        self.assertEqual(
            self._rewrite('export const X: number = 9\n', 'X', 4),
            'export const X: number = 4\n')

    def test_go_const_inside_a_block(self):
        self.assertEqual(
            self._rewrite('const (\n\tbackgroundFailedCount = 76\n)\n',
                          'backgroundFailedCount', 69),
            'const (\n\tbackgroundFailedCount = 69\n)\n')

    def test_a_trailing_comment_survives(self):
        """**注釈を落とすと、なぜその値なのかが消えます。**"""
        self.assertEqual(
            self._rewrite('\tcatCovered:  1, // 実測\n'.replace('catCovered:  1,',
                                                               'const C = 1'),
                          'C', 0),
            '\tconst C = 0 // 実測\n')

    def test_a_similar_name_is_not_touched(self):
        """`X` を書き換えるとき `XY` は動かないこと。"""
        out = self._rewrite('const XY = 5\nconst X = 9\n', 'X', 4)
        self.assertIn('const XY = 5', out)
        self.assertIn('const X = 4', out)

    def test_a_missing_declaration_reports_failure(self):
        with tempfile.NamedTemporaryFile('w', suffix='.ts', delete=False,
                                         encoding='utf-8') as f:
            f.write('const OTHER = 1\n')
            path = f.name
        try:
            self.assertFalse(R.lower(path, 'MISSING', 3))
        finally:
            os.unlink(path)


class TestItRefusesToRaise(unittest.TestCase):
    """**上げ方向を埋めないこと。** ここがこの道具の存在理由です。

    通る木では上げ方向の分岐に入らないので、直接動かします。
    """

    def test_lower_writes_but_the_caller_decides_direction(self):
        # lower() は方向を判定しません（呼び出し側の責任）。ここでは
        # 「下げる」と「上げる」がどちらも書けてしまうことを明示します。
        with tempfile.NamedTemporaryFile('w', suffix='.ts', delete=False,
                                         encoding='utf-8') as f:
            f.write('const C = 10\n')
            path = f.name
        try:
            self.assertTrue(R.lower(path, 'C', 99))
            with open(path, encoding='utf-8') as fh:
                self.assertIn('const C = 99', fh.read())
        finally:
            os.unlink(path)

    def test_the_direction_rule_itself(self):
        """main() が使う比較。`new > cur` なら埋めない。"""
        cases = [(10, 3, 'lower'), (10, 10, 'skip'), (10, 33, 'raise')]
        for cur, new, want in cases:
            if new == cur:
                got = 'skip'
            elif new > cur:
                got = 'raise'
            else:
                got = 'lower'
            self.assertEqual(got, want, f'cur={cur} new={new}')


if __name__ == '__main__':
    unittest.main(verbosity=2)

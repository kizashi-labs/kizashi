#!/usr/bin/env python3
"""skip_report.py の判定そのものを確かめます。

    python3 scripts/skip_report_test.py

**数える道具が数え損ねても、出力は同じ形をしています。** 「飛んだ 0 本」は
「本当に0本」と「数えられていない」の両方に見えます。ここで固定するのは
その区別です。
"""
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from skip_report import normalize, parse, report  # noqa: E402


def events(*specs):
    """Build a `go test -json` stream. specs: (test, action, *output lines)."""
    out = []
    for test, action, *lines in specs:
        for line in lines:
            out.append(json.dumps({'Package': 'p', 'Test': test,
                                   'Action': 'output', 'Output': line}))
        out.append(json.dumps({'Package': 'p', 'Test': test, 'Action': action}))
    return out


def pkg(name, action):
    """A package-level event — no Test field."""
    return json.dumps({'Package': name, 'Action': action})


class TestCounting(unittest.TestCase):
    def test_counts_each_outcome(self):
        outcomes, _, _, _ = parse(events(
            ('A', 'pass'), ('B', 'fail'), ('C', 'skip', 'x_test.go:1: なし'),
        ))
        self.assertEqual((outcomes['pass'], outcomes['fail'], outcomes['skip']),
                         (1, 1, 1))

    def test_package_level_events_are_not_tests(self):
        """パッケージの ok/skip をテストとして数えないこと。

        数えると、テストが1本も無いパッケージが「1本通った」に化けます。
        """
        stream = [json.dumps({'Package': 'p', 'Action': 'pass'}),
                  json.dumps({'Package': 'q', 'Action': 'skip'})]
        outcomes, _, _, _ = parse(stream)
        self.assertEqual(sum(outcomes.values()), 0)

    def test_non_json_lines_are_ignored(self):
        """ビルドエラーなどの生の行が混ざっても数え続けること。"""
        stream = ['# github.com/x/y', 'vet: broken'] + events(('A', 'pass'))
        outcomes, _, _, _ = parse(stream)
        self.assertEqual(outcomes['pass'], 1)

    def test_reason_comes_from_the_output(self):
        _, reasons, _, _ = parse(events(
            ('A', 'skip', 'a_test.go:12: TEST_DATABASE_URL not set'),
        ))
        self.assertEqual(reasons['p.A'], 'TEST_DATABASE_URL not set')

    def test_a_skip_with_no_message_says_so(self):
        """理由の書かれていない skip を、無言で「その他」に混ぜないこと。"""
        _, reasons, _, _ = parse(events(('A', 'skip')))
        self.assertIn('理由が書かれていません', reasons['p.A'])


class TestBrokenPackages(unittest.TestCase):
    """ビルドできなかったパッケージを、静かに0本として通さないこと。

    **実際にこれで見落としました。** agent を -tags ebpf で測ったとき、
    2パッケージが [build failed] で落ちていたのに、この道具は
    「762 本中 飛んだ 1 本」と出して**きれいに見えました。** そこにあった
    94 本は「飛んだ」でも「落ちた」でもなく、最初から存在しませんでした。
    """

    def test_a_package_that_produced_no_tests_and_failed_is_broken(self):
        _, _, _, broken = parse([pkg('github.com/x/y', 'fail')])
        self.assertEqual(broken, ['github.com/x/y'])

    def test_a_package_whose_test_failed_is_not_broken(self):
        """テストが落ちたパッケージは、ビルドできています。

        ここを区別しないと、普通のテスト失敗が「ビルド不能」に化けて、
        **本物のビルド不能がその中に埋もれます。**
        """
        stream = events(('A', 'fail')) + [pkg('p', 'fail')]
        _, _, _, broken = parse(stream)
        self.assertEqual(broken, [])

    def test_broken_packages_fail_even_without_a_ceiling(self):
        from collections import Counter
        buf, old = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = report(Counter({'pass': 5}), Counter(), None, ['github.com/x/y'])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)
        self.assertIn('ビルドできなかった', buf.getvalue())

    def test_broken_packages_beat_a_satisfied_ceiling(self):
        """上限を満たしていても、ビルド不能があれば落ちること。

        **本数は、存在するテストについてしか言えません。**
        """
        from collections import Counter
        buf, old = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = report(Counter({'pass': 5, 'skip': 5}), Counter(), 5, ['github.com/x/y'])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)


class TestNormalize(unittest.TestCase):
    def test_groups_the_same_cause(self):
        a = normalize('x_test.go:31: DB に届きません: dial tcp 1.2.3.4:5432')
        b = normalize('y_test.go:99: DB に届きません: dial tcp 1.2.3.4:5432')
        self.assertEqual(a, b)

    def test_uuids_do_not_split_a_reason(self):
        a = normalize('agent 3f2504e0-4f89-41d3-9a0c-0305e82c3301 not seeded')
        b = normalize('agent 550e8400-e29b-41d4-a716-446655440000 not seeded')
        self.assertEqual(a, b)

    def test_distinct_causes_stay_distinct(self):
        """潰しすぎないこと。**全部同じ理由にすれば一覧は短くなります。**"""
        a = normalize('TEST_DATABASE_URL not set')
        b = normalize('GeoIP database not available')
        self.assertNotEqual(a, b)


class TestCeiling(unittest.TestCase):
    def run_report(self, skips, ceiling):
        outcomes = {'pass': 10, 'fail': 0, 'skip': skips}
        from collections import Counter
        buf, old = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            return report(Counter(outcomes), Counter(), ceiling, [])
        finally:
            sys.stdout = old

    def test_exact_is_ok(self):
        self.assertEqual(self.run_report(5, 5), 0)

    def test_more_fails(self):
        self.assertEqual(self.run_report(6, 5), 1)

    def test_fewer_also_fails(self):
        """**減っても落ちること。** 下げないと、次に増えた分が差に隠れます。"""
        self.assertEqual(self.run_report(4, 5), 1)

    def test_no_ceiling_only_reports(self):
        self.assertEqual(self.run_report(900, None), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

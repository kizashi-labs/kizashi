#!/usr/bin/env python3
"""Drive the prometheus-rule check directly.

木がきれいな状態では、判定はどの肯定側の分岐にも入りません。見つけるものが
無い走査と、どこも見ていない走査は、出力が同じです。

`python3 scripts/check_prometheus_rules_test.py` で走ります。
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_prometheus_rules  # noqa: E402
from check_prometheus_rules import (  # noqa: E402
    _matcher_names, alerting_problems, collect, collect_alerting,
    collect_runbook, problems, prometheus_mounts, runbook_problems,
    runbook_sections,
)

RULES = {'groups': [{'name': 'g', 'rules': [
    {'alert': 'A', 'expr': 'edr_thing_total > 0'},
]}]}


class TestTheRuleFires(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(
            problems(['/c/a.yml'], {'/c/a.yml': 'deploy/a.yml'},
                     {'deploy/a.yml': RULES}),
            [])

    def test_referenced_but_not_mounted(self):
        found = problems(['/c/missing.yml'], {}, {})
        self.assertEqual(len(found), 1)
        self.assertIn('起動時に失敗', found[0])

    def test_mounted_but_not_referenced(self):
        """prometheus_alerts.yml がこれでした。19本が一度も評価されません。"""
        found = problems([], {'/c/a.yml': 'deploy/a.yml'},
                         {'deploy/a.yml': RULES})
        self.assertEqual(len(found), 1)
        self.assertIn('一度も評価されません', found[0])
        self.assertIn('1本', found[0])

    def test_a_mounted_non_rule_file_is_not_a_problem(self):
        """prometheus.yml 自体もマウントされています。ルールではありません。"""
        self.assertEqual(
            problems([], {'/c/prometheus.yml': 'deploy/prometheus.yml'},
                     {'deploy/prometheus.yml': {'scrape_configs': []}}),
            [])

    def test_names_differing_only_in_case(self):
        """EDRApiHighLatency と EDRAPIHighLatency が実際にこれでした。

        完全一致しか見ていないと「重複なし」です。Prometheus も別物として
        扱うので上書きは起きず、**両方が発火します。** 通知を繋いだ瞬間に、
        1つの事象で2通届きます。
        """
        other = {'groups': [{'name': 'g2', 'rules': [
            {'alert': 'a', 'expr': 'edr_thing_total > 1'},
        ]}]}
        found = problems(['/c/a.yml', '/c/b.yml'],
                         {'/c/a.yml': 'deploy/a.yml', '/c/b.yml': 'deploy/b.yml'},
                         {'deploy/a.yml': RULES, 'deploy/b.yml': other})
        self.assertEqual(len(found), 1)
        self.assertIn('大文字小文字の違いだけ', found[0])

    def test_the_same_name_twice_is_not_reported_as_a_case_clash(self):
        """完全一致は「上書き」で、綴り違いは「2回発火」です。別の問題なので
        別の文言で出ます。同じ名前を両方で報告すると、読んだ人はどちらが
        起きているのか分かりません。"""
        found = problems(['/c/a.yml', '/c/b.yml'],
                         {'/c/a.yml': 'deploy/a.yml', '/c/b.yml': 'deploy/b.yml'},
                         {'deploy/a.yml': RULES, 'deploy/b.yml': RULES})
        self.assertEqual(len(found), 1)
        self.assertIn('静かに上書き', found[0])

    def test_duplicate_alert_names(self):
        dup = {'groups': [{'name': 'g2', 'rules': [{'alert': 'A', 'expr': 'edr_thing_total > 1'}]}]}
        found = problems(['/c/a.yml', '/c/b.yml'],
                         {'/c/a.yml': 'deploy/a.yml', '/c/b.yml': 'deploy/b.yml'},
                         {'deploy/a.yml': RULES, 'deploy/b.yml': dup})
        self.assertEqual(len(found), 1)
        self.assertIn('静かに上書き', found[0])


class TestMounts(unittest.TestCase):
    def test_reads_the_prometheus_service_only(self):
        compose = {'services': {
            'prometheus': {'volumes': ['./a.yml:/c/a.yml:ro']},
            'grafana': {'volumes': ['./b.yml:/c/b.yml:ro']},
        }}
        self.assertEqual(prometheus_mounts(compose), {'/c/a.yml': 'deploy/a.yml'})

    def test_named_volumes_are_ignored(self):
        compose = {'services': {'prometheus': {'volumes': ['prometheus_data:/prometheus']}}}
        self.assertEqual(prometheus_mounts(compose), {})


class TestMainActsOnWhatItFound(unittest.TestCase):
    """判定が問題を返しても、main がそれを無視したら出力は「ok」です。

    木がきれいなあいだ、この2つは見分けがつきません。問題が0件なら、
    無視する実装も無視しない実装も同じ0を返すからです。汚した木を
    渡さないと確かめられません。
    """

    def _main_with(self, referenced, mounts, docs):
        # 通知側も一緒に差し替えます。片方だけだと、合成の木を渡したつもりで
        # 実物の alertmanager.yml が混ざります。実際に混ざって、きれいな木の
        # 検査が落ちました。**「渡したもので判定している」つもりが、
        # 半分は実物でした。**
        real = check_prometheus_rules.collect
        real_alerting = check_prometheus_rules.collect_alerting
        real_runbook = check_prometheus_rules.collect_runbook
        check_prometheus_rules.collect = lambda: (referenced, mounts, docs)
        check_prometheus_rules.collect_alerting = lambda: ([], [], {}, set())
        check_prometheus_rules.collect_runbook = lambda: ({}, set())
        try:
            return check_prometheus_rules.main()
        finally:
            check_prometheus_rules.collect = real
            check_prometheus_rules.collect_alerting = real_alerting
            check_prometheus_rules.collect_runbook = real_runbook

    def test_a_problem_fails(self):
        self.assertEqual(self._main_with(['/c/missing.yml'], {}, {}), 1)

    def test_a_clean_tree_passes(self):
        self.assertEqual(
            self._main_with(['/c/a.yml'], {'/c/a.yml': 'deploy/a.yml'},
                            {'deploy/a.yml': RULES}),
            0)

    def test_a_runbook_problem_also_fails(self):
        """手順への行き先の判定を main が呼んでいること。呼ばなくても、
        木がきれいなあいだは 0 のままです。"""
        real = check_prometheus_rules.collect
        real_alerting = check_prometheus_rules.collect_alerting
        real_runbook = check_prometheus_rules.collect_runbook
        check_prometheus_rules.collect = lambda: (
            ['/c/a.yml'], {'/c/a.yml': 'deploy/a.yml'}, {'deploy/a.yml': RULES})
        check_prometheus_rules.collect_alerting = lambda: ([], [], {}, set())
        # 手順の無いところへリンクしている状態。
        check_prometheus_rules.collect_runbook = lambda: ({'A': 'http://x#a'}, set())
        try:
            self.assertEqual(check_prometheus_rules.main(), 1)
        finally:
            check_prometheus_rules.collect = real
            check_prometheus_rules.collect_alerting = real_alerting
            check_prometheus_rules.collect_runbook = real_runbook

    def test_an_alerting_problem_also_fails(self):
        """通知側の判定を main が呼んでいること。

        呼ばなくても、木がきれいなあいだは 0 のままです。**足した判定を
        main から外す変更が、変異で生き残りました。** ルールの側だけを
        汚しても捕まりません。汚すのは通知の側です。
        """
        real = check_prometheus_rules.collect
        real_alerting = check_prometheus_rules.collect_alerting
        check_prometheus_rules.collect = lambda: (
            ['/c/a.yml'], {'/c/a.yml': 'deploy/a.yml'}, {'deploy/a.yml': RULES})
        # alertmanager を指しているのに、そのサービスが無い状態。
        check_prometheus_rules.collect_alerting = lambda: (
            ['alertmanager:9093'], ['prometheus'], {}, set())
        try:
            self.assertEqual(check_prometheus_rules.main(), 1)
        finally:
            check_prometheus_rules.collect = real
            check_prometheus_rules.collect_alerting = real_alerting


# prometheus.yml が読むと言っていなければならないルールファイル。
#
# 一覧にしてあるのは、逆向きに確かめるためです。assertIn を並べると、
# 1行消すだけでその確認は消え、木がきれいなあいだは誰も気づけません
# — 実際、この検査を変異させたらそれが生き残りました。
REQUIRED_RULE_FILES = [
    '/etc/prometheus/alerts.yml',
    '/etc/prometheus/rules/edr-alerts.yml',
    '/etc/prometheus/rules/edr-recording-rules.yml',
]

REQUIRED_RULE_DOCS = ['prometheus_alerts.yml', 'edr-alerts.yml']


def missing_from(haystacks, required):
    return [r for r in required if not any(r in h for h in haystacks)]


class TestTheRealTree(unittest.TestCase):
    """走査が本物の設定に届いていること。合成入力だけだと、実物を1つも
    読んでいない判定でも全部通ります。"""

    def test_it_reads_the_actual_files(self):
        referenced, mounts, docs = collect()
        self.assertEqual(missing_from(referenced, REQUIRED_RULE_FILES), [])
        self.assertEqual(missing_from(docs, REQUIRED_RULE_DOCS), [])

    def test_the_required_lists_are_not_hollow(self):
        """一覧が空や短くなっていたら、上の確認は何でも通ります。

        求める答えをここに書き下しているのは、`missing_from([], LIST) ==
        LIST` だと一覧が空でも通ってしまうためです。**一覧そのものを
        期待値に使うと、一覧を消す変更を捕まえられません。**
        """
        self.assertEqual(missing_from([], REQUIRED_RULE_FILES), [
            '/etc/prometheus/alerts.yml',
            '/etc/prometheus/rules/edr-alerts.yml',
            '/etc/prometheus/rules/edr-recording-rules.yml',
        ])
        self.assertEqual(
            missing_from(['/etc/prometheus/alerts.yml'], REQUIRED_RULE_FILES), [
                '/etc/prometheus/rules/edr-alerts.yml',
                '/etc/prometheus/rules/edr-recording-rules.yml',
            ])
        self.assertEqual(missing_from([], REQUIRED_RULE_DOCS),
                         ['prometheus_alerts.yml', 'edr-alerts.yml'])


MIN_AM = {'route': {'receiver': 'a'}, 'receivers': [{'name': 'a'}]}


class TestTheAlertingRuleFires(unittest.TestCase):
    """通知の配線。ルールが読まれることと、発火が届くことは別です。

    alerting: がコメントのままだったあいだ、30本は評価され、発火し、
    Prometheus の画面に赤く出て、そこで終わっていました。
    「マウントされているが読まれない」と同じ形が、1段上にありました。
    """

    def test_clean(self):
        self.assertEqual(
            alerting_problems(['alertmanager:9093'], ['alertmanager'], MIN_AM, set()),
            [])

    def test_target_with_no_service(self):
        """これが直前の状態でした（サービスが無く、参照もコメント）。"""
        found = alerting_problems(['alertmanager:9093'], ['prometheus'], {}, set())
        self.assertEqual(len(found), 1)
        self.assertIn('誰にも届きません', found[0])

    def test_route_points_at_a_missing_receiver(self):
        found = alerting_problems([], [], {'route': {'receiver': 'nope'},
                                           'receivers': []}, set())
        self.assertEqual(len(found), 1)
        self.assertIn('定義がありません', found[0])

    def test_a_receiver_nobody_routes_to(self):
        """書いてあるのに何も送られない receiver。設定を読んだ人は
        「PagerDuty に出る」と思います。"""
        found = alerting_problems([], [], {'route': {'receiver': 'a'},
                                           'receivers': [{'name': 'a'}, {'name': 'b'}]},
                                  set())
        self.assertEqual(len(found), 1)
        self.assertIn('どの route からも使われていません', found[0])

    def test_a_nested_route_counts_as_using_a_receiver(self):
        """critical の振り分けは route.routes[] の中にあります。入れ子を
        たどらないと、実際に使っている receiver を「死んでいる」と言います。"""
        am = {'route': {'receiver': 'a', 'routes': [{'receiver': 'b'}]},
              'receivers': [{'name': 'a'}, {'name': 'b'}]}
        self.assertEqual(alerting_problems([], [], am, set()), [])

    def test_inhibit_naming_an_alert_that_does_not_exist(self):
        """アラート名を変えると、抑制は黙って効かなくなります。効かなく
        なったことは、通知が増えるまで誰も気づきません。"""
        am = dict(MIN_AM, inhibit_rules=[
            {'source_matchers': ['alertname = "Gone"'], 'target_matchers': []}])
        found = alerting_problems([], [], am, {'Real'})
        self.assertEqual(len(found), 1)
        self.assertIn('抑制は黙って効かなくなります', found[0])

    def test_inhibit_naming_alerts_that_exist(self):
        am = dict(MIN_AM, inhibit_rules=[
            {'source_matchers': ['alertname = "Real"'],
             'target_matchers': ['alertname =~ "Other|Third"']}])
        self.assertEqual(
            alerting_problems([], [], am, {'Real', 'Other', 'Third'}), [])

    def test_an_inlined_secret(self):
        am = {'route': {'receiver': 'a'}, 'receivers': [
            {'name': 'a', 'slack_configs': [{'api_url': 'https://hooks.slack.com/x'}]}]}
        found = alerting_problems([], [], am, set())
        self.assertEqual(len(found), 1)
        self.assertIn('リポジトリに秘密が入ります', found[0])

    def test_the_file_reference_form_is_fine(self):
        am = {'route': {'receiver': 'a'}, 'receivers': [
            {'name': 'a', 'slack_configs': [{'api_url_file': '/run/secrets/x'}]}]}
        self.assertEqual(alerting_problems([], [], am, set()), [])

    def test_no_alertmanager_config_is_not_a_crash(self):
        """設定ファイルがまだ無い状態でも、判定は落ちないこと。"""
        self.assertEqual(alerting_problems([], [], {}, set()), [])


class TestMatcherNames(unittest.TestCase):
    """正規表現の実体を名前として扱わないこと。当てずっぽうで
    「存在しない」と言うより、見ないほうがましです。"""

    def test_it_reads_names_and_skips_patterns(self):
        for text, want in [
            ('alertname = "X"', ['X']),
            ('alertname =~ "A|B"', ['A', 'B']),
            ('alertname =~ "EDRConsumerLag.*"', []),
            ('severity = "critical"', []),
            ('not a matcher', []),
        ]:
            self.assertEqual(_matcher_names([text]), want, text)


class TestTheRealAlertingTree(unittest.TestCase):
    """合成入力だけだと、実物を1つも読んでいない判定でも全部通ります。"""

    def test_it_reads_the_actual_wiring(self):
        targets, services, am, names = collect_alerting()
        self.assertIn('alertmanager:9093', targets)
        self.assertIn('alertmanager', services)
        self.assertIn('edr-slack', [r.get('name') for r in am.get('receivers', [])])
        self.assertGreater(len(am.get('inhibit_rules', [])), 0)
        self.assertGreater(len(names), 20)


class TestTheRunbookRuleFires(unittest.TestCase):
    """通知が指す手順が、実在すること。

    直す前の実測: 12本が wiki.internal を指し（このリポジトリのどこにも
    定義が無いホスト）、うち7本は**手順そのものが存在しません**でした。
    逆に手順があるのにリンクの無いアラートが4本、実在しないアラート宛ての
    手順が4つ。**指す側と指される側が、両方向にずれていました。**
    """

    def test_clean(self):
        self.assertEqual(runbook_problems({'A': 'http://x#a'}, {'A'}), [])

    def test_a_link_to_a_procedure_that_does_not_exist(self):
        found = runbook_problems({'A': 'http://x#a'}, set())
        self.assertEqual(len(found), 1)
        self.assertIn('障害の最中に開いて初めて分かります', found[0])

    def test_a_procedure_with_no_link(self):
        found = runbook_problems({'A': None}, {'A'})
        self.assertEqual(len(found), 1)
        self.assertIn('そこへ辿り着けません', found[0])

    def test_the_placeholder_host(self):
        found = runbook_problems({'A': 'https://wiki.internal/runbooks/a#a'}, {'A'})
        self.assertEqual(len(found), 1)
        self.assertIn('wiki.internal', found[0])

    def test_an_anchor_that_points_elsewhere(self):
        """ページは開きます。開いた先が違うだけです — 障害の最中に。"""
        found = runbook_problems({'A': 'http://x#somewhere-else'}, {'A'})
        self.assertEqual(len(found), 1)
        self.assertIn('別の場所に飛びます', found[0])

    def test_a_procedure_for_an_alert_that_does_not_exist(self):
        """EDRDatabaseDown / EDRDetectionEngineDown / EDRDetectionConsumerLag が
        これでした。改名前の名前のまま残り、誰も辿り着けません。"""
        found = runbook_problems({}, {'Ghost'})
        self.assertEqual(len(found), 1)
        self.assertIn('誰も辿り着かない手順です', found[0])

    def test_an_alert_with_neither_is_not_a_problem(self):
        """手順が無く、リンクも無いのは、ずれてはいません。"""
        self.assertEqual(runbook_problems({'A': None}, set()), [])

    def test_headings_that_are_not_alert_names_are_ignored(self):
        text = ('### EDRAgentsOffline\n'
                '### 証明書の期限（Prometheus のアラートではありません）\n'
                '### ダッシュボード一覧\n')
        self.assertEqual(runbook_sections(text), {'EDRAgentsOffline'})


class TestTheRealRunbook(unittest.TestCase):
    def test_it_reads_the_actual_doc(self):
        alerts, sections = collect_runbook()
        self.assertGreater(len(alerts), 25)
        self.assertIn('EDRAgentsOffline', sections)
        self.assertIn('EDRBackupStale', sections)


if __name__ == '__main__':
    unittest.main(verbosity=2)

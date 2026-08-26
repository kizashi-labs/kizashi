#!/usr/bin/env python3
"""出荷しているアラートが本当に読まれているか — の判定が骨抜きにされたら。

対象:
  scripts/check_prometheus_rules.py          （配線: 参照⇔マウント、名前の重複）
  server/internal/metrics/alert_rules_contract_test.go （expr の metric が実在するか）
  deploy/prometheus.yml / deploy/prometheus_alerts.yml / deploy/prometheus/rules/edr-alerts.yml

`deploy/prometheus_alerts.yml` は19本のアラートを持ったまま、コンテナには
マウントされているのに rule_files から消えていました。**ファイルがあることと、
読まれていることは別です。** 外から見ると、書いたアラートは確かにそこにあります。

判定は2箇所に分かれています。配線は Python 側、metric 名は Go 側です。
同じ事実を両方で判定しようとして実際に結論が割れたので、片方を消しました。
なので変異もその線で分けています。

一つだけ、1箇所の変異では殺せないものがあります: main() が problems() の
返り値を無視する、という壊し方です。木がきれいなあいだは問題が0件なので、
無視してもしなくても出力が同じになります。汚した木を渡さないと見分けが
つかないため、check_prometheus_rules_test.py の TestMainActsOnWhatItFound が
collect() を差し替えてそこを見ています。ここではその検査自身を変異させます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

CHK = 'scripts/check_prometheus_rules.py'
CHKT = 'scripts/check_prometheus_rules_test.py'
GO = 'server/internal/metrics/alert_rules_contract_test.go'
PROM = 'deploy/prometheus.yml'
LEGACY = 'deploy/prometheus_alerts.yml'
NEW = 'deploy/prometheus/rules/edr-alerts.yml'
AM = 'deploy/alertmanager.yml'
RB = 'docs/ops/監視ランブック.md'

CASES = [
    # ── 守られている設定そのもの ───────────────────────────────────────────
    (PROM, '  - /etc/prometheus/alerts.yml', '',
     '19本入りのファイルが、また誰にも読まれなくなる'),
    (PROM, '  - /etc/prometheus/rules/edr-alerts.yml',
           '  - /etc/prometheus/rules/nope.yml',
     'rule_files が、何もマウントされていないパスを指す'),
    (NEW, '      - alert: EDRBackgroundComponentFailing',
          '      - alert: EDRAPIHighLatency',
     'アラート名が重複し、片方が静かに消える'),
    (LEGACY, 'increase(edr_alerts_created_total[1h]) > 1000',
             'increase(edr_alerts_invented_total[1h]) > 1000',
     'アラートが、サーバが出していない metric を見る'),
    (NEW, 'edr_background_failures_total', 'edr_background_failures',
     '新しい背景失敗アラートが、存在しない名前を見る'),

    # ── 配線の判定（Python） ───────────────────────────────────────────────
    (CHK, '        if ref not in mounts:', '        if False:',
     '参照されているのにマウントが無い、を言わなくなる'),
    (CHK, '        if container not in referenced:', '        if False:',
     'マウントされているのに参照が無い、を言わなくなる'),
    (CHK, '                if name in seen:', '                if False:',
     'アラート名の重複を言わなくなる'),
    (CHK, '                if key in folded and folded[key][0] != name:',
          '                if False:',
     '大文字小文字だけ違う名前を言わなくなる（2回発火が見えなくなる）'),
    (CHK, "                key = re.sub(r'[^a-z0-9]', '', name.lower())",
          '                key = name',
     '名前を畳まなくなる（完全一致しか見なくなる）'),
    (CHK, '                if key in folded and folded[key][0] != name:',
          '                if key in folded:',
     '完全に同じ名前まで「綴り違い」として報告する'),
    (CHK, "        if not isinstance(doc, dict) or 'groups' not in doc:\n"
          "            continue  # ルールファイルではない",
          "        if not isinstance(doc, dict):\n"
          "            continue  # ルールファイルではない",
     'prometheus.yml 自体を「読まれていないルールファイル」と誤って言う'),
    (CHK, "        if host.startswith('./'):", '        if True:',
     '名前付きボリュームをマウント済みルールファイルとして数える'),
    (CHK, "    referenced = list(prom.get('rule_files') or [])",
          '    referenced = []',
     '走査が rule_files を読まなくなる'),

    # ── 通知の配線 ─────────────────────────────────────────────────────────
    (PROM, "alerting:\n  alertmanagers:\n    - static_configs:\n"
           "        - targets: ['alertmanager:9093']",
           "# alerting:\n#   alertmanagers:\n#     - static_configs:\n"
           "#         - targets: ['alertmanager:9093']",
     'alerting: がまたコメントに戻る（30本がどこにも届かなくなる）'),
    (AM, "      - api_url_file: /etc/alertmanager/secrets/slack_webhook_url",
         "      - api_url: https://hooks.slack.com/services/T0/B0/XXXX",
     'Slack の webhook をリポジトリに直書きする'),
    (AM, "  receiver: 'edr-slack'", "  receiver: 'edr-nonexistent'",
     'route が、定義の無い receiver を指す'),
    (AM, "      - alertname =~ \"EDRHighAPIErrorRate|EDRAPIHighLatency|EDRApiHighRequestRate\"",
         "      - alertname =~ \"EDRApiHighErrorRate|EDRApiHighLatency\"",
     '抑制が、もう存在しないアラート名を指す'),
    (CHK, '        if host not in services:', '        if False:',
     '実体の無い alertmanager を指していても言わなくなる'),
    (CHK, '    for name in sorted(used - receivers):', '    for name in []:',
     '定義の無い receiver を指す route を言わなくなる'),
    (CHK, '    for name in sorted(receivers - used):', '    for name in []:',
     'どこからも使われない receiver を言わなくなる'),
    (CHK, '                if name not in alert_names:', '                if False:',
     '幽霊を指す抑制ルールを言わなくなる'),
    (CHK, '                    if bad in cfg:', '                    if False:',
     '直書きされた秘密を言わなくなる'),
    (CHK, "        for r in node.get('routes') or []:\n"
          "            out.extend(_routes(r))",
          '',
     '入れ子の route をたどらなくなる（critical の振り分けが見えなくなる）'),
    (CHK, '    found += alerting_problems(*collect_alerting())', '',
     'main が通知の配線を一切見なくなる'),

    # ── 手順への行き先 ─────────────────────────────────────────────────────
    (NEW, '#edrbackupstale"', '#wrong-anchor"',
     'runbook_url が、見出しと違う場所に飛ぶ'),
    (RB, '### EDRBackupStale\n', '### EDRBackupStaleOld\n',
     '手順の見出しが、アラート名から外れる（リンク先が消える）'),
    (CHK, '        if url and not has:', '        if False:',
     '存在しない手順を指すリンクを言わなくなる'),
    (CHK, '        if has and not url:', '        if False:',
     '手順があるのにリンクが無い、を言わなくなる'),
    (CHK, "        if url and 'wiki.internal' in url:", '        if False:',
     'wiki.internal に戻しても言わなくなる'),
    (CHK, "        if url and has and url.rsplit('#', 1)[-1] != name.lower():",
          '        if False:',
     'アンカーの食い違いを言わなくなる'),
    (CHK, '    for name in sorted(sections - set(alerts)):', '    for name in []:',
     '誰も辿り着かない手順を言わなくなる'),
    (CHK, "    return set(re.findall(r'^### ([A-Za-z][A-Za-z0-9_]*)\\s*$', text, re.M))",
          "    return set(re.findall(r'^### (.+)$', text, re.M))",
     '見出しの取り出しが、アラート名でないものまで拾う'),
    (CHK, '    found += runbook_problems(*collect_runbook())', '',
     'main が手順への行き先を一切見なくなる'),

    # ── 判定を動かす側 ─────────────────────────────────────────────────────
    (CHK, '    if found:', '    if False:',
     'main が、見つけた問題を無視して ok と言う'),
    (CHKT, "    '/etc/prometheus/alerts.yml',\n", '',
     '実物を読んでいることの確認から、19本入りのファイルが抜ける'),
    (CHKT, "REQUIRED_RULE_DOCS = ['prometheus_alerts.yml', 'edr-alerts.yml']",
           "REQUIRED_RULE_DOCS = []",
     '実物を読んでいることの確認が、何も求めなくなる'),

    # ── metric 名の判定（Go） ──────────────────────────────────────────────
    (GO, '\t\tfilepath.Join(base, "prometheus", "rules", "edr-alerts.yml"),', '',
     'Go の契約が、ルールファイルを1本しか読まなくなる'),
    (GO, '\tfor name := range declaredMetricNames(t) {\n\t\texported[name] = true\n\t}',
         '',
     'ラベルが1つも観測されていない CounterVec が「誰も出していない」に見える'),
]

CMD = [sys.executable, '-c',
       'import subprocess,sys;'
       'a=subprocess.run([sys.executable,"scripts/check_prometheus_rules.py"]).returncode;'
       'b=subprocess.run([sys.executable,"scripts/check_prometheus_rules_test.py"]).returncode;'
       'c=subprocess.run(["go","test","-count=1","./internal/metrics/"],cwd="server").returncode;'
       'sys.exit(a or b or c)']

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=CMD,
    cwd='.',
    # Python 側は構文エラーだけがビルド失敗です。unittest の失敗を
    # Traceback で判定していた頃は、本物の失敗をビルド失敗に数えていました。
    build_markers=('SyntaxError:', 'IndentationError:'),
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

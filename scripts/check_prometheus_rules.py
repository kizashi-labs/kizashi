#!/usr/bin/env python3
"""Are the alert rules we ship actually loaded?

`deploy/prometheus_alerts.yml` は19本のアラートを持ったまま、どこからも
読まれていませんでした。docker-compose はコンテナにマウントしているのに、
prometheus.yml の rule_files からだけ消えていた — 一度「存在しない死んだ
参照」として整理されたときに、マウントの方は残ったためです。

中身は EDRApiDown / PostgresDown / NATSDown / EDRDetectionDown。いちばん
基本的な「落ちている」の検知が、リポジトリを見れば確かにそこにあるのに、
一度も評価されていません。**ファイルがあることと、読まれていることは別です。**

このキャンペーンで何度も出てきた形と同じです。「無い」と「見えていない」
「読まれていない」が、外からは同じ顔をしています。

確かめること:

  1. rule_files が挙げる各パスに、マウントが1つずつあること
  2. prometheus のコンテナにマウントされたルールファイルが、すべて
     rule_files に載っていること
  3. アラート名が重複していないこと（同名は後勝ちで静かに消えます）

expr が実在する metric を指しているかは、ここでは見ません。
`server/internal/metrics/alert_rules_contract_test.go` が同じことを、
実際の /metrics 出力と宣言の両方を見て確かめています。**同じ事実を2箇所で
判定すると、片方だけを直したときに食い違い、どちらが正しいか分からなく
なります** — 実際にこの検査を書いた直後、Go 側と結論が割れました。

`python3 scripts/check_prometheus_rules.py` で走ります。判定そのものは
`scripts/check_prometheus_rules_test.py` が動かします。
"""
from __future__ import annotations

import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROM = os.path.join(ROOT, 'deploy/prometheus.yml')
COMPOSE = os.path.join(ROOT, 'deploy/docker-compose.monitoring.yml')


def load(path):
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)


def prometheus_mounts(compose: dict) -> dict[str, str]:
    """container path -> repo-relative host path, for the prometheus service."""
    svc = (compose.get('services') or {}).get('prometheus') or {}
    out = {}
    for v in svc.get('volumes', []):
        if not isinstance(v, str) or ':' not in v:
            continue
        parts = v.split(':')
        host, container = parts[0], parts[1]
        if host.startswith('./'):
            out[container] = os.path.join('deploy', host[2:])
    return out


def problems(referenced: list[str], mounts: dict[str, str],
             docs: dict[str, dict]) -> list[str]:
    """The whole rule, as one function over measurements.

    `docs` は host パス -> 読み込んだ YAML。ファイルを読むのは呼び出し側で、
    ここは判定だけです。そうしないと、判定を動かすのに一時ファイルが要ります。
    """
    out: list[str] = []

    for ref in referenced:
        if ref not in mounts:
            out.append(
                f'prometheus.yml が {ref} を読もうとしていますが、'
                'docker-compose.monitoring.yml はそこに何もマウントしていません。'
                'Prometheus は起動時に失敗します')

    for container, host in mounts.items():
        doc = docs.get(host)
        if not isinstance(doc, dict) or 'groups' not in doc:
            continue  # ルールファイルではない
        if container not in referenced:
            n = sum(len(g.get('rules', [])) for g in doc['groups'])
            out.append(
                f'{host} は {container} にマウントされていますが、'
                f'rule_files に載っていません。{n}本のルールが一度も評価されません')

    seen: dict[str, str] = {}
    # 大文字小文字と区切りを落とした名前。`EDRApiHighLatency` と
    # `EDRAPIHighLatency` は Prometheus にとっては別のアラートなので、
    # 上書きは起きません。**両方とも発火します。**
    #
    # 完全一致だけを見ていたあいだ、この2本は「重複なし」でした。中身は
    # 同じ p95 > 2s / for 5m / severity warning で、違いは `sum by (le)` の
    # 有無だけです。通知を繋いだ瞬間に、1つの事象で2通届きます。
    folded: dict[str, tuple[str, str]] = {}
    for container in referenced:
        host = mounts.get(container)
        doc = docs.get(host) if host else None
        if not isinstance(doc, dict):
            continue
        for g in doc.get('groups', []):
            for r in g.get('rules', []):
                name = r.get('alert')
                if not name:
                    continue
                if name in seen:
                    out.append(
                        f'アラート名 {name} が {seen[name]} と {host} の両方にあります。'
                        'Prometheus は同名を静かに上書きします')
                seen[name] = host
                key = re.sub(r'[^a-z0-9]', '', name.lower())
                if key in folded and folded[key][0] != name:
                    other, ohost = folded[key]
                    out.append(
                        f'アラート名 {other} ({ohost}) と {name} ({host}) が'
                        '大文字小文字の違いだけです。Prometheus は別物として扱うので、'
                        '同じ事象で2回通知されます')
                folded[key] = (name, host)
    return sorted(set(out))


# ── 通知の配線 ───────────────────────────────────────────────────────────────
#
# ルールが読まれることと、発火が誰かに届くことは別です。alerting: が
# コメントのままだったあいだ、30本は評価され、発火し、Prometheus の画面に
# 赤く出て、そこで終わっていました。**「マウントされているが読まれない」と
# 同じ形が、1段上でもう一度ありました。**
#
# ここで見るのは、実際に走らせなくても分かることだけです。Alertmanager の
# スキーマそのもの（フィールド名が v0.27 に合っているか）は起動しないと
# 分からないので、**見ていません。**

def _matcher_names(matchers) -> list[str]:
    """`alertname = "X"` / `alertname =~ "A|B"` から実名だけを取り出す。

    正規表現の実体（`.*` を含むもの）は名前として扱いません。当てずっぽうで
    「存在しない」と言うより、見ないほうがましです。
    """
    out = []
    for m in matchers or []:
        if not isinstance(m, str):
            continue
        mo = re.match(r'\s*alertname\s*(=~|=)\s*"(.*)"\s*$', m)
        if not mo:
            continue
        op, val = mo.groups()
        for part in (val.split('|') if op == '=~' else [val]):
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', part):
                out.append(part)
    return out


def _routes(node) -> list[dict]:
    out = []
    if isinstance(node, dict):
        out.append(node)
        for r in node.get('routes') or []:
            out.extend(_routes(r))
    return out


def alerting_problems(targets: list[str], services: list[str],
                      am: dict, alert_names: set[str]) -> list[str]:
    """Is the notification path wired to something that exists?"""
    out: list[str] = []

    for t in targets:
        host = t.split(':')[0]
        if host not in services:
            out.append(
                f'prometheus.yml が alertmanager として {t} を指していますが、'
                f'docker-compose.monitoring.yml に {host} サービスがありません。'
                '発火しても誰にも届きません')

    if not isinstance(am, dict) or not am:
        return sorted(set(out))

    receivers = {r.get('name') for r in (am.get('receivers') or []) if r.get('name')}
    routes = _routes(am.get('route') or {})
    used = {r.get('receiver') for r in routes if r.get('receiver')}

    for name in sorted(used - receivers):
        out.append(f'route が receiver {name} を指していますが、定義がありません')
    for name in sorted(receivers - used):
        out.append(
            f'receiver {name} はどの route からも使われていません。'
            '書いてあるのに、そこへは何も送られません')

    # inhibit_rules がアラート名を挙げているなら、その名前が実在すること。
    # 名前を変えると抑制は黙って効かなくなります — 抑制が外れたことは、
    # 通知が増えるまで誰も気づきません。
    for rule in am.get('inhibit_rules') or []:
        for side in ('source_matchers', 'target_matchers'):
            for name in _matcher_names(rule.get(side)):
                if name not in alert_names:
                    out.append(
                        f'inhibit_rules の {side} が {name} を挙げていますが、'
                        'そのアラートは存在しません。抑制は黙って効かなくなります')

    # 秘密が直書きされていないこと。*_file で読む前提です。
    inline = {'api_url': 'api_url_file', 'routing_key': 'routing_key_file',
              'service_key': 'service_key_file'}
    for r in am.get('receivers') or []:
        for key, cfgs in r.items():
            if not isinstance(cfgs, list):
                continue
            for cfg in cfgs:
                if not isinstance(cfg, dict):
                    continue
                for bad, good in inline.items():
                    if bad in cfg:
                        out.append(
                            f'receiver {r.get("name")} が {bad} を直接書いています。'
                            f'{good} を使ってください。リポジトリに秘密が入ります')
    return sorted(set(out))


def _rule_docs(mounts: dict[str, str]) -> dict[str, dict]:
    docs: dict[str, dict] = {}
    for host in mounts.values():
        path = os.path.join(ROOT, host)
        if not os.path.exists(path):
            continue
        try:
            docs[host] = load(path)
        except yaml.YAMLError:
            docs[host] = {}
    return docs


# ── 手順への行き先 ───────────────────────────────────────────────────────────
#
# Slack と PagerDuty の本文は runbook_url を出します。この値が壊れていても、
# 壊れていることが分かるのは**障害の最中に開いた人**です。
#
# 直す前の実測: 12本が https://wiki.internal/... を指していて、そのホストは
# リポジトリのどこにも定義がありません。うち7本は**手順そのものが存在しません**
# でした。逆に、手順が書いてあるのにリンクが無いアラートが4本。さらに、
# アラート名の見出しが4つ、実在しないアラート宛てに書かれていました
# （EDRDatabaseDown / EDRDetectionEngineDown / EDRDetectionConsumerLag は
# 改名前の名前、EDRCertificateExpiry は作られなかったアラート）。
#
# **指す側と指される側が、両方向にずれていました。**

RUNBOOK_DOC = 'docs/ops/監視ランブック.md'


def runbook_sections(text: str) -> set[str]:
    """アラート名の形をした `### 見出し`。"""
    return set(re.findall(r'^### ([A-Za-z][A-Za-z0-9_]*)\s*$', text, re.M))


def runbook_problems(alerts: dict[str, str | None],
                     sections: set[str]) -> list[str]:
    """`alerts` は アラート名 -> runbook_url (無ければ None)。"""
    out: list[str] = []
    for name, url in sorted(alerts.items()):
        has = name in sections
        if url and not has:
            out.append(
                f'{name} の runbook_url が指す手順がありません。'
                f'{RUNBOOK_DOC} に "### {name}" を書くか、リンクを外してください。'
                '障害の最中に開いて初めて分かります')
        if has and not url:
            out.append(
                f'{name} の手順は書いてあるのに runbook_url がありません。'
                '通知を受け取った人はそこへ辿り着けません')
        if url and 'wiki.internal' in url:
            out.append(
                f'{name} の runbook_url が wiki.internal を指しています。'
                'このホストはこのリポジトリのどこにも定義がありません')
        if url and has and url.rsplit('#', 1)[-1] != name.lower():
            out.append(
                f'{name} の runbook_url のアンカーが見出しと一致しません。'
                'ページは開きますが、別の場所に飛びます')
    for name in sorted(sections - set(alerts)):
        out.append(
            f'{RUNBOOK_DOC} に "### {name}" がありますが、'
            'その名前のアラートはありません。誰も辿り着かない手順です')
    return sorted(set(out))


def collect_runbook():
    text = ''
    path = os.path.join(ROOT, RUNBOOK_DOC)
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            text = f.read()
    alerts: dict[str, str | None] = {}
    for doc in _rule_docs(prometheus_mounts(load(COMPOSE))).values():
        if not isinstance(doc, dict):
            continue
        for g in doc.get('groups') or []:
            for r in g.get('rules') or []:
                if r.get('alert'):
                    alerts[r['alert']] = (r.get('annotations') or {}).get('runbook_url')
    return alerts, runbook_sections(text)


def collect():
    """Read everything the rule needs off disk."""
    prom = load(PROM)
    referenced = list(prom.get('rule_files') or [])
    mounts = prometheus_mounts(load(COMPOSE))
    return referenced, mounts, _rule_docs(mounts)


def collect_alerting():
    """Read what the notification path needs off disk."""
    prom = load(PROM)
    targets: list[str] = []
    for am in (prom.get('alerting') or {}).get('alertmanagers') or []:
        for sc in am.get('static_configs') or []:
            targets.extend(sc.get('targets') or [])
    services = list((load(COMPOSE).get('services') or {}).keys())
    am_path = os.path.join(ROOT, 'deploy/alertmanager.yml')
    am_doc: dict = {}
    if os.path.exists(am_path):
        try:
            am_doc = load(am_path) or {}
        except yaml.YAMLError:
            am_doc = {}
    # ルール名は自分で読みます。collect() を呼ぶと、片方を差し替えたときに
    # もう片方も一緒に動いてしまい、**合成入力の検査に実物が混ざります。**
    # 実際に混ざって、きれいな合成木の検査が落ちました。
    names: set[str] = set()
    docs = _rule_docs(prometheus_mounts(load(COMPOSE)))
    for doc in docs.values():
        if not isinstance(doc, dict):
            continue
        for g in doc.get('groups') or []:
            for r in g.get('rules') or []:
                if r.get('alert'):
                    names.add(r['alert'])
    return targets, services, am_doc, names


def main() -> int:
    referenced, mounts, docs = collect()
    found = problems(referenced, mounts, docs)
    found += alerting_problems(*collect_alerting())
    found += runbook_problems(*collect_runbook())
    if found:
        print('見つかった問題:')
        for p in found:
            print(f'  - {p}')
        return 1
    total = sum(
        len([r for r in g.get('rules', []) if r.get('alert')])
        for container in referenced
        for g in (docs.get(mounts.get(container, ''), {}) or {}).get('groups', [])
    )
    print(f'ok — 参照 {len(referenced)} ファイル、アラート {total} 本、'
          'すべてマウント済みで名前の重複なし')
    return 0


if __name__ == '__main__':
    sys.exit(main())

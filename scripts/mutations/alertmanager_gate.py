#!/usr/bin/env python3
"""Alertmanager の確認が、走らないまま緑を返さないこと。

対象:
  scripts/check-alertmanager.sh
  scripts/check_alertmanager_test.py

`deploy/alertmanager.yml` は Go から読まれないので、`go test ./...` は
1行も触りません。**フィールド名が v0.27 のスキーマに合っているかは、
起動して初めて分かります。** そこを見るのが check-alertmanager.sh で、
`server/scripts/run_tests.sh` から走るようになりました。

ここで守るのは**終了コードの約束**です:

    0  確かめた
    1  確かめて、問題が見つかった
    2  **確かめられなかった**（バイナリを取ってこられない、など）

2 を 1 と分けていないと、ネットワークの無い環境で走らせたときに
**「確かめられなかった」が「問題なし」と同じ行になります。** それが
このキャンペーンが直し続けている形そのものです。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  `run_tests.sh` 側の判定にも置いていません。変異1件につき Go の全検査
  （約10分）を回すことになり、**走らせなくなる仕様書は無いのと同じ**
  だからです。あちらは実際に両方の道を通して確かめました
  （NO_ALERTMANAGER=1 で exit 3、既定で exit 0）。

  次の3つは置いてみて、生き残ったので外しました。**殺せない変異を
  並べておくと、毎回 SURVIVED が出て本物の生き残りがそこに埋もれます。**

  - **出荷ファイルへの `amtool check-config` を無効化する** —— 壊れた設定は
    そのあと「起動しません」で捕まります。check-config は起動より前に
    分かるだけで、見ているものは重なっています
  - **バイナリが無いときの exit 2 を変える** —— 取得に失敗した時点で
    手前の分岐が戻るので、この分岐に入る道が検査から作れません
  - **`runbook_url` が無いことを問題にしない** —— 注釈はこちらが投げて
    Alertmanager がそのまま渡すので、落ちる入力を作れません
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

S = 'scripts/check-alertmanager.sh'

CASES = [
    # ── 「確かめられなかった」を潰す ───────────────────────────────────────
    (S, '    say "!! Alertmanager を取得できません（ネットワーク）。確かめられませんでした"\n    exit 2',
        '    say "!! Alertmanager を取得できません（ネットワーク）。確かめられませんでした"\n    exit 0',
     '取ってこられなかったのを「確かめた」として返す'),
    (S, '  if ! curl -fsSL --max-time 120 -o "$WORK/am.tgz"',
        '  if ! curl -sSL --max-time 120 -o "$WORK/am.tgz"',
     'curl の -f を外す（404 の本文をファイルに書いて成功で戻ります）'),

    # ── 速くするための差し替えが、出荷値から離れる ─────────────────────────
    (S, "if 'group_wait: 30s' not in s:", "if False:",
     '出荷値が変わっても、勝手に書き換え続ける'),
    (S, "s = s.replace('group_wait: 30s', 'group_wait: 1s', 1)", '',
     'group_wait を差し替えなくなる（届く前に見切ります）'),

    # ── 届いたことの判定 ───────────────────────────────────────────────────
    (S, '''    problems.append("通知が1件も届きませんでした。"
                    "**ルールを書くことと、誰かに届くことは別です**")''',
        '    pass',
     '1件も届かなくても問題にしない'),
    (S, "if states.get('EDRHighAPIErrorRate') != 'suppressed':",
        "if False:",
     'inhibit_rules が効いていなくても問題にしない'),
    (S, '''if problems:
    print("見つかった問題:")''',
        '''if False:
    print("見つかった問題:")''',
     '見つかった問題を報告しない'),
    (S, '    raise SystemExit(1)', '    raise SystemExit(0)',
     '問題を並べたうえで、成功として戻る'),
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['python3', 'scripts/check_alertmanager_test.py'],
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

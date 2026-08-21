#!/usr/bin/env python3
"""抑制ルールを「無効」にしたら、本当に抑制しなくなること。

対象:
  server/internal/detection/suppression_loader.go   （適用する側。#757 で
                                                     store から移った）
  server/internal/store/suppressions.go             （書き手）

`suppression_rules` には**有効を表す旗が2つ**あります:

    is_active   コンソールの抑制ルール画面 (store.SuppressionStore) が書き、
                **実際に適用される側** (detection.PoolSuppressionLoader の
                ListActiveSuppressions) が読みます
    enabled     かつて internal/suppression.Engine の API が書いていました。
                **その Engine は撤去済み**（保存はできるが本番の検知経路から
                呼ばれなかったため）。いまは store.SuppressionStore が
                is_active と同じ値を書きます

**撤去しても、この旗を読む側は外せません。** 撤去した API が過去に
enabled=false を書いた行が残っており、読み手が見るのをやめると
**無効にしたはずの抑制が復活します。**

どちらも既定は TRUE です。**片方だけに書くと、書かなかった側は TRUE の
まま残ります。**

直す前に測りました (2026-08-11):

    Engine と同じ形で enabled=false の1件を入れる
      → Engine から見える件数 (enabled=true)        0
      → **実際に適用される側から見える件数**        1

**抑制を解除したつもりのルールが、アラートを落とし続けます。** 落とされた
アラートは送られないので、担当者からは攻撃されていない端末と同じです ——
**届かなかったアラートは後から取り戻せません。**

読み手は2つとも TRUE のときだけ適用し、書き手は2つに同じ値を書きます。
**抑制しない方向に倒します** —— 余計に届いたアラートは消せますが、
落ちたアラートは戻りません。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

A = 'server/internal/detection/suppression_loader.go'
S = 'server/internal/store/suppressions.go'

CASES = [
    # ── 読み手 ─────────────────────────────────────────────────────────────
    (A, '\t\t  AND COALESCE(enabled, TRUE) = TRUE\n\t\t  AND (expires_at', '\t\t  AND (expires_at',
     '適用する側が enabled を見なくなる（元の実装。off にしたルールが'
     'アラートを落とし続けます）'),
    (A, '\t\tWHERE is_active = TRUE\n\t\t  AND COALESCE(enabled, TRUE) = TRUE',
        '\t\tWHERE (is_active = TRUE\n\t\t  OR COALESCE(enabled, TRUE) = TRUE)',
     'どちらか片方でも on なら適用する（**抑制する方向に倒します**）'),
    (S, '\t\tVALUES ($1, $2, $3, $4, $5, $5, $6::uuid, $7)`,',
        '\t\tVALUES ($1, $2, $3, $4, $5, TRUE, $6::uuid, $7)`,',
     'コンソールの作成が、もう片方の旗を常に TRUE にする'),
    (S, '"UPDATE suppression_rules SET is_active=$2, enabled=$2, updated_at=NOW() WHERE id=$1"',
        '"UPDATE suppression_rules SET is_active=$2, updated_at=NOW() WHERE id=$1"',
     'SetActive が片方の旗しか動かさない（元の実装）'),
    (S, '"UPDATE suppression_rules SET is_active=$2, enabled=$2, updated_at=NOW() WHERE id=$1"',
        '"UPDATE suppression_rules SET is_active=NOT $2, enabled=NOT $2, updated_at=NOW() WHERE id=$1"',
     'SetActive の向きが逆になる'),
]

# Engine (internal/suppression) は撤去したので、その3件
# (TestAddRuleWritesBothFlags / TestUpdateRuleWritesBothFlags /
# TestLoadFromDBHonoursBothFlags) は外した。表の検査は撤去後の状態を
# 留めるものに改名されている。
RUN = ('TestARuleDisabledOnEitherFlagIsNotApplied|TestTheConsoleWritesBothFlags|'
       'TestSetActiveMovesBothFlags|TestTheRetiredSuppressionTableHasNoReaderAndNoWriter')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/store/', './cmd/detection/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

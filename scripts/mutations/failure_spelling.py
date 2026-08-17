#!/usr/bin/env python3
"""失敗の報告が、その回を「終えられなかった」に落とすこと。

対象:
  server/internal/tick/tick.go
  server/internal/tick/tracked_workers_test.go
  server/internal/cloud/poller.go
  server/internal/detection/correlation.go

失敗を報告する綴りが3つありました。実測 (2026-08-12):

    fail(ctx, err, msg)                  147 箇所（internal/scheduler の中だけ）
    metrics.BackgroundFailed(comp, ...)   72 箇所（12 package）
    tick.Fail(ctx, err, msg)              10 箇所

どれも「失敗を報告する」ですが、**答える問いが違います**:

    BackgroundFailed  この部品が失敗した（edr_background_failures_total）
    Fail              この回が仕事を終えられなかった（last_success を押さない）

**`Run` で回している仕事の中で `BackgroundFailed` だけを使うと、失敗は
数えられるのに、その回は成功として刻まれます。** 実測:

    Run の中で BackgroundFailed を呼んだあと  この回の記録 = 0 件
    Run の中で tick.Fail を呼んだあと          この回の記録 = 1 件

0 件なら `Run` は `last_success` を更新します —— **毎回失敗しているワーカーが、
健全なワーカーと同じ姿**です。

実測: `Run` で回している 14 の仕事のうち **13 が `BackgroundFailed` を
使っていました**（6つはそれだけ、7つは `Fail` と混在）。`tick.FailComponent`
が両方します —— 部品ごとの件数は残したまま、この回を落とします。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  `internal/scheduler` の 147 箇所の `fail` への変異も置いていません。
  **あちらは元から回を落とします**（`fail` は `tick.Fail` の委譲です）。
  その形は `server_scheduler.py` と `tracked_workers.py` が見ています。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

K = 'server/internal/tick/tick.go'
T = 'server/internal/tick/tracked_workers_test.go'
CP = 'server/internal/cloud/poller.go'
CO = 'server/internal/detection/correlation.go'

CASES = [
    # ── 仕組みそのもの ───────────────────────────────────────────────────
    (K, '\tmetrics.BackgroundFailed(component, err, msg, args...)\n'
        '\tif st, ok := ctx.Value(stateKey{}).(*state); ok {\n\t\tst.add()\n\t}\n',
        '\tmetrics.BackgroundFailed(component, err, msg, args...)\n',
     '`FailComponent` が、部品の件数だけ数えて回を落とさない'
     '（**`last_success` が動いたままになります**）'),
    (K, '\tmetrics.BackgroundFailed(component, err, msg, args...)\n', '',
     '`FailComponent` が、部品ごとの件数を残さなくなる'),

    # ── 呼ぶ側 ───────────────────────────────────────────────────────────
    (CP, '\t\t\ttick.FailComponent(ctx, "cloud_poller"',
         '\t\t\tmetrics.BackgroundFailed("cloud_poller"',
     'クラウドの取り込みが、部品の件数だけ数える（**元の実装。回は成功と'
     'して刻まれます**）'),
    (CO, '\t\ttick.FailComponent(ctx, "correlation"',
         '\t\tmetrics.BackgroundFailed("correlation"',
     '相関エンジンが、部品の件数だけ数える（**元の実装**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, '\tsel, ok := call.Fun.(*ast.SelectorExpr)\n\tif !ok || sel.Sel.Name != "BackgroundFailed" {\n\t\treturn false\n\t}',
        '\tsel, ok := call.Fun.(*ast.SelectorExpr)\n\tif !ok || sel.Sel.Name != "BackgroundFailedXXX" {\n\t\treturn false\n\t}',
     '`metrics.BackgroundFailed` を1つも見つけなくなる（**0件を検査して緑**）'),
    (T, '\tpkg, ok := sel.X.(*ast.Ident)\n\treturn ok && pkg.Name == "metrics"',
        '\t_, ok = sel.X.(*ast.Ident)\n\treturn ok',
     '`metrics` 以外の同名関数まで数える'),
    (T, '\t\t\tcase *ast.SelectorExpr:\n\t\t\t\tseeds[pkg+"|"+a.Sel.Name] = true\n',
        '',
     '`tick.Run` に渡している関数を1つも覚えない（**走査の対象が'
     '空になります**）'),
    (T, 'const minTrackedWorkerNames = 120', 'const minTrackedWorkerNames = 0',
     '対象の床を 0 に落とす'),
    (T, '\t"metrics.BackgroundFailed(", // 部品ごとの件数\n', '',
     '`FailComponent` が部品の件数を残しているかを見なくなる'),
    (T, '\t"st.add()",                  // この回を「終えられなかった」に\n', '',
     '`FailComponent` が回を落としているかを見なくなる'),
    (T, '\tsel, ok := fun.(*ast.SelectorExpr)\n\tif !ok || sel.Sel.Name != "Run" {',
        '\tsel, ok := fun.(*ast.SelectorExpr)\n\tif !ok || sel.Sel.Name != "RunXXX" {',
     '`tick.Run` の呼び出しを1つも見つけなくなる'),
    (T, '\tif id, ok := fun.(*ast.Ident); ok {\n\t\treturn id.Name == trackRunName\n\t}\n',
        '',
     '`trackRun` に渡している 26 の仕事を走査の対象から外す'),
]

RUN = ('TestTrackedWorkersDoNotReportPastTheRun|TestTheSpellingDetectorRecognisesTheRealThing|'
       'TestFailComponentMarksTheRunAsWellAsTheComponent|TestFailReachesTheRun|'
       'TestEveryPeriodicWorkerRecordsThatItRan|TestTheTrackedWorkerNameFloorNoticesAnEmptyWalk')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/tick/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

#!/usr/bin/env python3
"""`error` を返せない関数でも、行の読み出しの失敗が誰かに届くこと。

対象:
  server/internal/store/rows_err_returnable_test.go
  server/internal/scheduler/insider_threat_detector.go
  server/internal/scheduler/network_anomaly_detector.go
  server/internal/dedup/alert_dedup.go
  server/internal/threatintel/feed.go

バックグラウンドの繰り返し処理は `error` を返しません。返す先が無いので、
唯一の出口はログと計測です。**そこを `slog.Warn` にしておくと、運用の設定で
最初に切られる段になります** —— 「回っているが何もできていない」が、外からは
「静かに動いている」と同じ姿になります。

実測 (2026-08-12): `error` を返さない関数の中で `rows.Err()` を捨てていた
箇所は 44（文字での数え方。構文木では 57 箇所を走査し、届いていないのが
44）。**うち 28 は `internal/scheduler` で、同じ関数がすでに
`fail(ctx, err, ...)` を呼んでいました** —— 報告の仕方を知っているのに、
この分岐だけが `slog.Warn` でした。

`fail` は `edr_scheduler_failures_total` と `last_success` に落ちるので、
「この回は仕事を終えられなかった」が外から見えます
（`internal/scheduler/heartbeat.go`）。scheduler の外には `fail` が無いので、
そちらは `slog.Error` です —— **少なくとも、切られない段に置きます。**

メッセージはどれも元から正直でした（「検出漏れがあります」「グラフの一部の
日が0件として描画されます」）。**言っていたのに、誰にも届いていませんでした。**

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  「途中まで読んだ結果をそのまま状態として据え置く」問題への変異も置いて
  いません。**まだ直していないからです** —— `threatintel/feed.go` は行ごとに
  `m.feeds` を書き換えるので、途中で切れると半分だけ新しい集合が残ります。
  `docs/判断待ちの一覧.md` に置いてあります。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/store/rows_err_returnable_test.go'
ITD = 'server/internal/scheduler/insider_threat_detector.go'
NAD = 'server/internal/scheduler/network_anomaly_detector.go'
DD = 'server/internal/dedup/alert_dedup.go'
TI = 'server/internal/threatintel/feed.go'

CASES = [
    # ── 元の姿に戻す ─────────────────────────────────────────────────────
    (ITD, '\t\tfail(ctx, err, "時間外アクセスの走査が途中で終わりました。検出漏れがあります")',
          '\t\tslog.Warn("時間外アクセスの走査が途中で終わりました。検出漏れがあります", "error", err)',
     '内部脅威の検出が、取りこぼしを `slog.Warn` で済ませる（**元の実装。'
     '「回っているが何もできていない」が外から見えません**）'),
    (NAD, '\t\tfail(ctx, err, "トラフィック急増の走査が途中で終わりました。検出漏れがあります")',
          '\t\tslog.Warn("トラフィック急増の走査が途中で終わりました。検出漏れがあります", "error", err)',
     'ネットワーク異常の検出が、取りこぼしを `slog.Warn` で済ませる'
     '（**元の実装**）'),
    (DD, '\t\ttick.Fail(ctx, err, "重複アラート群の走査が途中で終わりました。今回のパスでまとめられない重複が残ります")',
         '\t\tslog.Warn("重複アラート群の走査が途中で終わりました。今回のパスでまとめられない重複が残ります", "error", err)',
     '重複アラートの整理が、取りこぼしを `slog.Warn` で済ませる（**元の実装**）'),
    (TI, '\t\tslog.Error("脅威フィード一覧の読み込みが途中で終わりました。メモリ上のフィード集合は不完全です", "error", err)',
         '\t\tslog.Warn("脅威フィード一覧の読み込みが途中で終わりました。メモリ上のフィード集合は不完全です", "error", err)',
     '脅威フィードの読み込みが、不完全な集合を `slog.Warn` で済ませる'
     '（**元の実装**）'),

    # ── 判定そのもの ─────────────────────────────────────────────────────
    (T, '\t\t\tif id, ok := v.Fun.(*ast.Ident); ok && id.Name == "fail" {\n\t\t\t\tfound = true\n\t\t\t}',
        '',
     '`fail` を報告と認めなくなる（**scheduler の 28 箇所が違反として'
     '並びます**）'),
    (T, '\t\t\t\tif pkg.Name == "slog" && sel.Sel.Name == "Error" {',
        '\t\t\t\tif pkg.Name == "slog" {',
     '`slog.Warn` も報告と認める（**最初に切られる段が「届いた」に'
     'なります**）'),
    (T, '\t\tcase *ast.FuncLit:\n\t\t\treturn false\n\t\tcase *ast.ReturnStmt:\n\t\t\tfound = true',
        '\t\tcase *ast.FuncLit:\n\t\t\treturn true\n\t\tcase *ast.ReturnStmt:\n\t\t\tfound = true',
     '中の関数を、この関数がしたことと取り違える'),
    (T, '\tif block == nil {\n\t\treturn false\n\t}\n\tfound := false',
        '\tif block == nil {\n\t\treturn true\n\t}\n\tfound := false',
     '中身が無いものを報告と数える'),
    (T, 'const minVoidRowsErrSites = 45', 'const minVoidRowsErrSites = 0',
     '走査の床を 0 に落とす'),
    (T, '\t\t\tif !reportsFailure(is.Body) {', '\t\t\tif false {',
     '違反を1件も挙げなくなる'),
    (T, '\t\t\tchecks++\n', '',
     '見た箇所を数えなくなる（床の判定が一緒に緩みます）'),
    (T, 'func isVoidFunc(fn *ast.FuncDecl) bool { return !returnsError(fn) }',
        'func isVoidFunc(fn *ast.FuncDecl) bool { return returnsError(fn) }',
     '`error` を返す関数の方を見る（**返せない関数が走査から外れます**）'),
]

RUN = ('TestFunctionsThatCannotReturnAnErrorStillReportRowsErr|TestReportsFailureTellsWarnFromReporting|'
       'TestTheReturnableScanFloorsNoticeAnEmptyWalk|TestReturnsErrorLooksAtTheSignature|'
       'TestFunctionsThatCanReturnAnErrorDoNotDiscardRowsErr|TestDiscardsRowsErrTellsLoggingFromReturning|'
       'TestIsVoidFuncPicksTheOnesWithNowhereToReturn|TestUnreportedVoidSitesFindsTheRealThing')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

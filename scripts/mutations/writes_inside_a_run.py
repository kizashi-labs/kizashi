#!/usr/bin/env python3
"""「回」の中では、書き込みを捨てないこと。

対象:
  server/internal/cloud/poller.go
  server/internal/dedup/alert_dedup.go
  server/internal/reports/scheduler.go
  server/internal/threatintel/feed.go
  server/internal/tick/tracked_workers_test.go
  server/internal/api/handlers/discarded_write_test.go

捨てている書き込み 44 か所を4つに分類したとき、`has-run`（周期の仕事の
中）は 3 つの関数だと**手で書きました**。**手で書いた「これだけです」は、
数え落としを止めません。**

同じことを走査で言うようにしたら（`tick.Run` から3段たどって
`_, _ = ….Exec(…)` を挙げる）、**5 か所ではなく 7 か所**でした。
足りなかった 2 つ —— `reports/scheduler.go:runReport` と
`threatintel/feed.go:FetchFeed` —— は `restart` に分類していたもので、
どちらも `tick.Run` から届きます。

直した 7 か所が黙っていたときに起きること:

    cloud/poller.go       検知には送れているのに、クラウドイベントの
                          一覧に出ない
    alert_dedup.go ×2     統合先に印が付かず**次の周回が同じ群をもう一度
                          まとめようとする**／重複が閉じられず**画面には
                          重複が並んだまま**
    reports/scheduler.go  `last_run` が残らず、**再起動後に同じ期間の
                          レポートをもう一度送る**
    threatintel/feed.go   画面の「最終取得」が止まったまま IOC だけ増える

置いていない変異:

  重複を閉じる失敗を「1件ずつ報告する」に戻す変異は置いていません。
  **それは違反ではなく、うるさいだけの実装**です（DB が応答しないとき、
  ログが群の数だけ出ます）。検査が言えるのは「報告しているか」までです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

CP = 'server/internal/cloud/poller.go'
DD = 'server/internal/dedup/alert_dedup.go'
RS = 'server/internal/reports/scheduler.go'
TF = 'server/internal/threatintel/feed.go'
T = 'server/internal/tick/tracked_workers_test.go'
W = 'server/internal/api/handlers/discarded_write_test.go'

CASES = [
    # ── 元の実装に戻す ───────────────────────────────────────────────────
    (CP, '\t); err != nil {\n'
         '\t\ttick.Fail(ctx, err, "クラウドイベントを保存できませんでした。検知には送れていますが一覧には出ません",\n'
         '\t\t\t"provider", intg.Provider, "event", eventType)\n\t}\n',
         '\t)\n\t_ = fmt.Sprint\n',
     'クラウドイベントの保存の失敗が誰にも届かなくなる（**元の実装。'
     '検知には送れているのに一覧に出ません**）'),
    (DD, '\t\tif _, err := d.pool.Exec(ctx,\n'
         '\t\t\t`UPDATE alerts SET dedup_key=$1, dedup_count=COALESCE(dedup_count,0)+$2, updated_at=NOW()\n'
         '             WHERE id=$3::UUID`,\n'
         '\t\t\tkey, len(dupIDs), g.keepID,\n'
         '\t\t); err != nil {\n'
         '\t\t\ttick.Fail(ctx, err, "統合先アラートに重複の印を付けられませんでした",\n'
         '\t\t\t\t"title", g.title, "kept", g.keepID)\n'
         '\t\t}\n',
         '\t\t_, _ = d.pool.Exec(ctx,\n'
         '\t\t\t`UPDATE alerts SET dedup_key=$1, dedup_count=COALESCE(dedup_count,0)+$2, updated_at=NOW()\n'
         '             WHERE id=$3::UUID`,\n'
         '\t\t\tkey, len(dupIDs), g.keepID,\n'
         '\t\t)\n',
     '統合先への印が黙って捨てられる（**次の周回が同じ群をもう一度'
     'まとめようとします**）'),
    (DD, 'func (o closeOutcome) needsReporting() bool { return o.failed > 0 }',
         'func (o closeOutcome) needsReporting() bool { return false }',
     '重複を閉じられなかったことが誰にも届かなくなる（**画面には重複が'
     '並んだままです**）'),
    (DD, '\to.total++\n\tif err != nil {\n\t\to.failed++\n\t\to.last = err\n\t}',
         '\to.total++\n\tif err == nil {\n\t\to.failed++\n\t\to.last = err\n\t}',
     '閉じられた方を失敗に数える'),
    (DD, 'func (o closeOutcome) needsReporting() bool { return o.failed > 0 }',
         'func (o closeOutcome) needsReporting() bool { return o.total > 0 }',
     '**閉じられていても毎回報告する**（回が常に失敗になります）'),
    (RS, '\t\t\tif _, err := s.pool.Exec(ctx, `\n'
         '\t\t\t\tUPDATE scheduled_reports SET last_run=$2, next_run=$3, updated_at=NOW() WHERE id=$1`,\n'
         '\t\t\t\tr.ID, now, nextRun); err != nil {\n'
         '\t\t\t\ttick.Fail(ctx, err, "scheduler: 実行時刻を記録できませんでした。再起動後に同じレポートをもう一度送ります",\n'
         '\t\t\t\t\t"id", r.ID)\n'
         '\t\t\t}\n',
         '\t\t\t_, _ = s.pool.Exec(ctx, `\n'
         '\t\t\t\tUPDATE scheduled_reports SET last_run=$2, next_run=$3, updated_at=NOW() WHERE id=$1`,\n'
         '\t\t\t\tr.ID, now, nextRun)\n',
     'レポートの実行時刻が残らない（**元の実装。再起動後に同じ期間の'
     'レポートをもう一度送ります**）'),
    (TF, '\t\t`, feedID, imported); err != nil {\n'
         '\t\t\ttick.Fail(ctx, err, "threatintel: 取得結果を記録できませんでした。画面の最終取得が止まって見えます",\n'
         '\t\t\t\t"feed", feed.Name, "imported", imported)\n\t\t}\n',
         '\t\t`, feedID, imported)\n\t\t_ = ctx\n',
     'フィードの取得結果の失敗が誰にも届かなくなる（**元の実装。画面の'
     '「最終取得」が止まったまま IOC だけ増えます**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, 'const reachableDiscardedWriteSites = 0',
        'const reachableDiscardedWriteSites = 100',
     '件数を留めなくなる'),
    (T, '\tcase "Exec", "SendBatch", "CopyFrom":\n\t\treturn true\n\t}\n\treturn false\n}\n\nfunc reachableDiscardedWrites',
        '\tcase "SendBatch", "CopyFrom":\n\t\treturn true\n\t}\n\treturn false\n}\n\nfunc reachableDiscardedWrites',
     '`Exec` を見なくなる（**捨てている書き込みのほぼ全部です**）'),
    (T, '\t\tif id, lok := l.(*ast.Ident); !lok || id.Name != "_" {\n\t\t\treturn false\n\t\t}',
        '\t\tif id, lok := l.(*ast.Ident); !lok || id.Name == "_" {\n\t\t\treturn false\n\t\t}',
     'error を受け取っている方を違反にする'),
    (T, '\tif !ok || len(as.Lhs) == 0 || len(as.Rhs) != 1 {\n\t\treturn false\n\t}',
        '\tif !ok || len(as.Lhs) == 0 || len(as.Rhs) < 1 {\n\t\treturn false\n\t}',
     '右辺が複数の代入まで数える'),
    (T, '\t\t\tif !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {\n'
        '\t\t\t\tcontinue\n\t\t\t}\n'
        '\t\t\tast.Inspect(fn.Body, func(n ast.Node) bool {\n'
        '\t\t\t\tif !discardsAWriteHere(n) {',
        '\t\t\tif !ok || fn.Body == nil || names[pkg+"|"+fn.Name.Name] == false && false {\n'
        '\t\t\t\tcontinue\n\t\t\t}\n'
        '\t\t\tast.Inspect(fn.Body, func(n ast.Node) bool {\n'
        '\t\t\t\tif !discardsAWriteHere(n) {',
     '「回」の中かどうかを見ずに全部挙げる（**37 か所が違反になります**）'),

    # ── parse できない file を黙って飛ばさないこと ───────────────────────
    #
    # **これが生き残りの原因でした。** 構文を壊した file が
    # 「捨てている書き込みが無い file」と同じ扱いになり、元の実装に
    # 戻す変異が「直っている」と読まれていました。
    (T, '\t\tf, parseErr := parser.ParseFile(fset, rel, src, 0)\n'
        '\t\tif parseErr != nil {\n\t\t\treturn parseErr\n\t\t}\n'
        '\t\tpkg := filepath.ToSlash(filepath.Dir(rel))\n'
        '\t\tfor _, decl := range f.Decls {\n'
        '\t\t\tfn, ok := decl.(*ast.FuncDecl)\n'
        '\t\t\tif !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {\n'
        '\t\t\t\tcontinue\n\t\t\t}\n'
        '\t\t\tast.Inspect(fn.Body, func(n ast.Node) bool {\n'
        '\t\t\t\tif !discardsAWriteHere(n) {',
        '\t\tf, parseErr := parser.ParseFile(fset, rel, src, 0)\n'
        '\t\tif parseErr != nil {\n\t\t\treturn nil\n\t\t}\n'
        '\t\tpkg := filepath.ToSlash(filepath.Dir(rel))\n'
        '\t\tfor _, decl := range f.Decls {\n'
        '\t\t\tfn, ok := decl.(*ast.FuncDecl)\n'
        '\t\t\tif !ok || fn.Body == nil || !names[pkg+"|"+fn.Name.Name] {\n'
        '\t\t\t\tcontinue\n\t\t\t}\n'
        '\t\t\tast.Inspect(fn.Body, func(n ast.Node) bool {\n'
        '\t\t\t\tif !discardsAWriteHere(n) {',
     'parse できない file を黙って飛ばす（**壊れた file が「問題の無い '
     'file」と同じ扱いになります**）'),

    # ── 分類の側の数 ─────────────────────────────────────────────────────
    (W, 'const discardedWritesTotal = 0', 'const discardedWritesTotal = 44',
     '直した 7 か所を、まだ捨てていることにする'),
]

HARNESS_DD = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', './internal/dedup/'],
    cwd='server',
)

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestTrackedWorkersDoNotDiscardWrites|'
         'TestTheDiscardedWriteRecogniserHereMatchesTheOtherOne|'
         'TestTrackedWorkersDoNotSwallowErrorsSilently|'
         'TestAFileThatDoesNotParseIsAFailureNotAnAbsence',
         './internal/tick/'],
    cwd='server',
)

HARNESS_W = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestNoDiscardedWriteIsAnsweredWithSuccess|TestEveryDiscardedWriteIsClassified|'
         'TestEveryWriteCategoryIsOneOfTheFour',
         './internal/api/handlers/'],
    cwd='server',
)

DD_ONLY = {'func (o closeOutcome) needsReporting() bool { return o.failed > 0 }',
           '\to.total++\n\tif err != nil {\n\t\to.failed++\n\t\to.last = err\n\t}'}
DD_CASES = [c for c in CASES if c[0] == DD and c[1] in DD_ONLY]
TICK_CASES = [c for c in CASES if c[0] != W and c not in DD_CASES]
WRITE_CASES = [c for c in CASES if c[0] == W]

if __name__ == '__main__':
    rc = HARNESS.run(TICK_CASES)
    rc |= HARNESS_DD.run(DD_CASES)
    rc |= HARNESS_W.run(WRITE_CASES)
    sys.exit(rc)

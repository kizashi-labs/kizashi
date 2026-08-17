#!/usr/bin/env python3
"""ハンドラが store の error を捨てて、画面に「0」を出さないこと。

対象:
  server/internal/api/handlers/discarded_store_error_test.go
  server/internal/api/handlers/alerts_handler.go
  server/internal/api/handlers/rules_ie_handler.go
  server/internal/api/handlers/system_updates_handler.go
  server/internal/api/handlers/live_response_handler.go
  server/internal/api/handlers/zero_trust_handler.go

実測 (2026-08-12): `x, _ = h.<ストア>.<メソッド>(…)` の形が 19 か所。
1つずつ読んで、全部 `ReadOK(c, err)` に通しました。**直す前に画面へ
出ていたのはこれです**:

    alerts_handler   ダッシュボードの「最近のアラート」「脅威の多い端末」
                     「24時間の時系列」が空 —— 0 件と同じ姿
    rules_ie         **「検知ルール 0 件」** —— ルールが1本も無い配置と
                     DB に届かない配置が区別できない
    system_updates   **「最新です」** —— 更新が出ていても、読めなければ
                     `up_to_date` を返していた
    live_response    再接続した端末に、それまでのコマンドが1つも無い
                     ものが流れる

**`if rows != nil` は死んだ分岐でした。** pgx の `pool.Query` は失敗時に
`errRows{err}` を返すので nil になりません。`Next()` が即 false、
`rows.Err()` が `slog.Warn` に出て、区画は空のまま返っていました ——
**「読めなかった」と「1件も無い」が同じ応答**です。

置いていない変異:

  `ReadOK` そのものへの変異は置いていません。**`handler_reads.py` が
  見ています**（`absent` を広げる／失敗を通す、など）。

  `data, _ := json.Marshal(…)` のような、store ではない `_` への変異も
  置いていません。実測 536 か所あり、捨ててよいものが多く混ざります ——
  この検査は `h.<フィールド>.<メソッド>` の形だけを見ます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/api/handlers/discarded_store_error_test.go'
AL = 'server/internal/api/handlers/alerts_handler.go'
RI = 'server/internal/api/handlers/rules_ie_handler.go'
SU = 'server/internal/api/handlers/system_updates_handler.go'
LR = 'server/internal/api/handlers/live_response_handler.go'
ZT = 'server/internal/api/handlers/zero_trust_handler.go'

CASES = [
    # ── 元の実装に戻す ───────────────────────────────────────────────────
    (AL, '\trecentAlerts, _, err := h.Store.ListAlerts(ctx, store.AlertFilter{Limit: 5, Offset: 0})\n'
         '\tif !ReadOK(c, err) {\n\t\treturn\n\t}',
         '\trecentAlerts, _, _ := h.Store.ListAlerts(ctx, store.AlertFilter{Limit: 5, Offset: 0})',
     'ダッシュボードの「最近のアラート」が、読めなくても空で返る（元の実装）'),
    (AL, '\ttopAgents, err := h.Store.TopThreatenedAgents(ctx, 5)\n'
         '\tif !ReadOK(c, err) {\n\t\treturn\n\t}',
         '\ttopAgents, _ := h.Store.TopThreatenedAgents(ctx, 5)',
     '「脅威の多い端末」が空で返る（**0 件と同じ姿**）'),
    (AL, '\talertBuckets, err := h.Store.AlertTimeline(ctx, 24)\n'
         '\tif err != nil && !absent(err) {\n\t\treturn nil, err\n\t}',
         '\talertBuckets, _ := h.Store.AlertTimeline(ctx, 24)',
     '24時間の時系列が、読めなくても「アラート0件」のグラフになる'),
    (RI, '\t_, detTotal, err := h.ruleStore.List(c.Request.Context(), store.RuleFilter{Limit: 1})\n'
         '\tif !ReadOK(c, err) {\n\t\treturn\n\t}',
         '\t_, detTotal, _ := h.ruleStore.List(c.Request.Context(), store.RuleFilter{Limit: 1})',
     '**「検知ルール 0 件」**（元の実装。ルールが無い配置と DB に'
     '届かない配置が同じ表示です）'),
    (SU, '\t\tlatest, err := h.store.LatestAvailable(c.Request.Context())\n'
         '\t\tif !ReadOK(c, err) {\n\t\t\treturn\n\t\t}',
         '\t\tlatest, _ := h.store.LatestAvailable(c.Request.Context())',
     '**「最新です」**（元の実装。更新が出ていても、読めなければ '
     '`up_to_date` を返します）'),
    (LR, '\texisting, err := h.Store.ListCommands(c.Request.Context(), sessionID)\n'
         '\tif !ReadOK(c, err) {\n\t\treturn\n\t}',
         '\texisting, _ := h.Store.ListCommands(c.Request.Context(), sessionID)',
     '再接続した端末に、それまでのコマンドが1つも無いものが流れる'),
    (ZT, '\tdeniedRows, err := h.pool.Query(ctx,\n'
         '\t\t`SELECT resource, COUNT(*) as cnt FROM zero_trust_access_logs\n'
         '\t\t WHERE decision=\'deny\' AND logged_at >= NOW() - INTERVAL \'7 days\'\n'
         '\t\t GROUP BY resource ORDER BY cnt DESC LIMIT 10`)\n'
         '\tif !ReadOK(c, err) {\n\t\treturn\n\t}',
         '\tdeniedRows, _ := h.pool.Query(ctx,\n'
         '\t\t`SELECT resource, COUNT(*) as cnt FROM zero_trust_access_logs\n'
         '\t\t WHERE decision=\'deny\' AND logged_at >= NOW() - INTERVAL \'7 days\'\n'
         '\t\t GROUP BY resource ORDER BY cnt DESC LIMIT 10`)',
     '「拒否の多いリソース」が空で返る（**元の実装**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (T, 'const discardedStoreErrors = 0', 'const discardedStoreErrors = 100',
     '件数を留めなくなる'),
    (T, '\trecv, ok := inner.X.(*ast.Ident)\n\treturn ok && recv.Name == "h"',
        '\trecv, ok := inner.X.(*ast.Ident)\n\treturn ok && recv.Name == "zzz"',
     'レシーバの名前を取り違える（**0 件を検査して緑**）'),
    (T, '\t\tif !keeps {\n\t\t\treturn false\n\t\t}', '\t\tif keeps {\n\t\t\treturn false\n\t\t}',
     '受け取っている側がある形を外す'),
    (T, '\tif len(as.Rhs) != 1 || len(as.Lhs) < 1 {', '\tif len(as.Rhs) != 1 || len(as.Lhs) < 2 {',
     '`_ = h.Store.Foo(…)` の形を見なくなる（**返り値が `error` 1つだけの'
     '呼び出しが素通りします**）'),
    (T, '\tlast, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)\n\tif !ok || last.Name != "_" {\n\t\treturn false\n\t}',
        '\tlast, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)\n\tif !ok || last.Name == "_" {\n\t\treturn false\n\t}',
     'error を受け取っている方を違反にする'),
    (T, 'const handlerFuncFloor = 500', 'const handlerFuncFloor = 0',
     '**走査の床を外す**（0 件が「無い」なのか「探していない」なのか'
     '分からなくなります）'),
    (T, '\t\tif parseErr != nil {\n\t\t\treturn parseErr\n\t\t}\n\t\tfor _, decl := range f.Decls {\n'
        '\t\t\tif fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {\n\t\t\t\tn++\n\t\t\t}\n\t\t}',
        '\t\tif parseErr != nil {\n\t\t\treturn parseErr\n\t\t}\n\t\tfor _, decl := range f.Decls {\n'
        '\t\t\tif fn, ok := decl.(*ast.FuncDecl); ok && fn.Body == nil {\n\t\t\t\tn++\n\t\t\t}\n\t\t}',
     '床の数え方を壊す（本体のある関数を数えなくなります）'),
    (T, '\t\tif parseErr != nil {\n\t\t\t// **黙って飛ばすと、その file は走査から消えます。**\n\t\t\treturn parseErr\n\t\t}',
        '\t\tif parseErr != nil {\n\t\t\treturn nil\n\t\t}',
     'parse できない file を黙って飛ばす'),
]

RUN = ('TestHandlersDoNotDiscardStoreErrors|TestTheStoreErrorRecogniserLooksAtTheShape|'
       'TestTheBackupCodeCallDoesNotDiscardItsError|'
       'TestABrokenHandlerFileIsAFailureNotAnAbsence')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

#!/usr/bin/env python3
"""ログを書いて戻るだけの箇所に、理由が要ること。

対象:
  server/internal/scheduler/bare_log_and_return_test.go
  server/internal/scheduler/backup_scheduler.go
  server/internal/scheduler/darkweb_scheduler.go
  server/internal/scheduler/api_key_rotator.go
  server/internal/scheduler/realtime_correlator.go

`internal/scheduler` のワーカーには報告する相手がいません。呼び出し側は
次の周回です。`fail(ctx, err, …)` はその行き先で、`trackRun` が
`edr_scheduler_failures_total` と `last_success` に落とします。

**`slog` を書いて `return` するだけの箇所は、そこへ届きません。**
以前は上限（34）で押さえていました。**上限は「これ以上増やすな」しか
言いません** —— いま在る 34 が届かなくてよいものかは、誰も見ていません
でした。

実測 (2026-08-12): 34 か所を1つずつ読み、**5 か所は本当に「この回は
仕事を終えられなかった」でした**:

    backup_scheduler   pg_dump 失敗 / 整合性検証の失敗
    darkweb_scheduler  照合対象を読めなかった / キャッシュを解釈できなかった
    api_key_rotator    列の存在確認の error を `_ =` で捨てていて、
                       **DB が応答しないだけで「列が無い」**になっていた

もう1つ、`realtime_correlator` のアラート解釈失敗は**回の外**（NATS の
購読コールバック）なので `metrics.BackgroundFailed` に出しました。

残りの 29 か所には理由を書きました（25 の宛先）。理由の側も、宛先が
実在することを見ます —— **直した箇所の理由が残ると、次に同じ場所が
生えたときに黙って通ります。**

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  理由を1つ消す変異も置いていません。**それは「違反を1件増やす」だけで、
  仕組みではなく一覧の話です**（一覧が効いていることは、宛先の判定を
  潰す変異が見ています）。

  存在確認の走査で「挙げる側」を `if true` に潰す変異も置いていません。
  **違反が 0 件なので、どのテストも殺せません。** 判定そのもの
  （`discardsTheAnswer` / `looksLikeExistenceProbe`）は切り出してあり、
  違反する見本を食わせる検査が見ています。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/scheduler/bare_log_and_return_test.go'
B = 'server/internal/scheduler/backup_scheduler.go'
D = 'server/internal/scheduler/darkweb_scheduler.go'
A = 'server/internal/scheduler/api_key_rotator.go'
RC = 'server/internal/scheduler/realtime_correlator.go'
CSC = 'server/internal/scheduler/compliance_scorer.go'
IOT = 'server/internal/api/handlers/iot_ot_handler.go'
PT = 'server/internal/store/probe_error_test.go'

# 列の存在確認。**まとめて1つの変異にしてあります** —— 受け口だけ、
# 分岐だけを戻すと構文として通らず、「検査が落ちた」のか「ビルドが
# 落ちた」のかが区別できません。
PROBE_NOW = """\tif err := r.pool.QueryRow(ctx,
\t\t`SELECT EXISTS (
\t\t\tSELECT 1 FROM information_schema.columns
\t\t\tWHERE table_schema = 'public'
\t\t\t  AND table_name   = 'api_keys'
\t\t\t  AND column_name  = 'expires_at'
\t\t)`,
\t).Scan(&hasExpiresAt); err != nil {
\t\tfail(ctx, err, "APIKeyRotator: expires_at列の存在確認に失敗しました")
\t\treturn
\t}
"""

PROBE_WAS = """\t_ = r.pool.QueryRow(ctx,
\t\t`SELECT EXISTS (
\t\t\tSELECT 1 FROM information_schema.columns
\t\t\tWHERE table_schema = 'public'
\t\t\t  AND table_name   = 'api_keys'
\t\t\t  AND column_name  = 'expires_at'
\t\t)`,
\t).Scan(&hasExpiresAt)
"""

# ISO 27001 のスコア。**まとめて1つの変異にしてあります** ——
# 元の実装は `_ =` で存在確認の error を捨てる形で、そこまで戻さないと
# 「捨てている」ことを見る検査に当たりません。
SCORER_NOW = """\tvar recentAuditLogs int
\tif store.TableIsThere(ctx, s.pool, "audit_logs") {
\t\tif err := s.pool.QueryRow(ctx, `
\t\t\tSELECT COUNT(*) FROM audit_logs WHERE created_at >= NOW() - INTERVAL '30 days'`,
\t\t).Scan(&recentAuditLogs); err != nil {
\t\t\tfail(ctx, err, "コンプライアンススコア: 監査ログを数えられないため記録しません")
\t\t\treturn
\t\t}
\t}
"""

SCORER_WAS = """\tvar auditLogCount int
\t_ = s.pool.QueryRow(ctx, `
\t\tSELECT COUNT(*) FROM information_schema.tables
\t\tWHERE table_schema='public' AND table_name='audit_logs'`).Scan(&auditLogCount)
\tvar recentAuditLogs int
\tif auditLogCount > 0 {
\t\t_ = s.pool.QueryRow(ctx, `
\t\t\tSELECT COUNT(*) FROM audit_logs WHERE created_at >= NOW() - INTERVAL '30 days'`,
\t\t).Scan(&recentAuditLogs)
\t}
\t_ = store.TableIsThere
"""

CASES = [
    # ── 直した5か所 ──────────────────────────────────────────────────────
    (B, '\t\tfail(ctx, pgErr, "pg_dumpに失敗しました")\n',
        '\t\tslog.Error("pg_dumpに失敗しました", "error", pgErr)\n',
     'pg_dump の失敗が、回に届かなくなる（**元の実装。バックアップを1つも'
     '取れていない回が、成功として刻まれます**）'),
    (B, '\t\tfail(ctx, verifyErr, "バックアップの整合性検証に失敗しました", "filename", filename)\n',
        '\t\tslog.Error("バックアップの整合性検証に失敗しました", "filename", filename, "error", verifyErr)\n',
     '整合性検証の失敗が、回に届かなくなる（**元の実装**）'),
    (D, '\t\tfail(ctx, err, "ダークウェブ: 照合対象を取得できませんでした")\n',
        '\t\tslog.Error("ダークウェブ: 照合対象を取得できませんでした", "error", err)\n',
     'ダークウェブの照合対象が読めなかったことが、回に届かなくなる'
     '（**「何も出ていない」が正常な画面なので、動いていないことと'
     '区別がつきません**）'),
    (D, '\t\tfail(ctx, err, "darkweb: キャッシュした投稿一覧を解釈できず、照合を行いませんでした")\n',
        '\t\tslog.Error("darkweb: キャッシュした投稿一覧を解釈できず、照合を行いませんでした", "error", err)\n',
     'キャッシュを解釈できなかったことが、回に届かなくなる'),
    (A, PROBE_NOW, PROBE_WAS,
     '列の存在確認の error をまた捨てる（**元の実装。DB が応答しない'
     'だけで「列が無い」になり、期限切れ間近の API キーの通知が'
     '丸ごと飛びます**）'),
    (RC, '\t\tmetrics.BackgroundFailed("realtime_correlator", err,\n'
         '\t\t\t"相関: アラートのメッセージを解釈できず、相関に載せませんでした")\n',
         '\t\t_ = metrics.BackgroundFailed\n'
         '\t\tslog.Error("相関: アラートのメッセージを解釈できず、相関に載せませんでした", "error", err)\n',
     '相関に載らなかったアラートが、計測に出なくなる（**元の実装。'
     'ここは回の外なので、部品ごとの件数が唯一の出口です**）'),

    # ── 捨てていた存在確認（同じ形が他に2つありました） ──────────────────
    (CSC, SCORER_NOW, SCORER_WAS,
     'ISO 27001 のスコアが、`audit_logs` の有無を確かめずに計算される'
     '（**元の実装。DB が一時的に応答しないだけで 20 点低いスコアが'
     '履歴に書かれます** —— 監査ログが在るのに「A.12.4 未達」）'),
    (IOT, '\tcolErr := h.pool.QueryRow(ctx,\n'
          '\t\t`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name=\'iot_devices\' AND column_name=\'protocol\')`).Scan(&colExists)\n'
          '\tcolExists = probeAnswer(colExists, colErr)\n',
          '\t_ = h.pool.QueryRow(ctx,\n'
          '\t\t`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name=\'iot_devices\' AND column_name=\'protocol\')`).Scan(&colExists)\n',
     '列の存在確認が失敗しても「列が無い」と答える（**元の実装。機器の'
     'protocol / network_zone が既定値で画面に並びます**）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (PT, '\tid, ok := as.Lhs[0].(*ast.Ident)\n\treturn ok && id.Name == "_"',
         '\t_, ok := as.Lhs[0].(*ast.Ident)\n\treturn ok',
     '`_ =` 以外の受け方まで「捨てている」に数える'),
    (PT, '\treturn strings.Contains(low, "information_schema") || strings.Contains(low, "pg_tables")',
         '\treturn strings.Contains(low, "information_schema_XXX")',
     '`pg_tables` の存在確認を1つも見つけなくなる（**前にも同じ狭め方で'
     '30 か所を見落としました**）'),
    (PT, 'const minProbeQueries = 15', 'const minProbeQueries = 0',
     '走査の床を 0 に落とす'),

    (T, '\t\tcase *ast.CaseClause:\n\t\t\tlist = v.Body\n', '',
     '`switch` の枝の中の書き捨てを見なくなる'),
    (T, '\t\tcase *ast.CommClause:\n\t\t\tlist = v.Body\n', '',
     '`select` の枝の中の書き捨てを見なくなる'),
    (T, '\t\tret, ok := list[i+1].(*ast.ReturnStmt)\n\t\t\tif !ok || len(ret.Results) != 0 {',
        '\t\tret, ok := list[i+1].(*ast.ReturnStmt)\n\t\t\tif !ok || len(ret.Results) < 0 {',
     '値を返している `return` まで「書き捨て」に数える'),
    (T, '\tif !ok || pkg.Name != "slog" {', '\tif !ok || pkg.Name == "" {',
     '`slog` 以外の同じ形まで数える'),
    (T, '\tcall, ok := es.X.(*ast.CallExpr)\n\tif !ok {\n\t\treturn nil\n\t}\n',
        '\tcall, ok := es.X.(*ast.CallExpr)\n\tif !ok {\n\t\treturn nil\n\t}\n\t_ = call\n\treturn nil\n',
     '`slog.X(…)` を1つも見つけなくなる（**0件を検査して緑**）'),
    (T, 'const minBareLogAndReturnSites = 20', 'const minBareLogAndReturnSites = 0',
     '走査の床を 0 に落とす'),
    (T, 'const bareLogAndReturnSiteCount = 31', 'const bareLogAndReturnSiteCount = 100',
     '件数を留めなくなる（**同じ関数に増やした分が、鍵の検査では'
     '見えません**）'),
    (T, '\treturn reasons[s.key()] == ""\n', '\treturn false\n',
     '理由の無い箇所を1件も挙げなくなる（**新しい書き捨てが黙って'
     '通ります**）'),
    (T, '\t\tif !seen[key] {\n\t\t\tstale = append(stale, key)\n\t\t}\n', '\t\t_ = key\n',
     '宛先の消えた理由が残っても気づかなくなる（**次に同じ場所が'
     '生えたときに黙って通ります**）'),
    (T, '\tfor _, s := range sites {\n\t\tseen[s.key()] = true\n\t}\n', '',
     '在る宛先を1つも覚えない（**理由が全部「古い」になります** —— '
     'その逆確認）'),
    (T, 'func (s bareSite) key() string { return s.file + ":" + s.fn }',
        'func (s bareSite) key() string { return s.file }',
     '理由の宛先をファイル単位にする（**同じファイルの別の関数が、'
     '書いてある理由で通ります**）'),
]

RUN = ('TestEveryBareLogAndReturnHasAReason|'
       'TestTheBareLogAndReturnScanRecognisesTheRealThing|'
       'TestTheBareLogAndReturnFloorNoticesAnEmptyWalk|'
       'TestTheBareLogAndReturnReasonsCoverTheMeasuredSites|'
       'TestTheBareLogAndReturnJudgementRecognisesTheRealThing|'
       'TestTheStaleReasonScanRecognisesTheRealThing|'
       'TestEverySchedulerRecordsThatItRan|'
       'TestNoExistenceProbeThrowsAwayItsError|'
       'TestTheProbeErrorJudgementRecognisesTheRealThing|'
       'TestTheProbeScanFloorNoticesAnEmptyWalk')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/scheduler/', './internal/store/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

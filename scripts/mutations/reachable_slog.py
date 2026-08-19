#!/usr/bin/env python3
"""`tick.Run` から届く `slog.Error` が、回にも届くこと。

対象:
  server/internal/api/handlers/alert_enrichment_pipeline.go
  server/internal/cloud/poller.go
  server/internal/shipper/elasticsearch.go
  server/internal/detection/risk_action.go
  server/internal/sync/wazuh.go
  server/internal/updater/applier.go

前回、`tick.Run` から3段たどって `metrics.BackgroundFailed` を 10 か所
見つけました。**同じ到達判定で `slog.Error` を探すと、さらに 13 か所**
出ました。**続けて `slog.Warn` を探すと 30 か所**あり、19 を移しました
（`Warn` は運用の設定で最初に切られる段です —— このセッションでも
`Error` を `Warn` に落とす変更が検査を通ったことがありました）。

**`internal/scheduler` も `slog.Error` については全部見ます**
（2026-08-12）。あちらを走査に入れると 13 か所あり、どれも
「この回は仕事を終えられなかった」でした —— 証明書の状態更新、
コンプライアンススコアの保存、エスカレーション、レポートメール、
ダイジェストメール、フィード取得、デッドエージェントの非アクティブ化、
KPI 定義の引き当て、ベースラインの除外ルール。`fail` に移しました。

`slog.Warn` は 54 か所ありました。**error 値を持っていた 45 を `fail` に
移し**、残り 9 の宛先（検出の報告・設定の話・テーブルがまだ無い配置）に
理由を書きました。`internal/scheduler` も走査に入れています。

「黙って捨てる」21 か所も読みました。**どれも `for rows.Next()` の中の
`rows.Scan` で、直後の `rows.Err()` が `fail` に出しています** ——
pgx は Scan が失敗した時点で結果セットを終えるので、`continue` は1行を
飛ばすのではなく走査が終わります。理由を書いて走査に入れました。

**これで3つの段とも `server/internal` 全体を見ています。**

最後に「error を受け取って何も言わない分岐」を測ると 4 か所で、
どれも直後に `rows.Err()`／`skipped` の件数でまとめて報告していました
——**pgx は Scan が失敗した時点で結果セットを終える**ので、`continue`
は1行を飛ばすのではなく、そこで走査が終わります（`internal/scheduler` の中は「ログして戻る」の検査が別に
見ています）。

    alert_enrichment  テーブル確認の失敗（**この回は何も濃くしていません**）
    cloud/poller      設定を読めない統合／イベントを組み立てられない
                      （画面上は「設定済み」のまま、一度も収集されません）
    shipper           **ES が受け取らなかった文書**（送信自体は成功なので、
                      ログ以外に跡が残りません）
    risk_action       **自動隔離の失敗**（成功時だけ severity 10 の
                      アラートが立ち、失敗は画面のどこにも出ませんでした）
                      ／その失敗アラートの保存に失敗
    sync/wazuh        端末ごとの脆弱性取得（合計だけ見ると「脆弱性なし」）
    updater/applier   ロールバック記録の失敗（**行が 'applying' のまま
                      残ります**）
    detection/anomaly ベースライン更新／異常検知（**古い土台の上で
                      判定し続けます**）

置いていない変異:

  `internal/scheduler` の中の 12 か所には置いていません。**あちらは
  `bare_log_and_return.py` が理由つきで留めています。**

  「分類のない箇所を挙げる」判定への変異は置いていません。**判定は
  `background_failed.py` と同じ `siteNeedsClassifying` で、あちらが
  見ています。**

  到達判定そのものへの変異は `background_failed.py` にあります
  （`trackedCallDepth`、クロージャ、鍵の形）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

AE = 'server/internal/api/handlers/alert_enrichment_pipeline.go'
CP = 'server/internal/cloud/poller.go'
ES = 'server/internal/shipper/elasticsearch.go'
RA = 'server/internal/detection/risk_action.go'
WZ = 'server/internal/sync/wazuh.go'
UP = 'server/internal/updater/applier.go'
SK = 'server/internal/api/handlers/skipped_row_test.go'
AW = 'server/internal/api/handlers/answered_with_a_value_test.go'
W = 'server/internal/tick/tracked_workers_test.go'

CASES = [
    (AE, '\t\ttick.Fail(ctx, err, "アラートエンリッチメント: alerts テーブルの有無を確認できませんでした")\n',
         '\t\tslog.Error("アラートエンリッチメント: alerts テーブルの有無を確認できませんでした", "error", err)\n',
     'エンリッチメントのテーブル確認の失敗が、回に届かなくなる（元の実装）'),
    (CP, '\t\t\ttick.Fail(ctx, err, "クラウド統合の設定を読めませんでした。この統合は収集されません",\n'
         '\t\t\t\t"integration", intg.Name, "provider", intg.Provider)\n',
         '\t\t\tslog.Error("クラウド統合の設定を読めませんでした。この統合は収集されません",\n'
         '\t\t\t\t"integration", intg.Name, "provider", intg.Provider, "error", err)\n',
     '設定を読めないクラウド統合が、回に届かなくなる（**画面上は'
     '「設定済み」のまま、一度も収集されません**）'),
    (RA, '\t\t\ttick.Fail(ctx, err, "RiskActionMonitor: 自動隔離に失敗しました",\n',
         '\t\t\tslog.Error("RiskActionMonitor: 自動隔離に失敗しました",\n',
     '**自動隔離の失敗**が、回に届かなくなる（元の実装。成功時だけ'
     'アラートが立つので、失敗は画面のどこにも出ません）'),
    (WZ, '\t\t\ttick.Fail(ctx, err, "Wazuh: 端末の脆弱性を取得できませんでした",\n'
         '\t\t\t\t"wazuh_agent", wa.ID)\n',
         '\t\t\tslog.Error("Wazuh: 端末の脆弱性を取得できませんでした",\n'
         '\t\t\t\t"wazuh_agent", wa.ID, "error", err)\n',
     '端末ごとの脆弱性取得の失敗が、回に届かなくなる（**合計だけ見ると'
     '「脆弱性なし」に読めます**）'),
    (UP, '\ttick.Fail(ctx, cause, "applier: step failed", "id", id, "step", step)\n',
         '\tslog.Error("applier: step failed", "id", id, "step", step, "error", cause)\n',
     '更新の失敗が、回に届かなくなる'),

    # ── 直した箇所が、理由の一覧からも消えていること ─────────────────────
    (SK, '\t// `cloud/poller.go:poll` は直しました (2026-08-12) —— 記録だけでなく\n',
         '\t"cloud/poller.go:poll": "直したのに理由が残っています",\n\t// \n',
     '直した箇所の理由が一覧に残っても気づかなくなる（**次に同じ形が'
     '生えたときに黙って通ります**）'),
    (AW, '\tconst want = 36', '\tconst want = 37',
     '理由つきで外した件数を実測から引き離す'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (W, 'const reachableSlogErrorSites = 3', 'const reachableSlogErrorSites = 100',
     '件数を留めなくなる'),
    (W, 'const reachableSlogWarnSites = 22', 'const reachableSlogWarnSites = 100',
     '`Warn` の件数を留めなくなる'),
    (W, 'const silentErrorBranchSites = 27', 'const silentErrorBranchSites = 100',
     '**黙って捨てた error** の件数を留めなくなる'),
    (W, '\t\tcase *ast.CallExpr:\n\t\t\tsilent = false\n', '',
     '報告している分岐まで「黙っている」に数える（**`tick.Fail` を'
     '書いた箇所が全部違反になります**）'),
    (W, '\t\t\tif len(v.Results) > 0 {', '\t\t\tif len(v.Results) < 0 {',
     '`return err` を「黙っている」に数える（**呼び出し側が受け取って'
     'いても違反になります**）'),
    (W, 'strings.Contains(strings.ToLower(id.Name), "err")',
        'strings.Contains(strings.ToLower(id.Name), "")',
     'error でない変数の分岐まで数える'),
    (W, '\tfound := reachableLogSites(t, "Warn", warnScanSkip)', '\tfound := reachableLogSites(t, "Error", warnScanSkip)',
     '`Warn` の代わりに `Error` を見る（**`Warn` 止まりが全部'
     '素通りします**）'),
    ('server/internal/cloud/poller.go',
     '\t\ttick.Fail(ctx, err, "クラウドイベントのNATS送信に失敗")\n',
     '\t\tslog.Warn("クラウドイベントのNATS送信に失敗", "error", err)\n',
     '検知に届かなかったクラウドイベントが、`Warn` 止まりに戻る'),
    ('server/internal/reports/scheduler.go',
     '\t\ttick.Fail(ctx, err, "scheduler: report generation failed", "id", r.ID)\n',
     '\t\tslog.Warn("scheduler: report generation failed", "id", r.ID, "error", err)\n',
     'レポートを作れなかったことが、`Warn` 止まりに戻る'),
    (W, '\tif !ok || sel.Sel.Name != level {\n\t\treturn false\n\t}\n', '',
     '`slog` のどの段でも「ログ止まり」に数える（**`slog.Info` まで'
     '違反になります**）'),
    (W, '\treturn ok && pkg.Name == "slog"', '\treturn ok && pkg.Name != ""',
     '`slog` 以外の同名関数まで数える'),
    (W, 'var slogScanSkip = []string{}',
        'var slogScanSkip = []string{"scheduler/"}',
     '`slog.Error` の走査から `internal/scheduler` をまた外す'
     '（**13 か所が見えなくなります**）'),
    (W, 'var warnScanSkip = []string{}',
        'var warnScanSkip = []string{"scheduler/"}',
     '`slog.Warn` の走査から `internal/scheduler` をまた外す'
     '（**45 か所直した package が見えなくなります**）'),
    (W, 'var silentScanSkip = []string{}',
        'var silentScanSkip = []string{"scheduler/"}',
     '「黙って捨てる」の走査から `internal/scheduler` をまた外す'
     '（**21 か所が見えなくなります**）'),
    ('server/internal/scheduler/incident_escalation.go',
     '\t\tfail(ctx, err, "高重大度エスカレーション失敗")\n',
     '\t\tslog.Warn("高重大度エスカレーション失敗", "error", err)\n',
     '高重大度インシデントのエスカレーション失敗が、`Warn` 止まりに戻る'),
    ('server/internal/scheduler/incident_escalation.go',
     '\t\tfail(ctx, err, "クリティカルエスカレーション失敗")\n',
     '\t\tslog.Error("クリティカルエスカレーション失敗", "error", err)\n',
     'クリティカルインシデントのエスカレーション失敗が、回に届かなく'
     'なる（元の実装）'),
    ('server/internal/detection/anomaly.go',
     '\t\ttick.Fail(ctx, err, "異常検知エラー")\n',
     '\t\tslog.Error("異常検知エラー", "error", err)\n',
     '異常検知の失敗が、ログ止まりに戻る（**古いベースラインの上で'
     '判定し続けていることが、外から見えません**）'),
]

RUN = ('TestNoSkipExceptionHasGoneStale|TestNoReturnExceptionHasGoneStale|'
       'TestReturnExceptionCountIsPinned|TestFailuresAreNotAnsweredWithAValue|'
       'TestTrackedWorkersDoNotReportPastTheRun|'
       'TestTrackedWorkersDoNotReportOnlyToTheLog|'
       'TestTheSlogErrorDetectorRecognisesTheRealThing|'
       'TestTheSlogScanSkipListIsExactlyTheScheduler|'
       'TestTrackedWorkersDoNotDowngradeToWarn|'
       'TestTrackedWorkersDoNotSwallowErrorsSilently|'
       'TestTheSilentErrorJudgementRecognisesTheRealThing')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/api/handlers/', './internal/tick/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

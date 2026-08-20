#!/usr/bin/env python3
"""端末に届かなかった指示を「しました」と答えないこと。

対象:
  server/internal/api/handlers/agents_handler.go
  server/internal/api/handlers/quarantine_handler.go
  server/internal/api/handlers/auth_handler.go
  server/internal/api/handlers/reports_handler.go
  server/internal/api/handlers/discarded_store_error_test.go
  server/internal/tick/background_failed_test.go

走査を `_ = h.<ストア>.<メソッド>(…)` の形にも広げて出てきた 20 か所を
読みました。**一番重いのは隔離です。**

    Isolate  DB は `isolated` になりますが、端末に指示が届かなければ
             その端末はネットワークに繋がったままで、応答は
             「隔離しました」と答えていました。

ハートビートには `should_unisolate`（DB が解除済みなら端末に巻き戻しを
指示する）がありますが、**`should_isolate` はありません**（実測
2026-08-12）。つまり**この送信が失敗したら、端末は二度と隔離されません。**
いまは 500 で答えます。解除の方は次のハートビートが巻き戻すので、跡だけ
残します —— **同じ形に見えて、答え方が違います。**

ほかに直したもの: 対応操作の記録8種（インシデントの時系列から誰がいつ
何をしたかが抜ける）、検疫からの復元（画面は「復元済み」、実物は検疫の
まま）、ログインのセッション記録（一覧に出ず強制ログアウトもできない）、
初回パスワード変更フラグ、webhook の登録（一覧には出るのに一度も発火
しない）、レポートジョブの3状態、ハートビートのアラート解決、
フィードの同期記録。

置いていない変異:

  20 か所すべてへの変異は置いていません。**1つ戻せば
  `discardedStoreErrors` が 0 から 1 になります** —— 代表して、答え方が
  分かれたものに置いてあります。

## 対応操作の記録の反転を殺せるようにしたこと

対応操作の記録で `err != nil` を `err == nil` に反転する変異は、
**DB 無しでは殺せない**ものとしてここに書き残していました —— 通る木では
どちらの分岐も通らないので、走査でも件数でも見分けがつきません。

`AgentHandler.ResponseActions` を具体型
（`*store.ResponseActionStore`）からインターフェイス
（`ResponseActionRecorder`）に変えて、**失敗する記録先を渡せる**ように
しました（`response_action_record_test.go`）。DB は要りません ——
要るのは「失敗する書き込み先」だけです。

反転した先は「**記録できたときに失敗を報告し、できなかったときは
黙る**」で、応答は「隔離しました」のまま返ります。事後の調査は
「誰も隔離していないのに端末が切れている」という形で始まります。

指示の送信の方は `command_delivery_test.go` が形（`err != nil`・5xx・
`return`）を見ているので、前から殺せます。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

AH = 'server/internal/api/handlers/agents_handler.go'
QH = 'server/internal/api/handlers/quarantine_handler.go'
RH = 'server/internal/api/handlers/reports_handler.go'
T = 'server/internal/api/handlers/discarded_store_error_test.go'
BF = 'server/internal/tick/background_failed_test.go'

CASES = [
    # ── 元の実装に戻す ───────────────────────────────────────────────────
    # #757 以降、隔離は Gatekeeper 1 本を通る。ハンドラが直接 Commander を
    # 叩く形は無くなったので、同じ趣旨を現在の呼び出しに当て直す。
    (AH, '\t}); err != nil {\n\t\tslog.Error("隔離コマンドの送信に失敗しました", "agent", id, "error", err)',
         '\t}); err == nil {\n\t\tslog.Error("隔離コマンドの送信に失敗しました", "agent", id, "error", err)',
     '**届いた方を失敗として扱う**（届かなかった回は「隔離しました」に'
     '戻ります）'),
    (AH, '\t\tc.JSON(http.StatusBadGateway, gin.H{\n'
         '\t\t\t"error": "隔離を記録しましたが、エンドポイントへの指示に失敗しました。端末はまだネットワークに接続されています",\n'
         '\t\t\t"id":    id,\n\t\t})\n\t\treturn\n',
         '',
     '**届かなくても「隔離しました」と答える**（元の実装。指示が届かない'
     'まま 200 を返すと、DB と画面だけが隔離済みになります）'),

    (QH, '\t\t\tc.JSON(http.StatusInternalServerError, gin.H{\n'
         '\t\t\t\t"error": "復元コマンドを端末に届けられませんでした。ファイルは検疫のままです",\n'
         '\t\t\t})\n\t\t\treturn\n',
         '',
     '**復元コマンドが届かなくても先へ進む**（`MarkRestored` だけが通り、'
     '画面は「復元済み」、実物は検疫のままです）'),
    (RH, '\t\tif err := h.ReportStore.Complete(ctx, jobID, payload); err != nil {\n'
         '\t\t\tmetrics.BackgroundFailed("report_job", err,\n'
         '\t\t\t\t"出来上がったレポートを保存できませんでした。running のまま取り出せません",\n'
         '\t\t\t\t"job_id", jobID, "type", reportType)\n\t\t}',
         '\t\t_ = h.ReportStore.Complete(ctx, jobID, payload)',
     '出来上がったレポートの保存失敗が黙る（**`running` のまま'
     '取り出せません**）'),

    # ── 対応操作の記録（失敗する記録先を渡して殺す） ─────────────────────
    (AH, '\tif _, err := h.ResponseActions.Record(c.Request.Context(), agentID, action, status, by, details); err != nil {',
         '\tif _, err := h.ResponseActions.Record(c.Request.Context(), agentID, action, status, by, details); err == nil {',
     '**記録できたときに失敗を報告し、できなかったときは黙る**'
     '（時系列から操作が抜けたことに誰も気づけません）'),
    (AH, '\tif h.ResponseActions == nil {\n\t\treturn\n\t}\n'
         '\tif _, err := h.ResponseActions.Record(c.Request.Context(), agentID, action, status, by, details); err != nil {',
         '\tif h.ResponseActions == nil {\n\t\treturn\n\t}\n'
         '\tif _, err := h.ResponseActions.Record(c.Request.Context(), agentID, status, action, by, details); err != nil {',
     '**操作と状態を入れ替える**（行は残るのに「何をしたか」が'
     '別のものになります）'),
    (AH, '\tif h.ResponseActions == nil {\n\t\treturn\n\t}\n', '',
     '記録先を持たない構成で nil を呼ぶ（起動構成によっては落ちます）'),

    # ── 件数 ─────────────────────────────────────────────────────────────
    (T, 'const discardedStoreErrors = 0', 'const discardedStoreErrors = 100',
     '件数を留めなくなる'),
    (BF, '\tbackgroundFailedCount = 68', '\tbackgroundFailedCount = 500',
     '`metrics.BackgroundFailed` の件数を留めなくなる'),
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestHandlersDoNotDiscardStoreErrors|TestTheStoreErrorRecogniserLooksAtTheShape|'
         'TestACommandThatDidNotReachTheEndpointIsNotAnsweredWithSuccess|'
         'TestTheCommandDeliveryRuleActuallyFires|TestTheHeartbeatOnlyRollsBackIsolation|'
         'TestAFailedResponseActionRecordIsReported|TestNoResponseActionStoreIsNotAFailure',
         './internal/api/handlers/'],
    cwd='server',
)

BF_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', 'TestEveryBackgroundFailedSiteIsClassified',
         './internal/tick/'],
    cwd='server',
)

BF_ONLY = {BF}
if __name__ == '__main__':
    rc = HARNESS.run([c for c in CASES if c[0] not in BF_ONLY])
    rc |= BF_HARNESS.run([c for c in CASES if c[0] in BF_ONLY])
    sys.exit(rc)

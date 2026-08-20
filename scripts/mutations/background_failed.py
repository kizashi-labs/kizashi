#!/usr/bin/env python3
"""`metrics.BackgroundFailed` を呼んでよい場所が、分類されていること。

対象:
  server/internal/tick/background_failed_test.go
  server/internal/detection/correlation.go
  server/internal/tick/tracked_workers_test.go
  server/internal/shipper/elasticsearch.go

失敗を報告する綴りは3つあり、**答える問いが違います**:

    BackgroundFailed  この部品が失敗した（edr_background_failures_total）
    Fail              この回が仕事を終えられなかった（last_success を押さない）
    FailComponent     その両方

「回」があるのは**周期的に回る仕事の中だけ**です。`tick.Run` に直に
渡している関数の中で `BackgroundFailed` を呼ぶのは違反で、そちらは
`TestTrackedWorkersDoNotReportPastTheRun` が 0 件に留めています。

**その外の 58 か所は「そのままで正しいはず」と書いたまま、確かめて
いませんでした。** 1つずつ読んだ結果 (2026-08-12):

    起動時        8  プロセス起動時に一度だけ
    要求ごと      5  利用者が待っていて、応答でも分かります
    イベントごと 21  1件ごと。呼び出し側は次のイベントです
    errorを返す  11  呼び出し側が受け取ります
    仕組み        1  internal/tick 自身

**1つは分類できませんでした。** `detection/correlation.go:upsertCase` は
`tick.Run` で回している `runOnce` から呼ばれています —— 上の検査は
`tick.Run` に**直に渡している関数**しか見ていないので、そこから呼ばれる
関数は漏れます。`tick.FailComponent` に移しました（58 → 56）。

**そこで検査を3段たどるように広げたら、さらに 10 か所出ました**（56 → 46）:

    shipper.Flush 2・wazuh.SyncAgents 2・compliance.EvaluateAll・
    heartbeat_monitor.createOfflineAlert・virustotal 2・
    threatintel.FetchURLhaus・threatintel.syncPublicFeeds

`shipper.Flush` は `tick.Run(ctx, "es", func(ctx){ s.Flush(ctx) })` の形で、
**クロージャに包まれていたので直に渡している関数としても見えて
いませんでした。**

置いていない変異:

  分類そのもの（どの箇所がどの分類か）への変異は置いていません。
  **分類を1つ書き換えても、5つのどれかである限り検査は通ります** ——
  それは一覧の中身の話で、仕組みの話ではありません。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/tick/background_failed_test.go'
C = 'server/internal/detection/correlation.go'
W = 'server/internal/tick/tracked_workers_test.go'

CASES = [
    (C, '\t\t\ttick.FailComponent(ctx, "correlation", e,',
        '\t\t\tmetrics.BackgroundFailed("correlation", e,',
     'インシデント自動作成の失敗が、部品の件数だけになる（**`tick.Run` で'
     '回している仕事の中なので、その回は成功として刻まれます**）'),

    ('server/internal/shipper/elasticsearch.go',
     '\t\ttick.FailComponent(ctx, "es_shipper", err, "ES bulk 送信失敗", "docs", len(docs))\n',
     '\t\tmetrics.BackgroundFailed("es_shipper", err, "ES bulk 送信失敗", "docs", len(docs))\n'
     '\t\t_ = tick.Failing\n',
     'Elasticsearch への送信失敗が、部品の件数だけになる（**`tick.Run` で'
     '回している仕事の中なので、その回は成功として刻まれます**）'),
    (W, '\t\t\tcase *ast.FuncLit:\n', '\t\t\tcase *ast.BadExpr:\n',
     'クロージャで包んだワーカーを見なくなる（**`tick.Run(ctx, "es", '
     'func(ctx){ s.Flush(ctx) })` の形が丸ごと外れます**）'),
    (W, '!names[pkg+"|"+fn.Name.Name]', '!names[pkg+"/"+fn.Name.Name]',
     '走査の鍵を名前の集合と違う形にする（**照合が全部外れて、'
     '0 件を検査して緑になります**）'),
    (W, 'const minMatchedWorkerDecls = 120', 'const minMatchedWorkerDecls = 0',
     '鍵が合っているかの床を 0 に落とす'),
    (W, 'const trackedCallDepth = 3', 'const trackedCallDepth = 1',
     '呼ばれる先をたどらなくなる（**`upsertCase` のように、渡した関数から'
     '呼ばれる先が漏れます**）'),
    (W, 'const minTrackedWorkerNames = 120', 'const minTrackedWorkerNames = 0',
     '到達した関数の床を 0 に落とす'),

    (T, 'backgroundFailedCount = 75', 'backgroundFailedCount = 500',
     '箇所の数を留めなくなる'),
    (T, 'backgroundFailedFuncs = 60', 'backgroundFailedFuncs = 500',
     '宛先の数を留めなくなる'),
    (T, '\treturn m[key] == ""\n', '\treturn false\n',
     '分類の無い箇所を1件も挙げなくなる（**新しい呼び出しが黙って'
     '通ります**）'),
    (T, '\t\tif !seen[key] {\n\t\t\tstale = append(stale, key)\n\t\t}\n', '\t\t_ = key\n',
     '宛先の消えた分類が残っても気づかなくなる'),
    (T, '\tcase catStartup, catPerReq, catPerEvent, catReturns, catMechanism, catUntracked:\n\t\treturn true\n', '',
     '5つ以外の自由文を分類として認める（**「あとで見る」でも通ります**）'),
    (T, '\treturn len(counts) >= 4\n', '\treturn true\n',
     '全部を1つの分類に寄せても通る（**分類が1種類なら分類ではありません**）'),
]

RUN = ('TestEveryBackgroundFailedSiteIsClassified|'
       'TestEveryClassificationIsOneOfTheFive|'
       'TestTheClassificationStalenessScanRecognisesTheRealThing|'
       'TestTheClassificationJudgementsRecogniseTheRealThing|'
       'TestTrackedWorkersDoNotReportPastTheRun|'
       'TestClosureWrappedWorkersAreSeeded|TestTheMatchedDeclFloorIsNotHollowedOut|'
       'TestTheTrackedWorkerNameFloorNoticesAnEmptyWalk')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/tick/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

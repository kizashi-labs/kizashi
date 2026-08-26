#!/usr/bin/env python3
"""失敗の行き先が、数を消すためだけの呼び出しになっていないか。

対象:
  server/internal/metrics/metrics.go              （BackgroundFailed / AlertDropped）
  server/internal/metrics/background_failed_test.go
  server/internal/metrics/alert_dropped_test.go

answered_with_a_value_test.go は、分岐にログ以外の呼び出しがあれば
「値で答えているだけではない」として数えません。**つまり slog.Error を
BackgroundFailed に書き換えるだけで、43箇所が上限から静かに消えます。**
それが正しいのは、BackgroundFailed が本当に別の行き先を持っているあいだ
だけです。中身が slog に戻ったら、43箇所は消えたまま戻ってきません。

この形は、このキャンペーンでいちばん危ない書き換えです。数字は下がり、
コミットは通り、外から見える情報は1ビットも増えていません。

AlertDropped も同じ理由でここにあります。こちらは一度 edr_alerts_dropped_total
という新しい counter を足しましたが、edr_alert_insert_failures_total が
同じ事実をすでに数えていたので畳みました。**同じ事実に名前が2つあると、
片方だけを見ている画面が生まれます。**
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

M = 'server/internal/metrics/metrics.go'
BT = 'server/internal/metrics/background_failed_test.go'
AT = 'server/internal/metrics/alert_dropped_test.go'
GATE = 'server/internal/api/handlers/answered_with_a_value_test.go'

CASES = [
    # ── 行き先そのもの ─────────────────────────────────────────────────────
    (M, '\tBackgroundFailures.WithLabelValues(component).Inc()\n'
        '\tBackgroundLastFailureTimestamp.WithLabelValues(component)'
        '.Set(float64(time.Now().Unix()))',
        '',
     'BackgroundFailed が、またログ行だけに戻る'),
    (M, '\tBackgroundLastFailureTimestamp.WithLabelValues(component)'
        '.Set(float64(time.Now().Unix()))',
        '',
     '最終失敗時刻が動かなくなる（去年100回と今100回が同じ形になる）'),
    (M, '\tslog.Error(msg, append(args, "component", component, "error", err)...)',
        '',
     '理由が残らなくなる（件数は指標にあるが、なぜかはログにしか無い）'),
    (M, '\tBackgroundFailures.WithLabelValues(component).Inc()',
        '\tBackgroundFailures.WithLabelValues("all").Inc()',
     '全経路が1つのラベルに潰れ、どこが止まっているか分からなくなる'),
    (M, '\tAlertInsertFailures.WithLabelValues(source).Inc()', '',
     '出すと決めた警報が消えたことが、どこにも数えられなくなる'),
    (M, '\t\t"source", source, "title", title, "error", err)',
        '\t\t"source", source, "error", err)',
     'どのアラートが消えたのか分からなくなる'),

    # ── 見張る側 ───────────────────────────────────────────────────────────
    (BT, '\t"BackgroundFailures",             // 何回失敗したか\n'
         '\t"BackgroundLastFailureTimestamp", // いつ失敗したか',
         '',
     '検査が、指標への書き込みを求めなくなる'),
    (BT, '\t"slog.",                          // なぜ失敗したか', '',
     '検査が、ログへの書き込みを求めなくなる'),
    (BT, '\t"BackgroundLastFailureTimestamp", // いつ失敗したか',
         '\t"BackgroundLastFailureTimestampX", // いつ失敗したか',
     '求めるものの名前が、実在しないものを指す'),
    (AT, '\t`"title", title`,      // どのアラートか（宣言ではなく、記録に載っていること）', '',
     'アラート名の記録を求めなくなる'),
    (AT, '\t`"title", title`,      // どのアラートか（宣言ではなく、記録に載っていること）',
         '\t"title",               // どのアラートか（宣言ではなく、記録に載っていること）',
     '探す文字列が、引数の宣言だけで満たされる形に戻る'),

    # ── 上限と理由リスト ───────────────────────────────────────────────────
    (GATE, '\tanswerReturnCeiling = 13', '\tanswerReturnCeiling = 20',
     'return の上限が0から上がる'),
    (GATE, '\t\tif s.kind == "return" {\n'
           '\t\t\tif _, ok := returnExceptions[s.file+":"+s.fn]; ok {\n'
           '\t\t\t\tcontinue\n\t\t\t}\n\t\t}',
           '',
     '理由リストが何も外さなくなる'),

    # ── 実際の呼び出し側 ───────────────────────────────────────────────────
    ('server/internal/notify/notifier.go',
     'metrics.BackgroundFailed("notify", err, "通知チャンネル一覧の取得に失敗しました")',
     'slog.Error("通知チャンネル一覧の取得に失敗しました", "error", err)',
     '送られなかった通知が、また数えられなくなる'),
    ('server/internal/shipper/elasticsearch.go',
     'tick.FailComponent(ctx, "es_shipper", err, "ES bulk 送信失敗", "docs", len(docs))',
     'slog.Error("ES bulk 送信失敗", "error", err, "docs", len(docs))\n\t\t_ = tick.Failing',
     'Elasticsearch に着かなかった文書が、また数えられなくなる'),
    # 同じ呼び出しがこのファイルに2つあり、直すのは前の1つだけです。
    # 1つしか無いファイルを選ぶと metrics の import が落ちて、ビルドエラー
    # になります — 検査が落ちたのではないので、それは kill ではありません。
    ('server/internal/api/handlers/mobile_compliance_scanner.go',
     'metrics.AlertDropped("mdm_compliance", err, f.Title)',
     'slog.Error("アラート作成失敗", "error", err)',
     '消えたコンプライアンス警報が、また数えられなくなる'),
]

RUN = ('TestBackgroundFailed|TestBackgroundFailures|TestADroppedAlert|'
       'TestDroppedAlerts|TestAlertDroppedRecords|'
       'TestFailuresAreNotAnsweredWithAValue|TestTheAnswerRuleFires|'
       'TestNoReturnExceptionHasGoneStale')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/metrics/', './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

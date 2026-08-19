#!/usr/bin/env python3
"""諦めた回が誰かに届くか — の仕組みと、それを見張る判定。

対象:
  server/internal/tick/tick.go  （旧 internal/scheduler/heartbeat.go）
  server/internal/scheduler/fail_reaches_someone_test.go

39本のスケジューラには、失敗を報告する相手がいません。呼び出し側は次の
周回です。なので107箇所が slog に書いて return していました。**ログは、
見に行った人にだけ届きます。** 証明書の更新が3日前から毎回失敗していても、
外から見えるのは「更新された証明書が無い」だけで、更新が要らなかったのと
区別がつきません。

fail がその行き先で、trackRun が edr_scheduler_failures_total と
last_success に落とします。この2つが繋がっていないと、fail は「数を
下げるためだけの呼び出し」になります — 分岐にログ以外の呼び出しがあると
answered_with_a_value_test.go は数えないので、slog.Error を fail に
書き換えるだけで107箇所が静かに数から消えます。それが許されるのは、
本当に別の行き先を持っているあいだだけです。

なのでここでは、仕組みと、それを見張る判定の両方を壊します。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

HB = 'server/internal/tick/tick.go'
FR = 'server/internal/scheduler/fail_reaches_someone_test.go'

CASES = [
    # ── 仕組み ─────────────────────────────────────────────────────────────
    (HB, '\tslog.Error(msg, append(args, "error", err)...)\n'
         '\tif st, ok := ctx.Value(stateKey{}).(*state); ok {\n\t\tst.add()\n\t}',
         '\tslog.Error(msg, append(args, "error", err)...)',
     'fail が、またログ行だけに戻る'),
    (HB, '\tif n := st.count(); n > 0 {\n'
         '\t\tmetrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))\n'
         '\t\treturn\n\t}',
         '',
     '諦めた回が、成功として記録される'),
    (HB, '\t\tmetrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))\n\t\treturn',
         '\t\tmetrics.SchedulerFailures.WithLabelValues(name).Add(float64(n))',
     '失敗した回でも last_success が動く（毎回失敗が健全と同じ形になる）'),
    (HB, '\tmetrics.SchedulerLastSuccessTimestamp.WithLabelValues(name)'
         '.Set(float64(time.Now().Unix()))\n}',
         '}',
     'last_success が一度も押されない'),
    (HB, '\tfn(context.WithValue(ctx, stateKey{}, st))', '\tfn(ctx)',
     'tick が自分の記録先に届かない'),
    (HB, '\ts.n++', '\ts.n = 1',
     '同じ回に何度諦めても1件に潰れる'),

    # ── 見張る側 ───────────────────────────────────────────────────────────
    (FR, '\t"st.add()", // この回が仕事を終えられなかったこと',
         '\t"func", // この回が仕事を終えられなかったこと',
     '検査が、必ず在るものを探すようになる'),
    (FR, '\t"slog.Error",\n', '',
     '理由がログに残ることの確認をやめる'),
    (FR, '\t"metrics.SchedulerLastSuccessTimestamp", // 最後に終えられたのはいつか', '',
     'trackRun が last_success に落としているかを見なくなる'),
    # 逆向きの確認そのものを `if false` にする変異は、ここには置いていません。
    # got が未使用になってビルドが落ちるので、検査が落ちたのか import が
    # 落ちたのかが区別できません。上の2件（一覧から項目を落とす）が、
    # その確認を実際に通っています。


    # ── 変換のときに分けた判断 ─────────────────────────────────────────────
    (
        'server/internal/scheduler/threat_feed_importer.go',
        '\t\tfail(ctx, err, "脅威フィード: threat_feeds テーブルの有無を確認'
        'できませんでした")\n\t\treturn\n\t}\n\tif !exists {',
        '\t\treturn\n\t}\n\tif !exists {',
     '「確認できなかった」が、また「テーブルが無い」と同じ扱いになる'),
    # billing_grace_worker の「ライセンス行がまだ無いだけ」の分岐は、ここには
    # 置いていません。壊すと errors と pgx が未使用になってビルドが落ちるので、
    # 検査が落ちたのか import が落ちたのかが区別できません。そもそも
    # w.check には DB が要り、単体テストは構築だけを見ています。

]

# -run を書くときは、対象を実際に動かす検査を落とさないこと。
# 最初にこの仕様書を走らせたとき、tick_outcome_test.go を入れ忘れたまま
# 「記録先に届かない」変異が生き残り、繋がりを確かめる検査が無いのだと
# 読み違えました。**動いていない検査と、通った検査は、要約行が同じです。**
RUN = ('TestATick|TestEveryPlaceThatGaveUp|TestFailOutside|TestFailingSees|'
       'TestTrackRun|'
       'TestFailWritesSomewhereOtherThanTheLog|'
       'TestFailuresAreNotAnsweredWithAValue|TestTheAnswerRuleFires|'
       'TestNoReturnExceptionHasGoneStale')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN,
         './internal/scheduler/', './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

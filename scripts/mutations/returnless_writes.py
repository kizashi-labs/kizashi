#!/usr/bin/env python3
"""返り値の無い関数が、書けなかったことを呼び出し側に渡すこと。

対象:
  server/internal/store/hunt_store.go
  server/internal/store/saved_hunt_store.go
  server/internal/store/suppressions.go
  server/internal/store/live_response.go
  server/internal/billing/store.go
  server/internal/api/handlers/mdm_integration_handler.go
  server/internal/api/handlers/hunt_handler.go
  server/internal/billing/handler.go
  server/internal/detection/engine.go

捨てている書き込みのうち、**返り値そのものが無かった 7 つの関数**に
`error` を持たせました。**どう答えるかを store が決めていた**のが元の形
です —— 返り値が無ければ、呼び出し側に選択肢がありません。

呼び出し側の答え方は3通りに分かれました:

    要求そのもの      `HuntHandler.RecordRun` は「記録する」ための要求
                      です。書けていないのに "recorded" と答えるのは、
                      何もしていないのに「しました」と言うのと同じ ——
                      `WriteOK` で 500 にします。
    応答には載らない  ライブレスポンスのポーリング、MDM 同期の記録、
                      Stripe の webhook。**応答は別のことを答えて
                      います。** 部品ごとの件数に出します。
    イベントごと      抑制ルールのヒット数（`detection.Engine`）。

**Stripe だけは向きが逆です。** 印を書けなかったときに 500 を返すと、
Stripe が再送し、**印が無いままもう一度処理されます** —— 二重処理は
その印が防いでいるものです。200 のまま、件数に出します。

置いていない変異:

  `IncrementRunCount` の呼び出し側への変異は置いていません。**本番の
  呼び出し側がありません**（検査からしか呼ばれていません）。`error` を
  返す形にしたのは、次に誰かが呼ぶときに選べるようにするためです。

## `err != nil` の反転を殺せるようにしたこと

抑制ルールのヒット数と MDM の記録で `err != nil` を `err == nil` に反転
する変異は、**DB が無いと殺せない**ものとしてここに書き残していました
—— 通る木ではどちらの分岐も通らないので、走査でも件数でも見分けが
つきません。反転した先は「**書けたときに失敗を報告し、書けなかった
ときは黙る**」です。

DB を立てずに殺せるようになりました。要るのは「失敗する書き込み先」
だけで、DB そのものではありません:

    抑制ルールのヒット数  `Engine.noteSuppressionHit` に切り出して、
                          `SuppressionHitCounter` の偽物を渡します
                          （`suppression_hit_report_test.go`）。
    MDM の記録            **届かないプールを渡します**
                          （`mdm_sync_record_test.go`）。
                          `MDMIntegrationHandler` は `*pgxpool.Pool` を
                          直に持つので偽物を挟めませんが、127.0.0.1:1 に
                          向けたプールは即座に接続を拒否され、
                          **本番で最も起きる失敗（DB に届かない）と
                          同じ経路**を通ります。

DB を立てる検査（`restart_shape.py` の群）はまだ要りますが、それは
**Postgres の側の振る舞い**（RLS、権限、並行更新）を確かめるものだけに
なりました。

## 走査を広げて出てきたもの

`_ = h.Store.RecordRun(…)` に戻す変異が生き残りました。`discarded_store_
error_test.go` は左辺が2つ以上の形しか見ておらず、**返り値が `error` 1つ
だけの呼び出しを捨てる形**が素通りしていたためです。広げたら **20 か所**
出ました —— 隔離・プロセス停止・ファイル隔離・スキャン・ログイン・
パスワード変更・webhook。まだ読んでいないので、上限として留めています。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

HS = 'server/internal/store/hunt_store.go'
SU = 'server/internal/store/suppressions.go'
LR = 'server/internal/store/live_response.go'
BS = 'server/internal/billing/store.go'
BH = 'server/internal/billing/handler.go'
HH = 'server/internal/api/handlers/hunt_handler.go'
LH = 'server/internal/api/handlers/live_response_handler.go'
MD = 'server/internal/api/handlers/mdm_integration_handler.go'
EN = 'server/internal/detection/engine.go'
DW = 'server/internal/api/handlers/discarded_write_test.go'

CASES = [
    # ── store 側が返り値を捨てる形に戻る ─────────────────────────────────
    (HS, '\t_, err := s.pool.Exec(ctx, `\n'
         '\t\tUPDATE saved_hunts SET last_run=NOW(), run_count=run_count+1 WHERE id=$1::uuid`, id)\n'
         '\treturn err',
         '\t_, _ = s.pool.Exec(ctx, `\n'
         '\t\tUPDATE saved_hunts SET last_run=NOW(), run_count=run_count+1 WHERE id=$1::uuid`, id)\n'
         '\treturn nil',
     'ハントの実行記録が捨てられる（**「記録しました」と答えながら'
     '1行も書いていません**）'),
    (SU, '\t_, err := s.pool.Exec(ctx,\n'
         '\t\t"UPDATE suppression_rules SET hit_count = hit_count + 1 WHERE id = $1", id,\n'
         '\t)\n\treturn err',
         '\t_, _ = s.pool.Exec(ctx,\n'
         '\t\t"UPDATE suppression_rules SET hit_count = hit_count + 1 WHERE id = $1", id,\n'
         '\t)\n\treturn nil',
     '抑制ルールのヒット数が捨てられる（**効いているルールが0件に'
     '見えます**）'),
    (LR, '\t_, err := s.pool.Exec(ctx, `\n'
         '\t\tUPDATE live_response_sessions SET last_activity = NOW() WHERE token = $1\n'
         '\t`, token)\n\treturn err',
         '\t_, _ = s.pool.Exec(ctx, `\n'
         '\t\tUPDATE live_response_sessions SET last_activity = NOW() WHERE token = $1\n'
         '\t`, token)\n\treturn nil',
     'セッションの延命が捨てられる（**使用中でも30分で期限切れ**）'),
    (LR, '\t_, err := s.pool.Exec(ctx, `\n'
         '\t\tUPDATE live_response_sessions SET last_activity = NOW() WHERE token = $1',
         '\t_, err := s.pool.Exec(context.Background(), `\n'
         '\t\tUPDATE live_response_sessions SET last_activity = NOW() WHERE token = $1',
     '`ctx` を無視して `context.Background()` に戻る（**要求が打ち切られても'
     '走り続け、テナントの設定も乗りません**）'),

    # ── 呼び出し側の答え方 ───────────────────────────────────────────────
    (HH, '\tif err := h.Store.RecordRun(c.Request.Context(), id); !WriteOK(c, err) {\n\t\treturn\n\t}',
         '\t_ = h.Store.RecordRun(c.Request.Context(), id)',
     '「記録する」要求が、書けていなくても "recorded" と答える'),
    (LH, '\tif err := h.Store.TouchSession(c.Request.Context(), token); err != nil {\n'
         '\t\tmetrics.BackgroundFailed("live_response_touch", err,\n'
         '\t\t\t"ライブレスポンスのセッションを延命できませんでした。使用中でも30分で期限切れになります")\n\t}',
         '\t_ = h.Store.TouchSession(c.Request.Context(), token)',
     '延命の失敗が誰にも届かなくなる'),
    (LH, '\tif err := h.Store.TouchSession(c.Request.Context(), token); err != nil {\n'
         '\t\tmetrics.BackgroundFailed("live_response_touch", err,\n'
         '\t\t\t"ライブレスポンスのセッションを延命できませんでした。使用中でも30分で期限切れになります")\n\t}',
         '\tif err := h.Store.TouchSession(c.Request.Context(), token); !WriteOK(c, err) {\n\t\treturn\n\t}',
     '**延命の失敗でポーリングを 500 にする**（端末が指示を受け取れなく'
     'なります —— そちらの方が悪い形です）'),
    (BH, '\tif err := h.store.MarkEventProcessed(ctx, event.ID, processErr); err != nil {\n'
         '\t\tmetrics.BackgroundFailed("stripe_webhook", err,\n'
         '\t\t\t"Stripe イベントを処理済みにできませんでした。同じ webhook が再送されると二重に処理されます",\n'
         '\t\t\t"event_id", event.ID, "type", event.Type)\n\t}',
         '\t_ = h.store.MarkEventProcessed(ctx, event.ID, processErr)',
     'Stripe の印が書けなかったことが誰にも届かなくなる'),

    # ── `err != nil` の反転（偽物・届かないプールで殺す） ────────────────
    (EN, '\tif err := e.suppressionHit.IncrHitCount(ctx, ruleID); err != nil {',
         '\tif err := e.suppressionHit.IncrHitCount(ctx, ruleID); err == nil {',
     '**書けたときに失敗を報告し、書けなかったときは黙る**'
     '（ヒット数は0のまま、棚卸しで消されます）'),
    (EN, '\tif err := e.suppressionHit.IncrHitCount(ctx, ruleID); err != nil {\n'
         '\t\tmetrics.BackgroundFailed("suppression_hit_count", err,\n'
         '\t\t\t"抑制ルールのヒット数を更新できませんでした。効いているルールが0件に見えます",\n'
         '\t\t\t"rule_id", ruleID)\n\t}',
         '\t_ = e.suppressionHit.IncrHitCount(ctx, ruleID)',
     'ヒット数の書き込み失敗が誰にも届かなくなる'),
    (MD, '\tif err := h.recordSyncResult(ctx, integType, success, errMsg); err != nil {',
         '\tif err := h.recordSyncResult(ctx, integType, success, errMsg); err == nil {',
     '**MDM 同期の記録が、書けたときだけ失敗として報告される**'
     '（画面には前回の結果が残ります）'),
    (MD, '\tif err := h.recordSyncResult(ctx, integType, success, errMsg); err != nil {\n'
         '\t\tmetrics.BackgroundFailed("mdm_sync_record", err,\n'
         '\t\t\t"MDM 同期の結果を記録できませんでした。画面には前回の結果が残ります",\n'
         '\t\t\t"integration", integType, "success", success)\n\t}',
         '\t_ = h.recordSyncResult(ctx, integType, success, errMsg)',
     'MDM 同期の記録の失敗が誰にも届かなくなる'),

    # ── 件数 ─────────────────────────────────────────────────────────────
    (DW, 'const discardedWritesTotal = 1', 'const discardedWritesTotal = 16',
     '直した 7 か所を、まだ捨てていることにする'),
]

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestNoDiscardedWriteIsAnsweredWithSuccess|TestEveryDiscardedWriteIsClassified|'
         'TestEveryWriteCategoryIsOneOfTheFour|TestTheDiscardedWriteWalkReachesTheTree|'
         'TestHandlersDoNotDiscardStoreErrors|TestTheStoreErrorRecogniserLooksAtTheShape',
         './internal/api/handlers/'],
    cwd='server',
)

BF_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestEveryBackgroundFailedSiteIsClassified|TestTheSmallCategoriesKeepTheirCount',
         './internal/tick/'],
    cwd='server',
)

ST = 'server/internal/store/tenant_conn_and_backup_code_test.go'

STORE_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', 'TestTouchSessionUsesTheCallersContext',
         './internal/store/'],
    cwd='server',
)

# 反転は件数では見分けがつきません（`BackgroundFailed` の呼び出しは
# 残ったままです）。偽物と届かないプールを渡す検査だけが殺せます。
REPORT_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestAFailedSuppressionHitCountIsReported|TestNoSuppressionCounterIsNotAFailure|'
         'TestAFailedMDMSyncRecordIsReported|TestTheDeadPoolReallyFailsTheWrite',
         './internal/detection/', './internal/api/handlers/'],
    cwd='server',
)

CTX_CASE = CASES[3]  # `context.Background()` に戻す
BF_ONLY = {LH, BH, EN, MD}
INVERSIONS = [c for c in CASES if 'err == nil' in c[2]]
BF_CASES = [c for c in CASES if c[0] in BF_ONLY and c not in INVERSIONS]
MAIN_CASES = [c for c in CASES if c[0] not in BF_ONLY]

if __name__ == '__main__':
    rc = HARNESS.run([c for c in MAIN_CASES if c is not CTX_CASE])
    rc |= BF_HARNESS.run(BF_CASES)
    rc |= STORE_HARNESS.run([CTX_CASE])
    rc |= REPORT_HARNESS.run(INVERSIONS)
    sys.exit(rc)

#!/usr/bin/env python3
"""捨てていた最後の9か所と、それを読んで出てきた欠陥。

対象:
  server/internal/api/handlers/asset_criticality_handler.go
  server/internal/api/handlers/ingest_handler.go
  server/internal/api/handlers/discarded_write_test.go
  server/internal/api/handlers/discarded_write_reasons_test.go
  server/internal/detection/curate_service.go
  server/internal/store/incidents.go
  server/internal/siem/connector.go
  server/internal/ldap/connector.go
  server/internal/tick/background_failed_test.go

残っていた 9 か所を1つずつ読みました。**答え方は形で決まりました:**

    store/incidents.go:Delete          `correlation_groups.incident_id` には
                                       外部キー（CASCADE 無し、migration 036）が
                                       あるので、**書けなければ直後の DELETE が
                                       23503 で落ちます。** 生の制約違反より
                                       先に答えます。
    detection/curate_service.go        **回がありました。** `curate_scheduler` の
                                       `trackRun` から届きます →
                                       `tick.FailComponent`。
    ingest_handler.go:upsertAgent      取り込みは落としません（落とす方が悪い
                                       形です）。件数に出します。
    siem/connector.go:sendOne          goroutine の中 → 件数。
    ldap/connector.go:SyncUsers        同期は成功しているので error は返さず、
                                       件数。**`CREATE TABLE` の方だけ残します**
                                       —— 直後の upsert が全件失敗して報告します。

**分類の誤りが3つ目です。** `RunRound` を `restart` に入れていましたが、
`curate_scheduler` の回の中でした。`internal/tick` の走査も挙げません ——
3段たどりますが**同じ package の中だけ**なので、
`internal/scheduler` → `internal/detection` の1段目で見えなくなります。

## 読んで出てきた欠陥: 手動の重要度は一度も効いていませんでした

`asset_criticality_handler.go` の捨てていた書き込みを追ったら、
**その行を読むものがどこにもありませんでした。**

    PUT  /endpoints/:id/criticality   `agent_criticality_<id>` に書いて 200
    GET  /endpoints/:id/criticality   `computeScoreForAgent` が計算し直して
                                      **同じ行を上書き**
    POST /endpoints/criticality/bulk  全端末について同じことをする

つまり手で決めた重要度は、**一覧の再計算ボタン1回で消えます**（再起動すら
要りません）。画面側は `manual_override` / `manual_score` を読んでいて、
**API が一度も送ったことのない項目**でした。

いま: 手動には印が付き、計算する側はその印を見て**計算も上書きもしません。**
計算値はもう保存しません —— 誰も読まないうえに、上書きしていたのがそれです。
印を持たない古い行（計算値のキャッシュ）は `false` として読まれるので、
migration は要りません。

## 変異に `_ = metrics.BackgroundFailed` が付いているもの

`ingest_handler.go` と `siem/connector.go` では、報告を消すと
**`metrics` の import が余って build が壊れます**（NOT-A-KILL であって
kill ではありません）。関数値を1つ残して、import だけを生かしています ——
確かめたいのは「`_, _ = Exec(…)` を走査が数えるか」で、import の話では
ありません。

## 置いていない変異

検査の assertion を `if false` に潰す変異は置いていません。**assertion
は、自分が消されたことを自分では検知できません。** その assertion が
効いていることは、**本番側の変異**（`storedCriticality` の呼び出しを
消す、段を写す）が殺されることで分かります —— そちらは置いてあります。
走査そのもの（`calls`・`countTierLadders`・`writesSystemMetadata`）は
見本を食わせているので潰せます。

## 床の向きを直しました

`TestTheDiscardedWriteWalkReachesTheTree` は「捨てている書き込みが 5 か所
以上見えること」を床にしていました。**残りを直すほど成り立たなくなる床**
です —— 9 → 1 で割れました。歩いた関数の数に変えました。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

AC = 'server/internal/api/handlers/asset_criticality_handler.go'
IH = 'server/internal/api/handlers/ingest_handler.go'
DW = 'server/internal/api/handlers/discarded_write_test.go'
DR = 'server/internal/api/handlers/discarded_write_reasons_test.go'
CS = 'server/internal/detection/curate_service.go'
IN = 'server/internal/store/incidents.go'
SI = 'server/internal/siem/connector.go'
LD = 'server/internal/ldap/connector.go'
BF = 'server/internal/tick/background_failed_test.go'
CO = 'server/internal/api/handlers/criticality_override_test.go'
CL = 'server/internal/api/handlers/criticality_list_test.go'
RT = 'server/internal/api/router.go'

HANDLER_CASES = [
    # ── 手動の重要度 ─────────────────────────────────────────────────────
    (AC, '\tif !saved.ManualOverride {\n\t\treturn nil, nil\n\t}\n', '',
     '**印を見ずに、保存されている値を全部使う**（古い計算値の'
     'キャッシュが「手動」として返ります）'),
    (AC, '\tif !saved.ManualOverride {', '\tif saved.ManualOverride {',
     '**印の向きを反転する**（手動だけが捨てられます）'),
    (AC, '\t\tManualOverride: true,', '\t\tManualOverride: false,',
     '**書く側が印を付けない**（元の姿。書けても一件も手動として'
     '読まれません）'),
    (AC, '\tif saved, ok := h.storedCriticality(ctx, agentID); ok {\n'
         '\t\tsaved.AgentID = agentID\n'
         '\t\tsaved.Tier = scoreTier(saved.Score)\n'
         '\t\treturn saved, nil\n\t}\n',
         '',
     '**保存されている値を見ずに、毎回計算する**（元の姿）'),
    (AC, '\treturn scoreAgent(in), nil',
         '\tresult := scoreAgent(in)\n'
         '\tscoreJSON, _ := json.Marshal(result)\n'
         '\t_, _ = h.pool.Exec(ctx,\n'
         '\t\t`INSERT INTO system_metadata (key, value) VALUES ($1, $2)\n'
         '\t\t ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,\n'
         '\t\tcriticalityKey(agentID), string(scoreJSON),\n\t)\n'
         '\treturn result, nil',
     '**計算値の保存が戻る**（元の姿。手で決めた重要度を上書きします）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (CO, 'func calls(f *ast.File, fn, want string) bool {\n\tfound := false',
         'func calls(f *ast.File, fn, want string) bool {\n\treturn true\n\tfound := false',
     '**呼び出しの走査が、どの関数も「呼んでいる」と答える**（読むのを'
     'やめても通ります）'),

    # ── 取り込み ─────────────────────────────────────────────────────────
    (IH, '\t\tif _, err := h.Pool.Exec(ctx, `\n'
         '\t\t\tUPDATE agents\n'
         '\t\t\t   SET last_seen  = NOW(),\n'
         '\t\t\t       status     = CASE WHEN status = \'isolated\'\n'
         '\t\t\t                         THEN \'isolated\' ELSE \'online\' END,\n'
         '\t\t\t       os_type    = CASE WHEN os_type = \'unknown\' AND $2 <> \'unknown\'\n'
         '\t\t\t                         THEN $2 ELSE os_type END,\n'
         '\t\t\t       updated_at = NOW()\n'
         '\t\t\t WHERE hostname = $1`, hostname, osType); err != nil {\n'
         '\t\t\tmetrics.BackgroundFailed("wazuh_agent_touch", err,\n'
         '\t\t\t\t"取り込み元の端末の last_seen を更新できませんでした。報告している端末が画面ではオフラインになります",\n'
         '\t\t\t\t"hostname", hostname)\n\t\t}',
         '\t\t_, _ = h.Pool.Exec(ctx, `\n'
         '\t\t\tUPDATE agents SET last_seen = NOW() WHERE hostname = $1`, hostname)\n'
         '\t\t_ = metrics.BackgroundFailed',
     '取り込み元の端末の last_seen の更新が黙って捨てられる（元の姿。'
     '**報告している端末が画面ではオフラインのまま**）'),

    # ── 一覧の経路と、画面が読む項目 ─────────────────────────────────────
    (RT, '\t\t\tep.GET("/criticality", s.handlers.AssetCriticality.List)\n', '',
     '**一覧の経路を消す**（元の姿。gin は 404 を返し、画面は'
     '「資産が1台も無い」として出ます）'),
    (AC, '\tScore        int                 `json:"criticality_score"`',
         '\tScore        int                 `json:"score"`',
     '**画面が読まない名前で点数を送る**（経路はあるのに、全行が0点で'
     '並びます）'),
    (AC, '\tID           string              `json:"id"`',
         '\tID           string              `json:"agent_id"`',
     '**画面が読まない名前で ID を送る**'),
    (AC, '\trow.ManualScore = &score\n', '',
     '手動の行が `manual_score` を持たなくなる（上書きダイアログが'
     '前の値を出せません）'),
    (AC, '\trow.ManualReason = m.result.Reason\n', '',
     '手動の行が理由を持たなくなる'),
    (AC, '\t\tstatus:       a.status,\n', '',
     '**一覧だけオフライン減点が効かなくなる**（同じ端末が、1台ぶんの'
     '画面と一覧で別の点数になります）'),
    (AC, '\t\tactiveAlerts: alerts[a.id],\n\t\thighVulns:    vulns[a.id],',
         '\t\tactiveAlerts: vulns[a.id],\n\t\thighVulns:    alerts[a.id],',
     'アラート数と脆弱性数を取り違える（**15点と10点が入れ替わります**）'),
    (AC, '\tManualScore  *int                `json:"manual_score,omitempty"`',
         '\tManualScore  *int                `json:"manual_score"`',
     '計算した行にも `manual_score` を出す（**全部が手動で決められて'
     'いるように見えます**）'),

    # ── 上書きの保存（画面の綴りと 0 点） ────────────────────────────────
    (AC, '\tv := score\n\tif v == nil {\n\t\tv = manualScore\n\t}\n',
         '\tv := score\n',
     '**`manual_score` を読まなくなる**（元の姿。画面が送る綴りなので、'
     '上書きの保存は必ず 400 で落ちます）'),
    (AC, '\tif v == nil || *v < 0 || *v > 100 {',
         '\tif v == nil || *v <= 0 || *v > 100 {',
     '**0 点を弾く**（`binding:"required"` と同じ。重要度 0 は'
     '正しい値です）'),

    # ── 点数の作り方が1つであること ──────────────────────────────────────
    (CL, 'func countTierLadders(f *ast.File) int {\n\tn := 0',
         'func countTierLadders(f *ast.File) int {\n\treturn 1\n\tn := 0',
     '**段の走査が、いつでも「1つ」と答える**（ladder が何個あっても'
     '通ります）'),

    # ── 件数と分類 ───────────────────────────────────────────────────────
    (DW, 'const discardedWritesTotal = 0', 'const discardedWritesTotal = 100',
     '捨てている書き込みの数を留めなくなる'),
    (DW, '\tconst floor = 2000', '\tconst floor = 0',
     '**走査が届いているかの床を 0 にする**（どんな走査も「届いた」と'
     '言います）'),
    (DR, '\tcatRestart:  0,', '\tcatRestart:  6,',
     '**記憶とDBの食い違いを 6 件まで許す**（0 が規則です）'),
    (DR, 'const discardedWriteFuncs = 0', 'const discardedWriteFuncs = 7',
     '分類の数を留めなくなる'),
]

STORE_CASES = [
    (IN, '\tif _, err := s.pool.Exec(ctx,\n'
         '\t\t"UPDATE correlation_groups SET incident_id = NULL WHERE incident_id = $1", id); err != nil {\n'
         '\t\treturn fmt.Errorf("相関グループの紐付けを外せませんでした: %w", err)\n\t}',
         '\t_, _ = s.pool.Exec(ctx, "UPDATE correlation_groups SET incident_id = NULL WHERE incident_id = $1", id)',
     '相関グループの紐付け外しが黙って捨てられる（元の姿。**利用者には'
     '23503 の生のメッセージが届きます**）'),
]

CURATE_CASES = [
    (CS, '\tif _, err := s.db.Exec(ctx,\n'
         '\t\t`UPDATE rules SET curate_state=$2 WHERE id = ANY($1) AND source=\'sigmahq\' AND enabled=false`,\n'
         '\t\tids, state); err != nil {',
         '\tif _, err := s.db.Exec(ctx,\n'
         '\t\t`UPDATE rules SET curate_state=$2 WHERE id = ANY($1) AND source=\'sigmahq\' AND enabled=false`,\n'
         '\t\tids, state); err == nil {',
     '**書けたときに失敗を報告し、書けなかったときは黙る**'),
    (CS, '\t\ttick.FailComponent(ctx, "curate_stamp", err,',
         '\t\ttick.FailComponent(context.Background(), "curate_stamp", err,',
     '**件数には出すが、その回は成功として刻まれる**（毎回失敗している'
     'スケジューラが健全なものと同じ姿になります）'),
    (CS, '\tif len(ids) == 0 {\n\t\treturn\n\t}\n', '',
     '対象0件でも毎周回 UPDATE を投げる'),
    (CS, '\t\tids, state); err != nil {', '\t\tstate, ids); err != nil {',
     '引数を入れ替える（別の状態を刻みます）'),
]

SIEM_LDAP_CASES = [
    (SI, '\t\t\tif _, err := c.pool.Exec(tctx,\n'
         '\t\t\t\t`UPDATE siem_configs SET sent_count = sent_count + 1, last_sent = NOW() WHERE id = $1`, id); err != nil {\n'
         '\t\t\t\tmetrics.BackgroundFailed("siem_sent_count", err,\n'
         '\t\t\t\t\t"SIEM 転送件数を記録できませんでした。再起動で転送件数が巻き戻ります",\n'
         '\t\t\t\t\t"config_id", id)\n\t\t\t}',
         '\t\t\t_, _ = c.pool.Exec(tctx,\n'
         '\t\t\t\t`UPDATE siem_configs SET sent_count = sent_count + 1, last_sent = NOW() WHERE id = $1`, id)\n'
         '\t\t\t_ = metrics.BackgroundFailed',
     'SIEM 転送件数の記録が黙って捨てられる（元の姿。**再起動で'
     '巻き戻ります**）'),
    (LD, '\tif _, err := c.pool.Exec(ctx, `\n'
         '\t\tUPDATE ldap_configs SET last_sync = NOW(), user_count = $1 WHERE enabled = true`, count); err != nil {\n'
         '\t\tmetrics.BackgroundFailed("ldap_sync", err,\n'
         '\t\t\t"LDAP 同期の記録を更新できませんでした。画面では一度も同期していないように見えます",\n'
         '\t\t\t"users", count)\n\t}',
         '\t_, _ = c.pool.Exec(ctx, `\n'
         '\t\tUPDATE ldap_configs SET last_sync = NOW(), user_count = $1 WHERE enabled = true`, count)',
     'LDAP 同期の記録が黙って捨てられる（元の姿。**一度も同期していない'
     '配置と同じ姿になります**）'),
]

BF_CASES = [
    (BF, '\tbackgroundFailedCount = 68', '\tbackgroundFailedCount = 500',
     '`metrics.BackgroundFailed` の件数を留めなくなる'),
    (BF, '\t"api/handlers/ingest_handler.go:upsertAgent": catPerReq,\n', '',
     '新しい報告先の分類を消す'),
]

# `run_mutations.py --check` が読む一覧です。**走らせる順は下で分けて
# いますが、pattern が当たるかはまとめて確かめます。**
CASES = HANDLER_CASES + STORE_CASES + SIEM_LDAP_CASES + CURATE_CASES + BF_CASES

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def harness(run, pkg):
    return Harness(root=ROOT, cmd=['go', 'test', '-count=1', '-run', run, pkg],
                   cwd='server')


HANDLER_HARNESS = harness(
    'TestTheListRowCarriesWhatTheConsoleReads|TestOnlyAManualRowCarriesTheManualFields|'
    'TestBothSpellingsOfTheManualScoreAreAccepted|'
    'TestEveryCriticalityPathGoesThroughOneScorer|TestTheCriticalityListRouteIsRegistered|'
    'TestTheListCarriesEveryScoringInput|TestTheTierLadderScanRecognisesTheRealThing|'
    'TestAStoredManualScoreIsUsedAndAComputedOneIsNot|'
    'TestWhatSetManualScoreWritesIsReadBackAsManual|'
    'TestOnlyTheManualEndpointWritesTheCriticalityRow|'
    'TestTheSystemMetadataWriteScanRecognisesTheRealThing|'
    'TestNoDiscardedWriteIsAnsweredWithSuccess|TestEveryDiscardedWriteIsClassified|'
    'TestEveryWriteCategoryIsOneOfTheFour|TestTheDiscardedWriteWalkReachesTheTree|'
    'TestTheDiscardedWriteScanRecognisesTheRealThing',
    './internal/api/handlers/')

# store / siem / ldap の書き込みは、handlers の走査（`server/internal` 全体を
# 歩きます）が数えます。
STORE_HARNESS = harness(
    'TestNoDiscardedWriteIsAnsweredWithSuccess|TestEveryDiscardedWriteIsClassified',
    './internal/api/handlers/')

CURATE_HARNESS = harness(
    'TestAFailedCurateStampDoesNotLeaveTheRunLookingSuccessful|'
    'TestNothingToStampIsNotAQuery|TestAStampFailureOutsideARunStillCounts',
    './internal/detection/')

BF_HARNESS = harness('TestEveryBackgroundFailedSiteIsClassified', './internal/tick/')

if __name__ == '__main__':
    rc = HANDLER_HARNESS.run(HANDLER_CASES)
    rc |= STORE_HARNESS.run(STORE_CASES + SIEM_LDAP_CASES)
    rc |= CURATE_HARNESS.run(CURATE_CASES)
    rc |= BF_HARNESS.run(BF_CASES)
    sys.exit(rc)

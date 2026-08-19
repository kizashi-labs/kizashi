#!/usr/bin/env python3
"""ハンドラの1行読みが、数えられなかった 0 を画面に出さないこと。

対象:
  server/internal/api/handlers/discarded_read_test.go
  server/internal/api/handlers/dns_security_handler.go
  server/internal/api/handlers/compliance_handler.go
  server/internal/api/handlers/soc_metrics_handler.go
  server/internal/api/handlers/gdpr_handler.go
  server/internal/api/handlers/pdf_report_handler.go
  server/internal/api/handlers/errs.go

`ReadFailure` の説明にある通りです ——「空の一覧は、読んだ人にとって最も
安心できる形をした嘘です」。あれは**一覧**の読み取りに入れた答えで、
**1行読み**（`_ = pool.QueryRow(…).Scan(&n)`）は手つかずでした。

実測 (2026-08-12): `internal/api/handlers` に 248 か所。

    223  読んだ値が応答に入る（`c.JSON` の引数・composite literal・
         `stats["x"] = n` のような入れ物への代入をたどって判定）
    227  `COUNT`/`SUM`/`MAX`/`COALESCE` の集計 —— **`pgx.ErrNoRows` が
         あり得ないので、そこで起きる error は本当の失敗です**
    208  その両方

**狭く探すと「出ていない」に見えます。** `c.JSON` の引数と composite
literal だけを見ていたときは 156 でした。代入をたどると 223 です。

**「一括では直せない」と前回書きましたが、直せます。** `ReadFailure` は
「本当に無いときに返す形」を引数に取るのでハンドラごとに違いますが、
`readOK` は**既定値のまま続ける**のでその形が要りません —— 42P01／
行なしのときの応答は1バイトも変わらず、それ以外だけ 500 になります。

**248 → 9。応答に入るものは 0 です。**

    dns_security 6・compliance 系 14・vuln_remediation 3
    soc_metrics 12・ops_report 10・patch 6・email_security 6・nta 6
    ztna 8・shift 8・gdpr 7・wireless 6・soar_workflows 5・
    network_anomalies 5・cloud_posture 5・ai_triage 5
    training / threat_fusion / pdf_report / patch_automation / pam /
    multi_tenant / metrics_history / forensics_automation / cloud_asset 各 4
    残り 88（一括）・asset_criticality 2・agents RiskScore 2

残った 9 か所は `readOK` を置けない場所です（`*gin.Context` を持たない、
または値を返す関数）。**1つずつ理由を書いてあり、理由の側も宛先が
実在することを見ています。**

置き換えは使い捨てのスクリプトでやりました。**2回壊しました** ——
1度目は `.Scan(` を探していて、複数行の形（ドットが前の行の末尾）を
丸ごと見落としました。2度目は `.Scan(new(int)) // …` のように**行末に
コメントがある1文**で、文の終わりを見つけられず次の文まで飲み込んで
構文が壊れました。どちらも「狭く探す」です。

置いていない変異:

  まだ直していない 242 か所への変異は置いていません。**直っていない
  ものを「壊す」ことはできません。**
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/api/handlers/discarded_read_test.go'
D = 'server/internal/api/handlers/dns_security_handler.go'
E = 'server/internal/api/handlers/errs.go'
CH = 'server/internal/api/handlers/compliance_handler.go'

SM = 'server/internal/api/handlers/soc_metrics_handler.go'

# MTTR の1文。**まとめて1つの変異にしてあります** —— 開き側だけ戻すと
# `)) {` `return` `}` が残って構文が壊れ、「検査が落ちた」のか
# 「ビルドが落ちた」のかが区別できません。
MTTR_NOW = """\tif !ReadOK(c, h.Pool.QueryRow(ctx, fmt.Sprintf(`
\t\t\tSELECT COALESCE(AVG(
\t\t\t\tEXTRACT(EPOCH FROM (asc2.changed_at - a.created_at)) / 3600
\t\t\t), 0)
\t\t\tFROM alerts a
\t\t\tJOIN (
\t\t\t\tSELECT DISTINCT ON (alert_id) alert_id, changed_at
\t\t\t\tFROM alert_status_changes
\t\t\t\tWHERE to_status = 'resolved'
\t\t\t\tORDER BY alert_id, changed_at ASC
\t\t\t) asc2 ON asc2.alert_id = a.id
\t\t\tWHERE a.created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&mttrHrs)) {
\t\treturn
\t}
"""

MTTR_WAS = """\t_ = h.Pool.QueryRow(ctx, fmt.Sprintf(`
\t\t\tSELECT COALESCE(AVG(
\t\t\t\tEXTRACT(EPOCH FROM (asc2.changed_at - a.created_at)) / 3600
\t\t\t), 0)
\t\t\tFROM alerts a
\t\t\tJOIN (
\t\t\t\tSELECT DISTINCT ON (alert_id) alert_id, changed_at
\t\t\t\tFROM alert_status_changes
\t\t\t\tWHERE to_status = 'resolved'
\t\t\t\tORDER BY alert_id, changed_at ASC
\t\t\t) asc2 ON asc2.alert_id = a.id
\t\t\tWHERE a.created_at >= NOW() - INTERVAL '%d days'`, days)).Scan(&mttrHrs)
"""

# リスクスコアの脆弱性件数。**1文ではなくブロックごと戻します** ——
# `readOK` の行だけ消すと `vulnScanErr` が未使用でビルドが落ち、
# 「検査が落ちた」のか「ビルドが落ちた」のかが区別できません。
RISK_NOW = """\tvar vulnScanErr error
\tif err == nil {
\t\tif rows2.Next() {
\t\t\tvulnScanErr = rows2.Scan(&rd.VulnCritical, &rd.VulnHigh)
\t\t}
\t\trows2.Close()
\t}
\tif !ReadOK(c, vulnScanErr) {
\t\treturn
\t}
"""

RISK_WAS = """\tif err == nil {
\t\tif rows2.Next() {
\t\t\t_ = rows2.Scan(&rd.VulnCritical, &rd.VulnHigh)
\t\t}
\t\trows2.Close()
\t}
"""

CASES = [
    (D, '\t\tif err := h.pool.QueryRow(ctx, q.sql).Scan(&n); err != nil {\n'
        '\t\t\tReadFailure(c, err, stats)\n\t\t\treturn\n\t\t}\n',
        '\t\t_ = h.pool.QueryRow(ctx, q.sql).Scan(&n)\n',
     'DNS のカードが、**数えられなかった 0 を「ブロック 0件」として'
     '画面に出す**（元の実装）'),

    (E, '\tif err == nil || absent(err) {\n\t\treturn true\n\t}\n',
        '\treturn true\n\tif err == nil {\n\t\treturn true\n\t}\n',
     '`ReadOK` が、読めなくても「読めた」と答える（**直した 20 か所が'
     '全部そのまま元に戻ります**）'),
    (E, '\tif err == nil || absent(err) {', '\tif err == nil {',
     '「本当に無い」（テーブル未作成・行なし）まで 500 にする'
     '（**まだマイグレーションが当たっていない画面が 500 になります**）'),
    (CH, '\t\tif !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries WHERE is_active`).Scan(&totalIOC)) {\n\t\t\treturn\n\t\t}\n',
         '\t\t_ = h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries WHERE is_active`).Scan(&totalIOC)\n',
     'コンプライアンス集計の IOC 件数が、また 0 のまま画面に出る'
     '（元の実装）'),

    (SM, MTTR_NOW, MTTR_WAS,
     'MTTR が、読めなかった 0 時間として画面に出る（**「平均対応時間 0 時間」は'
     '最高の数字に見えます**）'),

    ('server/internal/api/handlers/gdpr_handler.go',
     '\tif !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM privacy_incidents`+where, countArgs...).Scan(&total)) {\n\t\treturn\n\t}\n',
     '\t_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM privacy_incidents`+where, countArgs...).Scan(&total)\n',
     'プライバシー侵害の総件数が、読めなかった 0 として画面に出る'
     '（**GDPR の報告義務がかかる画面で「0件」です**）'),

    ('server/internal/api/handlers/pdf_report_handler.go',
     '\tif !ReadOK(c, h.pool.QueryRow(c.Request.Context(),\n'
     "\t\t`SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at >= NOW() - ($1 || ' ')::INTERVAL`, interval,\n"
     '\t).Scan(&data.CriticalAlerts)) {\n\t\treturn\n\t}\n',
     '\t_ = h.pool.QueryRow(c.Request.Context(),\n'
     "\t\t`SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at >= NOW() - ($1 || ' ')::INTERVAL`, interval,\n"
     '\t).Scan(&data.CriticalAlerts)\n',
     'PDF レポートの「重大アラート」が、読めなかった 0 として綴じられる'
     '（**紙になった 0 は、あとから「その期間は 0 件だった」として'
     '読まれます**）'),

    (T, '\t\t\t\twhere = append(where, base+":"+fn.Name.Name)\n', '',
     '理由の要る宛先を1つも挙げなくなる（**8つの理由が、一度も'
     '参照されなくなります**）'),
    (T, '\t\tif !seen[key] {\n\t\t\tstale = append(stale, key)\n\t\t}\n', '\t\t_ = key\n',
     '宛先の消えた理由が残っても気づかなくなる'),
    (T, '\tfor key := range reasons {\n', '\tfor key := range map[string]string{} {\n\t\t_ = reasons\n',
     '理由を1つも読まなくなる（**古い理由が全部見えなくなります**）'),
    ('server/internal/api/handlers/agents_handler.go', RISK_NOW, RISK_WAS,
     '端末のリスクスコアが、読めなかった脆弱性 0 件で計算される'
     '（**危険な端末が安全に見えます**）'),

    (T, 'const discardedHandlerReads = 9', 'const discardedHandlerReads = 400',
     '留めている数を実測から引き離す（増えても気づかなくなる）'),
    (T, 'const discardedHandlerReadsShown = 0', 'const discardedHandlerReadsShown = 400',
     '応答に入る数を留めなくなる'),
    (T, 'const discardedHandlerReadsAggregate = 6', 'const discardedHandlerReadsAggregate = 400',
     '集計の数を留めなくなる'),
    (T, '\tcase got < want:\n\t\treturn pinShrank\n', '',
     '減っても留めている数を下げさせなくなる（**次に増えても'
     '気づけません**）'),
    (T, '\tcase got > want:\n\t\treturn pinGrew\n', '',
     '増えても言わなくなる'),
    (T, '\t// 代入をたどります: `stats["x"] = n` の n も応答に入ります。\n'
        '\tfor i := 0; i < 5; i++ {\n', '\tfor i := 0; i < 0; i++ {\n',
     '入れ物への代入をたどらなくなる（**156 と 223 の差。「出ていない」に'
     '見えます**）'),
    (T, 'sel.Sel.Name != "JSON" && sel.Sel.Name != "IndentedJSON"',
        'sel.Sel.Name != "JSONXXX" && sel.Sel.Name != "IndentedJSONXXX"',
     '`c.JSON` を応答と見なくなる'),
    (T, '\tfor _, f := range []string{"count(", "sum(", "avg(", "max(", "min(", "coalesce("} {',
        '\tfor _, f := range []string{"select"} {',
     '1行の取り出しまで「集計」に数える（**あちらは `pgx.ErrNoRows` が'
     '「まだ無い」を意味します**）'),
    (T, '\tid, ok := as.Lhs[0].(*ast.Ident)\n\tif !ok || id.Name != "_" {\n\t\treturn false\n\t}\n',
        '\tif _, ok := as.Lhs[0].(*ast.Ident); !ok {\n\t\treturn false\n\t}\n',
     '`_ =` 以外の受け方まで数える'),
]

RUN = ('TestDiscardedRowReadsInHandlersAreNotGrowing|'
       'TestTheHandlerReadScanRecognisesTheRealThing|'
       'TestThePinVerdictRecognisesTheRealThing|'
       'TestReadOKAnswersOnlyWhatItCanAnswer|'
       'TestTheStaleHandlerReasonScanRecognisesTheRealThing')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

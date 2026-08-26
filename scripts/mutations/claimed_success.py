#!/usr/bin/env python3
"""やっていない作業を「やった」と答えないこと。

対象:
  server/internal/api/handlers/errs.go
  server/internal/api/handlers/claimed_success_test.go
  server/internal/api/handlers/table_probe_test.go
  server/internal/api/handlers/campaigns_handler.go
  server/internal/api/handlers/rbac_handler.go
  server/internal/api/handlers/fim_page_handler.go

変更系のハンドラに、テーブルが無いときそのまま成功を返すものが 8 つ
ありました。実測 (2026-08-12)、移行を当てていない DB に向けて:

    POST /api/v1/campaigns        200 {"id":"20260812060751","message":"created"}
    PUT  /admin/rbac/permissions  200 {"message":"Permissions saved"}
    DELETE /admin/edr-policies/:id 200 {"message":"削除しました"}

**どれも1行も書いていません。** `campaigns` が返した id は、存在しない
キャンペーンのものです。`rbac` のコメントには「Accept but silently
discard」と書いてありました —— 権限表を保存したつもりの管理者に、保存して
いないことは伝わりません。`fim` は、除外したつもりのファイルからアラートが
出続けます。

いまは 503 です:

    POST /api/v1/campaigns  503 {"error":"キャンペーンの作成はこの配備では
                                 利用できません…。保存していません。"}

一覧が空で返るのは「まだ何も無い」と読めます。**変更系は違います** ——
利用者は「やった」と言われたことを前提に次へ進み、取り消しも再実行も
確認もしません。

── もう1つ、前回の直しが半分だった件 ──────────────────────────────

前回「テーブル存在確認 49 個をすべて片付けた」と書きましたが、見ていたのは
`information_schema.tables` だけでした。**`pg_tables` を引く確認が 30 個
残っていました。** 同じ欠陥が、別の表の名前で隠れていました。

さらに、見張りの側にも同じ形がありました —— 早い脱出
（`if !strings.Contains(src, "information_schema") { continue }`）だけが
古い一覧のままで、**`pg_tables` しか出てこないファイルは丸ごと走査から
外れ、検査は緑を返していました。** 探し方を2か所に分けて持つと、片方だけが
古くなります。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

E = 'server/internal/api/handlers/errs.go'
C = 'server/internal/api/handlers/claimed_success_test.go'
P = 'server/internal/api/handlers/table_probe_test.go'
CH = 'server/internal/api/handlers/campaigns_handler.go'
RH = 'server/internal/api/handlers/rbac_handler.go'
FH = 'server/internal/api/handlers/fim_page_handler.go'

CASES = [
    # ── 成功を騙る形に戻す ───────────────────────────────────────────────
    (CH, '\t\tFeatureNotInstalled(c, "キャンペーンの作成")\n',
         '\t\tc.JSON(http.StatusOK, gin.H{"id": generateShortID(), "message": "created"})\n',
     'キャンペーンの作成が、でっち上げた id で「作成しました」と答える'
     '（**元の実装**）'),
    (RH, '\t\tFeatureNotInstalled(c, "権限設定の保存")\n',
         '\t\tc.JSON(http.StatusOK, gin.H{"message": "Permissions saved"})\n',
     '権限表が、保存せずに「保存しました」と答える（**元の実装。'
     'コメントに「silently discard」と書いてありました**）'),
    (FH, '\t\tFeatureNotInstalled(c, "FIM 除外ルールの追加")\n',
         '\t\tc.JSON(http.StatusOK, gin.H{"message": "ignore rule added"})\n',
     'FIM の除外ルールが、追加せずに「追加しました」と答える（**元の実装**）'),
    (E, '\tc.JSON(http.StatusServiceUnavailable, gin.H{',
        '\tc.JSON(http.StatusOK, gin.H{',
     '「利用できません」を 200 で返す（画面は成功として扱います）'),

    # ── 走査そのもの ─────────────────────────────────────────────────────
    (C, "\t\t\"tableIsThere\", \"tableExists\", \"TableExists\", \"Exists\", \"exists\",\n"
        "\t\t\"Table(\", \"Table)\",\n",
        "\t\t\"tableIsThere\",\n",
     '「テーブルが無いとき」の探し方を狭める（その形の分岐が走査から'
     '外れます）'),
    (C, '\tif !strings.HasPrefix(cond, "!") {\n\t\treturn false\n\t}',
        '\tif strings.HasPrefix(cond, "!") {\n\t\treturn false\n\t}',
     '否定の向きを逆にする'),
    (C, '\t\tcase "StatusOK", "StatusCreated", "StatusAccepted", "StatusNoContent":\n\t\t\tfound = true',
        '\t\tcase "StatusTeapot":\n\t\t\tfound = true',
     '2xx を1つも成功と見なくなる（**0件を検査して緑**）'),
    (C, 'const minAbsenceGuards = 50', 'const minAbsenceGuards = 0',
     '不在分岐の床を 0 に落とす'),
    (C, 'const minClaimedSuccessFiles = 200', 'const minClaimedSuccessFiles = 0',
     'ファイルの床を 0 に落とす'),
    (C, '`^(Create|Update|Delete|Add|Remove|Set|Assign|Approve|Reject|Start|Stop|Run|` +',
        '`^(Create)` + `(` +',
     '変更系の名前の一覧を狭める'),
    (C, '\treturn reasons[file+":"+fn] == ""', '\treturn false',
     '違反を1件も挙げなくなる'),
    (P, '\t\t\tif uses {\n\t\t\t\tseen[name+":"+fn.Name.Name] = true\n\t\t\t}\n', '',
     '理由の宛先に走査が届いているかを見なくなる'),
    (C, '\tif !answersSuccess(body) {\n\t\treturn false\n\t}', '\tif answersSuccess(body) {\n\t\treturn false\n\t}',
     '成功を返していない分岐の方を違反にする'),

    # ── 目録の一覧（前回の直しが半分だった分） ───────────────────────────
    (P, '\t"information_schema.tables",\n\t"information_schema.columns",\n\t"pg_tables",\n\t"pg_class",\n\t"to_regclass",\n',
        '\t"information_schema.tables",\n',
     '目録の一覧を `information_schema` だけに戻す（**30 個が数から'
     '消えます**）'),
    (P, '\t\tscanned++\n', '\t\tscanned++\n\t\tif !strings.Contains(string(src), "information_schema") {\n\t\t\treturn nil\n\t\t}\n',
     '早い脱出を古い一覧で戻す（**`pg_tables` しか出てこないファイルが'
     '丸ごと外れます**）'),
]

RUN = ('TestNoWriteEndpointClaimsSuccessWithoutWriting|TestTheMutatingNameListIsNotNarrowed|'
       'TestTheAbsenceGuardDetectorRecognisesTheRealThing|TestAnswersSuccessTellsSuccessFromFailure|'
       'TestTheAbsenceGuardFloorNoticesAnEmptyWalk|TestNoHandlerAsksInformationSchemaOnItsOwn|'
       'TestTheTableProbeDetectorRecognisesTheRealThing|TestNoInformationSchemaReasonHasGoneStale|'
       'TestTheHandlerScanFloorNoticesAnEmptyWalk|TestClaimedSuccessJudgementRecognisesTheRealThing|'
       'TestTheClaimedSuccessFileFloorNoticesAnEmptyWalk|TestFeatureNotInstalledDoesNotLookLikeSuccess')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

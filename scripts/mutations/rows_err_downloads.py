#!/usr/bin/env python3
"""書き出したファイルが、途中までであることを言わないまま手元に残ること。

対象:
  server/internal/api/handlers/audit_export_handler.go
  server/internal/api/handlers/audit_sign_handler.go
  server/internal/api/handlers/compliance_export_handler.go
  server/internal/api/handlers/export_handler.go
  server/internal/api/handlers/report_export_handler.go
  server/internal/api/handlers/rows_err_reported_test.go
  server/internal/api/handlers/answered_with_a_value_test.go

`rows.Next()` のループを抜けたあと、`rows.Err()` には「全部読み切ったのか、
途中で切れたのか」が入っています。**そこを警告ログに落として 200 を返すと、
途中までの中身が全件として返ります。**

直す前に測りました (2026-08-12)。監査ログの書き出しで、行の読み出しを
サーバ側から中断させました:

    format=json  200 / Content-Disposition: attachment / **途中までのファイル**
    format=cef   200 / Content-Disposition: attachment / **途中までのファイル**

受け取った側に、途中で切れたことを知る手掛かりがありません。**監査ログは
「その期間に何も無かった」ことの証拠に使われます。** 署名付きの書き出しは
さらに悪く、欠けた記録に HMAC を付けて「本物である」と証明していました。

一覧が途中までなら、画面を作り直せばもう一度取り直せます。**ファイルは
手元に残り、そのあと誰も取り直しません。** だからここは上限ではなく 0 です。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  「捨てている箇所の総数」に上限を置く案は取りませんでした。
  `rows_err_policy_test.go` が既に、**そのハンドラ自身がクエリ失敗に
  どう答えるかに合わせる**という規則を持っていて、応答せず先へ進む
  ハンドラでは捨てるのが正解だからです。総数の上限はその規則と喧嘩します。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

AE = 'server/internal/api/handlers/audit_export_handler.go'
AS = 'server/internal/api/handlers/audit_sign_handler.go'
CE = 'server/internal/api/handlers/compliance_export_handler.go'
EX = 'server/internal/api/handlers/export_handler.go'
RE = 'server/internal/api/handlers/report_export_handler.go'
T = 'server/internal/api/handlers/rows_err_reported_test.go'
A = 'server/internal/api/handlers/answered_with_a_value_test.go'

WARN = '\t\tslog.Warn("row iteration error", "error", err)'

CASES = [
    # ── 書き出しが黙って途中で終わること ─────────────────────────────────
    (AE, '\t\tslog.Error("audit export: rows.Err", "error", err)\n'
         '\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": "監査ログの読み出しが途中で失敗しました。書き出しは中止します"})\n'
         '\t\treturn\n',
         WARN + '\n',
     '監査ログの書き出しが、途中までのファイルを 200 で渡す（**元の実装**）'),
    (AS, '\t\tslog.Error("signed audit export: rows.Err", "error", err)\n'
         '\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": "監査ログの読み出しが途中で失敗しました。署名付き書き出しは中止します"})\n'
         '\t\treturn\n',
         WARN + '\n',
     '欠けた監査記録に HMAC を付けて「本物である」と証明する（**元の実装**）'),
    (CE, '\t\tslog.Error("compliance export: rows.Err", "error", err)\n'
         '\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": "コンプライアンス結果の読み出しが途中で失敗しました。書き出しは中止します"})\n'
         '\t\treturn\n',
         WARN + '\n',
     'コンプライアンス結果の書き出しが途中で終わる'),
    (EX, '\t\tslog.Error("export: rows.Err", "error", err)\n'
         '\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": "読み出しが途中で失敗しました。書き出しは中止します"})\n'
         '\t\treturn\n',
         WARN + '\n',
     '汎用の書き出しが途中で終わる'),
    (RE, '\t\tmarkCSVIncomplete(w, err)\n', '',
     '流している CSV に、途中で切れた印を書かなくなる'),

    # ── 判定そのもの ─────────────────────────────────────────────────────
    (T, '\t\tcase *ast.ReturnStmt:\n\t\t\treported = true',
        '\t\tcase *ast.ExprStmt:\n\t\t\treported = true',
     'ログを書くだけを「報告した」に数える（**捨てている箇所が全部消えます**）'),
    (T, '\t\tcase *ast.FuncLit:\n\t\t\t// 中の関数の return は、この関数から戻ることではありません。\n\t\t\treturn false',
        '\t\tcase *ast.FuncLit:\n\t\t\treturn true',
     '中の関数の return を、この関数から戻ることと取り違える'),
    (T, '\tif block == nil {\n\t\treturn false\n\t}', '\tif block == nil {\n\t\treturn true\n\t}',
     '中身が無いものを「報告した」に数える'),
    (T, '\t\tif isSilentDownloadTruncation(s, reasons) {',
        '\t\tif false {',
     '書き出しの違反を1件も挙げなくなる'),
    (T, '\t\tif !s.download {\n\t\t\tcontinue\n\t\t}\n\t\tdownloads = append(downloads, s)',
        '\t\tif !s.download {\n\t\t\tcontinue\n\t\t}',
     '書き出しの箇所を数えなくなる（床の判定が一緒に緩みます）'),
    (T, '\treturn reasons[s.file+":"+s.fn] == ""', '\treturn false',
     '違反の判定が、常に「違反でない」を返す'),
    (T, '\tif !s.download || !s.discarded {', '\tif !s.download {',
     '報告している書き出しまで違反にする'),
    (T, '\t\t\t\t\tif strings.Contains(lit.Value, "Content-Disposition") {',
        '\t\t\t\t\tif strings.Contains(lit.Value, "Content-Disposition-XXX") {',
     '書き出しの見分け方が何にも当たらなくなる（**0件を検査して緑**）'),
    (T, 'const minDownloadRowsErrSites = 6', 'const minDownloadRowsErrSites = 0',
     '書き出しの床を 0 に落とす'),
    (T, 'const minRowsErrSites = 580', 'const minRowsErrSites = 0',
     '走査の床を 0 に落とす'),
    (T, '\treturn scanned >= floor', '\treturn true',
     '走査が届いているかを見なくなる'),
    (T, '\tsel, ok := call.Fun.(*ast.SelectorExpr)\n\tif !ok || sel.Sel.Name != "Err" {',
        '\tsel, ok := call.Fun.(*ast.SelectorExpr)\n\tif !ok || sel.Sel.Name != "ErrX" {',
     '`rows.Err()` を1つも見つけなくなる'),

    # ── 外す条件（誰もしない報告を根拠にしないこと） ─────────────────────
    (A, '\t\tif !reportsRowsErr[sk.file+":"+sk.fn] {',
        '\t\tif false && !reportsRowsErr[sk.file+":"+sk.fn] {',
     '報告しているかを見ずに continue を外す（**元の状態。174 箇所が数から消えます**）'),
    (A, '\t\tif s.discarded {\n\t\t\tdiscards[key] = true\n\t\t}', '\t\tif false {\n\t\t\tdiscards[key] = true\n\t\t}',
     '捨てている関数も「報告している」に数える'),
    (A, '\tanswerContinueCeiling = 75', '\tanswerContinueCeiling = 1000',
     'continue の上限を実測から引き離す'),
    (A, '\tconst continueOutsideRowsErr = 88', '\tconst continueOutsideRowsErr = 1000',
     '外に出た continue の数を実測から引き離す'),
]

# ── 146 箇所を「そのハンドラ自身の答え方」に揃えた分 ─────────────────
#
# 実測 (2026-08-12)。`bas_scenarios` に 120,400 行を入れ、
# `statement_timeout` を 25ms にして `/api/v1/admin/bas/scenarios` を叩く:
#
#     揃える前  200 / {"scenarios":[],"total":0}   ← 「1件も無い」と同じ姿
#     揃えた後  500 / {"error":"データベース操作に失敗しました"}
#
# 揃えたのは、そのハンドラ自身がクエリ失敗で **戻る** ものだけです。
BASH = 'server/internal/api/handlers/bas_handler.go'
AGH = 'server/internal/api/handlers/agents_handler.go'

CASES += [
    (BASH, '\t\tslog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)\n'
           '\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})\n'
           '\t\treturn\n',
           '\t\tslog.Warn("row iteration error", "error", err)\n',
     'BAS の一覧が、途中で切れた結果を 200 で返す（**元の実装。'
     '「1件も無い」と同じ姿です**）'),
    (AGH, '\t\tslog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)\n'
          '\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": "プロセス情報の取得に失敗しました"})\n'
          '\t\treturn\n',
          '\t\tslog.Warn("row iteration error", "error", err)\n',
     'プロセス一覧が、途中で切れた結果を 200 で返す（**元の実装**）'),
]

RUN = ('TestDownloadsDoNotTruncateSilently|TestRowsErrIsReportedTellsLoggingFromReturning|'
       'TestTheRowsErrScanFloorNoticesAnEmptyWalk|TestFailuresAreNotAnsweredWithAValue|'
       'TestNoRowsErrCheckBlamesTheCaller|TestSilentDownloadTruncationIsRecognised|'
       'TestTheDownloadScanFloorNoticesAnEmptyWalk|TestMarkCSVIncompleteWritesSomethingUnmistakable|'
       'TestStreamingCSVExportsCallTheIncompleteMarker|TestSplitDownloadSitesSeparatesTheViolations')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

#!/usr/bin/env python3
"""失敗に値で答えていないか — の判定が、骨抜きにされたら気づけること。

対象:
  server/internal/api/handlers/answered_with_a_value_test.go
  server/internal/api/handlers/skipped_row_test.go

この2本は internal/ 全体を走査して、失敗した分岐が「値を返して終わる」
箇所を数えます。4系統（nil を error の位置に / assign / return / continue）
がすべて上限0で、残っている箇所は理由が書いてあります。

数字を守るものが無いと、上限を1つ上げるだけで違反が通ります。理由リストも
同じで、鍵を1文字変えれば例外が効かなくなり、逆に対象が消えても理由だけが
残ります。走査の側も同様に、範囲を狭めれば件数は下がります — 直したのと
同じ形で。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

GATE = 'server/internal/api/handlers/answered_with_a_value_test.go'
SKIP = 'server/internal/api/handlers/skipped_row_test.go'

CASES = [
    # ── 上限そのもの ───────────────────────────────────────────────────────
    (GATE, '\tanswerAssignCeiling = 4', '\tanswerAssignCeiling = 10',
     'assign の上限を 0 から上げる'),
    (GATE, '\tanswerReturnCeiling = 13', '\tanswerReturnCeiling = 20',
     'return の上限を 0 から上げる'),
    (GATE, '\tanswerContinueCeiling = 75', '\tanswerContinueCeiling = 400',
     'continue の上限を実測から上げる'),
    (GATE, '\tanswerNilErrCeiling = 0', '\tanswerNilErrCeiling = 5',
     'nil を error の位置に置く箇所の上限を上げる'),
    (SKIP, 'const silentSkipCeiling = 0', 'const silentSkipCeiling = 30',
     '黙って飛ばす行の上限を上げる'),

    # ── ラチェット（下回っても落ちること）─────────────────────────────
    (GATE, '\tif actual < ceiling {', '\tif false {',
     '実測が上限を下回っても言わなくなる'),

    # ── 理由リスト ─────────────────────────────────────────────────────────
    (GATE, '\t\tif s.kind == "return" {\n\t\t\tif _, ok := returnExceptions[s.file+":"+s.fn]; ok {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t}',
           '',
     'return の理由リストが何も外さなくなる'),
    (GATE, '\t\tif s.kind == "assign" {\n\t\t\tif _, ok := assignExceptions[s.file+":"+s.fn]; ok {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t}',
           '',
     'assign の理由リストが何も外さなくなる'),
    (GATE, '\t"yara/engine.go:matchString": "(c) 読めない16進文字列・壊れた正規表現は" +',
           '\t"yara/engine.go:matchStringx": "(c) 読めない16進文字列・壊れた正規表現は" +',
     'return の理由が、実在しない関数を指している'),
    (SKIP, '\t\tif _, ok := skipExceptions[s.file+":"+s.fn]; ok {\n\t\t\tcontinue\n\t\t}',
           '',
     '行スキャンの理由リストが何も外さなくなる'),
    (SKIP, '\t"api/handlers/geolocation_handler.go:isPrivateIP": "定数として書いた" +',
           '\t"api/handlers/geolocation_handler.go:isPrivateIPx": "定数として書いた" +',
     '行スキャンの理由が、実在しない関数を指している'),

    # ── 走査の範囲 ─────────────────────────────────────────────────────────
    (GATE, 'var answerRoots = []string{"../.."}', 'var answerRoots = []string{"."}',
     '走査を handlers ディレクトリだけに狭める'),
    (GATE, '\t\t\tif !isLoggingCall(s.X) {\n\t\t\t\treturn "", false\n\t\t\t}',
           '\t\t\treturn "", false',
     '記録してから値を返す分岐が、また見えなくなる'),
    (SKIP, '\t\tcase *ast.ExprStmt:\n\t\t\tif !isLoggingCall(v.X) {\n\t\t\t\treturn false // 後始末や再試行をしているものは対象外\n\t\t\t}',
           '\t\tcase *ast.ExprStmt:\n\t\t\treturn false',
     '記録してから飛ばす分岐が、また見えなくなる'),
    (SKIP, '\tcase *ast.CaseClause:\n\t\tout = append(out, v.Body)', '',
     'switch の case 節の中身を歩かなくなる'),
    (SKIP, '\t} else if list != nil {\n\t\trhs = errAssignedJustBefore(list, idx, is)\n\t}',
           '\t}',
     '代入を1行前に出した書き方が、また見えなくなる'),

    # ── 二重計上を避ける側（ここが緩むと continue が丸ごと数から消えます）─
    (GATE, '\t\tif !sk.viaRows {\n\t\t\tcontinue\n\t\t}', '',
     'rows.Err() が拾わない continue まで、行スキャン扱いで外す'),
    (GATE, '\tconst continueOutsideRowsErr = 88',
           '\tconst continueOutsideRowsErr = 380',
     'rows.Err() の外にある continue の総数を、実測から引き上げる'),
    (GATE, '\t\tif _, ok := skipExceptions[s.file+":"+s.fn]; ok {\n\t\t\t\tcontinue\n\t\t\t}',
           '',
     'continue の理由リストが何も外さなくなる'),
    (SKIP, '\tviaRows = (name == "Scan" && recv == rowsVar && rowsVar != "") '
           '|| handedTheRows(rhs, rowsVar)',
           '\tviaRows = true',
     '何でも「rows.Err() が拾う」に分類する'),

    # ── 判定そのもの ───────────────────────────────────────────────────────
    (GATE, '\t\tcase *ast.ReturnStmt:\n\t\t\tif touches(s, errs) {\n\t\t\t\treturn "", false\n\t\t\t}',
           '\t\tcase *ast.ReturnStmt:\n\t\t\tif false {\n\t\t\t\treturn "", false\n\t\t\t}',
     'err を返す分岐まで「値で答えている」に数える'),
]

RUN = ('TestFailuresAreNotAnsweredWithAValue|TestTheAnswerRuleFires|'
       'TestTheCeilingComplaint|TestNoReturnExceptionHasGoneStale|'
       'TestNoAssignExceptionHasGoneStale|TestSkippedRowsAreNotSilent|'
       'TestTheSkipRuleFires|TestTheSilentSkipCount|TestNoSkipExceptionHasGoneStale|'
       'TestScanFailureClosesTheResultSetInPgx')

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

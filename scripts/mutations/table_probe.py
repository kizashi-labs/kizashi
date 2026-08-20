#!/usr/bin/env python3
"""テーブルの存在確認が、「読めなかった」を「無い」に倒さないこと。

対象:
  server/internal/api/handlers/errs.go
  server/internal/api/handlers/table_probe_test.go
  server/internal/api/handlers/bas_handler.go
  server/internal/api/handlers/answered_with_a_value_test.go

この確認は、まだマイグレーションが当たっていない機能の画面を 500 に
しないために置かれています。ところが 49 個すべてが、**確認そのものの
失敗を「無い」と同じに扱っていました**:

    return err == nil && exists   # 24 個
    return exists                 # 18 個（err はログだけ、あるいは捨てる）
    return ok                     # 7 個（`_ =` で捨てる）

呼び出し側 193 箇所は、それを受けて 200 の空（76）・404（62）・503（54）を
返します。**DB に届かないだけで「その機能は使われていません」と同じ姿に
なります。**

直す前に測りました (2026-08-12)。`bas_scenarios` に 120,400 行、
`statement_timeout` 1ms で `/api/v1/admin/bas/scenarios`:

    直す前   200  {"scenarios":[],"total":0}   ← 「1件も無い」と同じ姿
    直した後 500  {"error":"データベース操作に失敗しました"}

テーブルが**本当に**無いときは、直す前後どちらも 200 の空です
（移行していない別DBで確認しました）。**変わるのは失敗したときだけです。**

`true` を返すのは、本物のクエリに答えさせるためです ——
DB 障害ならそのハンドラ自身の失敗時の答え方が、テーブルが本当に無いなら
42P01 を `absent()` が見分けて空を返します。

置いていない変異:

  検査の assert 行を潰す変異は置いていません。**どのテストも殺せない
  からです** —— それは「そのテストを消す」のと同じです。

  `slog.Warn` の行を消す変異も置いていません。**それだけで `slog` が
  未使用になり、コンパイルが通りません** —— 変異ではなく構文誤りです。

  `information_schema.tables` を `information_schema.views` に変える変異も
  置いていません。**DB のある環境でしか殺せず**、この一式は DB 無しで
  走るからです（`TestNoHandlerAsksInformationSchemaOnItsOwn` は文字として
  読むだけです）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

E = 'server/internal/store/table_probe.go'
T = 'server/internal/api/handlers/table_probe_test.go'
B = 'server/internal/api/handlers/bas_handler.go'
A = 'server/internal/api/handlers/answered_with_a_value_test.go'

CASES = [
    # ── 判定そのもの ─────────────────────────────────────────────────────
    (E, '\tif err != nil {\n\t\t// **見に行けなかっただけです。「無い」とは答えません。**\n\t\treturn true\n\t}',
        '\tif err != nil {\n\t\treturn false\n\t}',
     '確認の失敗を「無い」に倒す（**元の実装。120,400 行あるテーブルが'
     '「1件も無い」と同じ姿で返ります**）'),
    (E, '\tif err != nil {\n\t\t// **見に行けなかっただけです。「無い」とは答えません。**\n\t\treturn true\n\t}',
        '\tif err != nil {\n\t\treturn exists\n\t}',
     '確認の失敗を、走査できなかった変数の値（false）で答える'),
    (E, '\t\t// **見に行けなかっただけです。「無い」とは答えません。**\n\t\treturn true\n\t}\n\treturn exists',
        '\t\treturn true\n\t}\n\treturn true',
     'テーブルが本当に無くても「在る」と答える（**移行前の画面が 500 に'
     'なります**）'),
    (E, '\tif err != nil {\n\t\t// **見に行けなかっただけです。「無い」とは答えません。**\n\t\treturn true\n\t}\n',
        '',
     '判断から、失敗の分岐が消える'),

    # ── 確認が1か所に集まっていること ────────────────────────────────────
    (B, '\treturn tableIsThere(c.Request.Context(), h.pool, "bas_scenarios")',
        '\tvar exists bool\n'
        '\t_ = h.pool.QueryRow(c.Request.Context(),\n'
        '\t\t`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=\'bas_scenarios\')`).Scan(&exists)\n'
        '\treturn exists',
     'ハンドラが自前で `information_schema` を引きに戻る'),
    (T, '\tfor _, catalogue := range tableCatalogues {\n\t\tif strings.Contains(lit, catalogue) {\n\t\t\treturn true\n\t\t}\n\t}\n',
        '',
     '自前の確認を1つも見つけなくなる（**0件を検査して緑**）'),
    (T, '\treturn reasons[file+":"+fn] == ""', '\treturn false',
     '理由の有無を見ずに全部外す'),
    (T, '\tif !uses {\n\t\treturn false\n\t}', '\tif uses {\n\t\treturn false\n\t}',
     '確認を含まない関数の方を違反にする'),
    (T, 'const minHandlerFilesScanned = 500', 'const minHandlerFilesScanned = 0',
     '走査の床を 0 に落とす'),
    (T, 'const tableProbeRoot = "../.."', 'const tableProbeRoot = "."',
     '走査を `internal/api/handlers` に戻す（**外の 20 個が数から消えます**）'),

    # ── 理由の一覧が古くならないこと ─────────────────────────────────────
    (T, '\t\tif fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {\n\t\t\treturn true\n\t\t}',
        '\t\tif _, ok := decl.(*ast.FuncDecl); ok {\n\t\t\treturn true\n\t\t}',
     '理由の宛先が消えても気づかなくなる'),

    # ── 理由つきで外した件数 ─────────────────────────────────────────────
    (A, '\tconst want = 41', '\tconst want = 100',
     '理由つきで外した件数を実測から引き離す'),
    (A, '\t"store/table_probe.go:ProbeAnswer": "(c) 確認の失敗を「無い」に" +\n'
        '\t\t"倒さないための true です。失敗そのものは slog.Warn に出し、" +\n'
        '\t\t"応答は本物のクエリが決めます",\n',
        '',
     '`tableIsThere` の理由を消す（**上限0が「理由が書いてある」と'
     '言えなくなります**）'),
]

# ── handlers の外（scheduler / reports / detection / suppression / ldap） ──
AD = 'server/internal/detection/anomaly_detector.go'
RS = 'server/internal/reports/scheduler.go'
PT = 'server/internal/processtree/builder.go'
DM = 'server/internal/detectionmetrics/tracker.go'

CASES += [
    (AD, '\t\tslog.Error("anomaly_detector: ベースラインの読み出しが途中で失敗しました", "error", err)\n\t\treturn err\n',
         '\t\tslog.Warn("anomaly_detector: row iteration error", "error", err)\n',
     'ベースラインの読み込みが、途中までで「読み込めました」と答える'
     '（**元の実装**）'),
    (PT, '\t\tslog.Error("processtree: 行の読み出しが途中で失敗しました", "error", err)\n\t\treturn nil, err\n',
         '\t\tslog.Warn("processtree: row iteration error", "error", err)\n',
     'プロセス木が、途中までの木を返す（**親が読めていない子が根として'
     '並び、攻撃の連鎖が切れて見えます**）'),
    (DM, '\t\tslog.Error("detectionmetrics: 網羅表の走査が途中で失敗しました", "error", err)\n\t\treturn nil, err\n',
         '\t\tslog.Warn("detectionmetrics: GetMITRECoverage iteration failed", "error", err)\n',
     'MITRE 網羅率が、途中までのルールで計算される'),
    (RS, '\t\ttableExists := store.TableIsThere(ctx, s.pool, "scheduled_reports")',
         '\t\tvar tableExists bool\n'
         '\t\t_ = s.pool.QueryRow(ctx,\n'
         '\t\t\t`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=\'scheduled_reports\')`).Scan(&tableExists)',
     'レポートの予定表の確認が、自前に戻る'),
]

RUN = ('TestTableProbeFailureIsNotAbsence|TestTableProbeTimeoutIsNotAbsence|'
       'TestNoHandlerAsksInformationSchemaOnItsOwn|TestNoInformationSchemaReasonHasGoneStale|'
       'TestFailuresAreNotAnsweredWithAValue|TestReturnExceptionCountIsPinned|'
       'TestNoReturnExceptionHasGoneStale|TestProbeAnswerNeverTurnsAFailureIntoAbsence|'
       'TestProbeAnswerStillReportsRealAbsence|TestTheTableProbeDetectorRecognisesTheRealThing|'
       'TestTheHandlerScanFloorNoticesAnEmptyWalk|TestDeclaresFuncActuallyComparesTheName')

# handlers の外は、その package の検査で殺します。
OUTSIDE_HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1',
         '-run', 'TestFunctionsThatCanReturnAnErrorDoNotDiscardRowsErr|'
                 'TestNoHandlerAsksInformationSchemaOnItsOwn',
         './internal/store/', './internal/api/handlers/'],
    cwd='server',
)

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run', RUN, './internal/api/handlers/'],
    cwd='server',
)

OUTSIDE = {AD, RS, PT, DM}
INSIDE_CASES = [c for c in CASES if c[0] not in OUTSIDE]
OUTSIDE_CASES = [c for c in CASES if c[0] in OUTSIDE]

if __name__ == '__main__':
    rc = HARNESS.run(INSIDE_CASES)
    rc |= OUTSIDE_HARNESS.run(OUTSIDE_CASES)
    sys.exit(rc)

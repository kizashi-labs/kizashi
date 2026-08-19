#!/usr/bin/env python3
"""作り物を、実データとして 200 で返していないか。

対象:
  server/internal/api/handlers/fabricated_fixtures_test.go
  server/internal/api/handlers/itdr_handler.go

ITDR の宛先の書き間違い（`/api/itdr/…`）を直したら、**直した先が
作り物でした。** DB を1度も見ずに、その場で作ったインシデントを 200 で
返します:

    {"username": "admin.service", "risk_score": 9.1, "severity": "critical",
     "indicators": ["業務時間外の大量データアクセス", …],
     "detected_at": time.Now().Add(-20 * time.Minute)}

**SOC の画面です。** 実在しない admin.service の侵害を追わせます。
`id` は毎回 `uuid.New()` なので、再読み込みのたびに別のインシデントに
見え、「調査中」に変えることもできません。

**あの書き間違いだけが、作り物を画面に出さずに済ませていました。**

数えたら 15 file / 40 関数 → **全部 501 にして 0**。上限として
留めています —— どれを 501 にして、どれを本当に作るのかは機能の判断
なので `docs/判断待ちの一覧.md` に出してあります。

## 判定の形

    DB に触らない file の中で
    `uuid.New()` か `time.Now().Add(-…)` を含み
    200 で答える関数

## 置いていない変異

床（`walked < minFixtureScanFiles`）を `if false` に潰す変異は置いて
いません。**assertion は、自分が消されたことを自分では検知できません。**
床が効いていることは、**走査の根を `handlers` だけに狭める変異**が
そこで殺されることで分かります —— そちらは置いてあります。

（同じ理由で ITDR に作り物を戻す変異も置いていません: `uuid` も `time` も
import されていないので、build が壊れるだけです。）

## 判定の細部

`time.Now().Add(-…)` の**マイナス**が要ります: 有効期限の算出
（`Add(24 * time.Hour)`）は履歴の捏造ではありません。DB に触る file を
外すのは、`auth_handler.go` の `uuid.New()`（JWT の jti）を数えない
ためです。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mutate import Harness  # noqa: E402

T = 'server/internal/api/handlers/fabricated_fixtures_test.go'
H = 'server/internal/api/handlers/itdr_handler.go'
D = 'server/internal/api/handlers/drp_handler.go'
CS = 'server/internal/api/handlers/cspm_enhanced_handler.go'

CASES = [
    # ── 数 ───────────────────────────────────────────────────────────────
    (T, '\tfabricatedFixtureFuncs = 0', '\tfabricatedFixtureFuncs = 500',
     '作り物を返す関数の数を留めなくなる（0 が規則です）'),
    (T, '\tfabricatedFixtureFuncs = 0', '\tfabricatedFixtureFuncs = 3',
     '**作り物を3つまで許す**（0 が規則です）'),
    (T, '\tfabricatedFixtureFiles = 0', '\tfabricatedFixtureFiles = 500',
     'file の数を留めなくなる'),

    # ── 判定そのもの ─────────────────────────────────────────────────────
    (T, '\t\tif pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "uuid" && sel.Sel.Name == "New" {',
        '\t\tif pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "uuid" && sel.Sel.Name == "NewUnused" {',
     '**その場で作った id を見なくなる**（`uuid.New()` の record が'
     '素通りします）'),
    (T, '\t\tif sel.Sel.Name == "Add" && len(call.Args) == 1 {',
        '\t\tif sel.Sel.Name == "AddUnused" && len(call.Args) == 1 {',
     '**その場で作った履歴を見なくなる**（「20分前に検知」が'
     '素通りします）'),
    (T, '\t\t\t\tif u, ok := bin.X.(*ast.UnaryExpr); ok && u.Op == token.SUB {',
        '\t\t\t\tif u, ok := bin.X.(*ast.UnaryExpr); ok && u.Op != token.SUB {',
     '**マイナスの向きを反転する**（「20分前に検知」を見逃し、'
     '有効期限の算出を作り物に数えます）'),
    (T, '\t\tif touchesDatabase(string(src)) {\n\t\t\treturn nil\n\t\t}\n', '',
     '**DB に触る file も数える**（JWT の jti まで作り物になります）'),
    (T, 'func isFabricatedFixture(body *ast.BlockStmt) bool {\n'
        '\treturn inventsRecords(body) && answersWithSuccess(body)\n}',
        'func isFabricatedFixture(body *ast.BlockStmt) bool {\n'
        '\treturn inventsRecords(body)\n}',
     '**501 で返している例まで作り物に数える**（「これは無い」と言う'
     'ための例が違反になります）'),
    (T, 'func touchesDatabase(src string) bool {\n\tfor _, s := range',
        'func touchesDatabase(src string) bool {\n\treturn true\n\tfor _, s := range',
     '**どの file も「DB に触る」と答える**（走査が空になります）'),

    # ── 走査の広さ ───────────────────────────────────────────────────────
    #
    # **HTTP に答えるのは handlers だけではありません**
    # （`internal/ml/ml_handler.go`・`internal/billing/handler.go`）。
    # 元はこの package だけを歩いていました。
    (T, "const fixtureScanRoot = \"../..\"", "const fixtureScanRoot = \".\"",
     '**handlers だけを歩く**（別 package の作り物が走査の外に出ます）'),
    (T, '\t\t"api/handlers/itdr_handler.go":          "ID脅威",',
        '\t\t"itdr_handler.go":                        "ID脅威",',
     '**鍵を file 名に戻す**（一致しなくなり、黙って何も確かめなく'
     'なります）'),

    # ── ITDR ─────────────────────────────────────────────────────────────
    (H, '\tc.JSON(http.StatusNotImplemented, gin.H{',
        '\tc.JSON(http.StatusOK, gin.H{',
     '**ITDR が 200 で答える**（「まだ何も起きていない」と読まれ、'
     '待たれます）'),
    (D, '\tc.JSON(http.StatusNotImplemented, gin.H{',
        '\tc.JSON(http.StatusOK, gin.H{',
     '**DRP が 200 で答える**（漏洩を検出していないのに「検出0件」と'
     '読まれます）'),
    (CS, '\tc.JSON(http.StatusNotImplemented, gin.H{',
        '\tc.JSON(http.StatusOK, gin.H{',
     '**CSPM が 200 で答える**（設定不備0件に見えます）'),
]

# 置いていない変異:
#
#   ITDR に作り物を戻す変異は置いていません。**`uuid` も `time` も
#   import されていないので、build が壊れるだけです**（NOT-A-KILL で
#   あって kill ではありません）。走査が `uuid.New()` の record を
#   捕まえることは、見本を食わせる
#   `TestTheFixtureScanRecognisesTheRealThing` が確かめています ——
#   そして「ITDR が数の中に居ないこと」は上の件数が留めています。

HARNESS = Harness(
    root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    cmd=['go', 'test', '-count=1', '-run',
         'TestFabricatedFixturesAreNotGrowing|'
         'TestTheResponseFacingFixturesSayTheyAreUnimplemented|'
         'TestTheFixtureScanRecognisesTheRealThing',
         './internal/api/handlers/'],
    cwd='server',
)

if __name__ == '__main__':
    sys.exit(HARNESS.run(CASES))

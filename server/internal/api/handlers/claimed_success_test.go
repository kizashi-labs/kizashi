package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// **やっていない作業を「やった」と答えないこと。**
//
// 変更系のハンドラに、テーブルが無いときそのまま成功を返すものが 8 つ
// ありました。実測 (2026-08-12):
//
//	POST   /api/v1/campaigns          200 {"id":"<でっち上げ>","message":"created"}
//	PUT    /api/v1/campaigns/:id      200 {"message":"updated"}
//	DELETE /admin/edr-policies/:id    200 {"message":"削除しました"}
//	POST   /api/v1/fim/ignore-rules   200 {"message":"ignore rule added"}
//	POST   /admin/ldap/config         200 {"message":"ldap_configs テーブルが存在しません"}
//	POST   /admin/integrations/config 200 {"message":"Config saved"}
//	PUT    /admin/rbac/permissions    200 {"message":"Permissions saved"}
//	POST   /alerts/bulk-classify      200 {"processed":0,"classified":0,"skipped":0}
//
// **どれも1行も書いていません。** `campaigns` は存在しない id まで返すので、
// 画面はそれを「作成済みの1件」として持ちます。`rbac` のコメントには
// 「Accept but silently discard」と書いてありました —— 権限表を保存した
// つもりの管理者に、保存していないことは伝わりません。`fim` は、除外した
// つもりのファイルからアラートが出続けます。
//
// ── 読み取り側との違い ────────────────────────────────────────────
//
// 一覧が空で返るのは「まだ何も無い」と読めます（正しくないことも多いの
// ですが、少なくとも利用者は何も期待していません）。**変更系は違います** ——
// 利用者は「やった」と言われたことを前提に次へ進みます。取り消しも、
// 再実行も、確認もしません。
//
// ここは上限ではなく 0 です。

// mutatingHandler — 変更系の名前。
//
// **切り出してあるのは、この一覧を痩せさせる変更を殺せるようにするため**
// です。狭めると、その名前で書かれたハンドラが黙って外れます。
var mutatingHandler = regexp.MustCompile(
	`^(Create|Update|Delete|Add|Remove|Set|Assign|Approve|Reject|Start|Stop|Run|` +
		`Execute|Send|Import|Save|Register|Enable|Disable|Rotate|Revoke|Reset|` +
		`Trigger|Launch|Apply|Ack|Acknowledge|Resolve|Close|Bulk|Upsert|Post)`)

func TestTheMutatingNameListIsNotNarrowed(t *testing.T) {
	for _, name := range []string{
		"Create", "CreateIgnoreRule", "Update", "UpdatePermissions", "Delete",
		"SaveConfig", "BulkClassify", "Execute", "Revoke", "Apply",
	} {
		if !mutatingHandler.MatchString(name) {
			t.Errorf("%q を変更系と見ていません。**その名前のハンドラが"+
				"黙って走査から外れます**", name)
		}
	}
	for _, name := range []string{"List", "Get", "GetStats", "ListItems", "Export"} {
		if mutatingHandler.MatchString(name) {
			t.Errorf("%q を変更系に数えています。読み取りは別の規則です", name)
		}
	}
}

// looksLikeAbsenceGuard — その条件が「テーブルが無いとき」を指しているか。
//
// **切り出してあるのは、探し方を狭める変更を殺せるようにするため**です。
// いま違反は 0 件なので、走査の結果では気づけません。
func looksLikeAbsenceGuard(cond string) bool {
	if !strings.HasPrefix(cond, "!") {
		return false
	}
	for _, probe := range []string{
		"tableIsThere", "tableExists", "TableExists", "Exists", "exists",
		"Table(", "Table)",
	} {
		if strings.Contains(cond, probe) {
			return true
		}
	}
	return false
}

func TestTheAbsenceGuardDetectorRecognisesTheRealThing(t *testing.T) {
	for _, cond := range []string{
		`!tcExists`,
		`!h.tableExists(c, "edr_policies")`,
		`!tableIsThere(ctx, h.pool, "x")`,
		`!exists`,
		`!h.checkScenariosTable(c)`,
	} {
		if !looksLikeAbsenceGuard(cond) {
			t.Errorf("%q を「テーブルが無いとき」と見ていません。**その形で"+
				"書かれた分岐が走査から外れます**", cond)
		}
	}
	for _, cond := range []string{`err != nil`, `len(x) == 0`, `tcExists`} {
		if looksLikeAbsenceGuard(cond) {
			t.Errorf("%q を「テーブルが無いとき」に数えています", cond)
		}
	}
}

// answersSuccess — その本文が 2xx を返しているか。
func answersSuccess(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || found {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "http" {
			return true
		}
		switch sel.Sel.Name {
		case "StatusOK", "StatusCreated", "StatusAccepted", "StatusNoContent":
			found = true
		}
		return true
	})
	return found
}

// **やっていないのに「やった」と答えてよい場所。** 理由が要ります。
var claimedSuccessReasons = map[string]string{}

// 実測 (2026-08-12): この package の .go は 295 個。床は下に。
const minClaimedSuccessFiles = 200

func TestNoWriteEndpointClaimsSuccessWithoutWriting(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}

	type site struct {
		file string
		fn   string
		line int
		cond string
	}
	var bad []site
	scanned, guards := 0, 0

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		if readErr != nil {
			continue
		}
		scanned++
		f, parseErr := parser.ParseFile(fset, name, src, 0)
		if parseErr != nil {
			t.Errorf("%s を解析できません: %v", name, parseErr)
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !mutatingHandler.MatchString(fn.Name.Name) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				is, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				cond := condSource(src, fset, is.Cond)
				if !looksLikeAbsenceGuard(cond) {
					return true
				}
				guards++
				if !isClaimedSuccess(is.Body, name, fn.Name.Name, claimedSuccessReasons) {
					return true
				}
				bad = append(bad, site{name, fn.Name.Name,
					fset.Position(is.Pos()).Line, cond})
				return true
			})
		}
	}

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !rowsErrScanReached(scanned, minClaimedSuccessFiles) {
		t.Fatalf("走査が届いていません: %d ファイルしか見えません（床 %d）",
			scanned, minClaimedSuccessFiles)
	}
	// 変更系の中の「テーブルが無いとき」の分岐そのものが見えていること。
	// 実測 (2026-08-12): 68 箇所。
	if !rowsErrScanReached(guards, minAbsenceGuards) {
		t.Fatalf("走査が届いていません: 変更系の中の「テーブルが無いとき」の"+
			"分岐が %d 箇所しか見えません（実測 68、床 %d）", guards, minAbsenceGuards)
	}
	t.Logf("走査したファイル: %d / 変更系の不在分岐: %d", scanned, guards)

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	for _, s := range bad {
		t.Errorf("%s:%d %s が `%s` の中で成功を返しています。"+
			"**1行も書かずに「やった」と答えます** —— 利用者は取り消しも"+
			"再実行もしません。`FeatureNotInstalled` を使ってください",
			s.file, s.line, s.fn, s.cond)
	}
}

// 実測 (2026-08-12): 68 箇所。床は下に。
const minAbsenceGuards = 50

func TestTheAbsenceGuardFloorNoticesAnEmptyWalk(t *testing.T) {
	if rowsErrScanReached(0, minAbsenceGuards) {
		t.Error("**0 箇所でも「届いた」と言っています。**")
	}
	if !rowsErrScanReached(minAbsenceGuards, minAbsenceGuards) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minAbsenceGuards < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}

// condSource は条件式のソース文字列を返します。
func condSource(src []byte, fset *token.FileSet, e ast.Expr) string {
	start := fset.Position(e.Pos()).Offset
	end := fset.Position(e.End()).Offset
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	return string(src[start:end])
}

// 2xx の見分けが効くこと。
func TestAnswersSuccessTellsSuccessFromFailure(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	if !answersSuccess(parse(t, `c.JSON(http.StatusOK, gin.H{"message": "created"})`)) {
		t.Error("**200 を成功と見ていません。** これがまさに、書いていないのに" +
			"「やった」と答える形です")
	}
	if !answersSuccess(parse(t, `c.JSON(http.StatusCreated, gin.H{})`)) {
		t.Error("201 を成功と見ていません")
	}
	if answersSuccess(parse(t, `c.JSON(http.StatusServiceUnavailable, gin.H{})`)) {
		t.Error("503 を成功に数えています。**直したものが違反として並びます**")
	}
	if answersSuccess(parse(t, `FeatureNotInstalled(c, "x")`)) {
		t.Error("`FeatureNotInstalled` を成功に数えています")
	}
}

// isClaimedSuccess — その分岐が違反か。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするため**です。
// いま違反は 0 件なので、`if true` に潰しても挙がる件数は変わりません
// （変異が生き残りました）。
func isClaimedSuccess(body *ast.BlockStmt, file, fn string, reasons map[string]string) bool {
	if !answersSuccess(body) {
		return false
	}
	return reasons[file+":"+fn] == ""
}

// 違反の判定が効くこと。**違反する見本を食わせて確かめます。**
func TestClaimedSuccessJudgementRecognisesTheRealThing(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+body+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	ok200 := parse(t, `c.JSON(http.StatusOK, gin.H{"message": "created"})`)
	unavailable := parse(t, `FeatureNotInstalled(c, "x")`)
	reasons := map[string]string{"a.go:Excused": "理由が書いてあります"}

	if !isClaimedSuccess(ok200, "a.go", "NoReason", reasons) {
		t.Error("**理由の無い「やった」を、違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if isClaimedSuccess(ok200, "a.go", "Excused", reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}
	if isClaimedSuccess(unavailable, "a.go", "NoReason", reasons) {
		t.Error("**直したものを違反にしています。** 503 は「やっていない」" +
			"と言う応答です")
	}
}

// ファイルの床も、別に確かめます。**別の定数です。**
func TestTheClaimedSuccessFileFloorNoticesAnEmptyWalk(t *testing.T) {
	if rowsErrScanReached(0, minClaimedSuccessFiles) {
		t.Error("**0 ファイルでも「届いた」と言っています。**")
	}
	if rowsErrScanReached(minClaimedSuccessFiles-1, minClaimedSuccessFiles) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !rowsErrScanReached(minClaimedSuccessFiles, minClaimedSuccessFiles) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minClaimedSuccessFiles < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}

// `FeatureNotInstalled` が、成功に見えないこと。
//
// **文言が正直でも、200 なら画面は成功として扱います。**
// 直す前の `identity_handler` がまさにそれで、
// 「ldap_configs テーブルが存在しません」を 200 で返していました。
func TestFeatureNotInstalledDoesNotLookLikeSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	FeatureNotInstalled(c, "権限設定の保存")

	if w.Code < 500 {
		t.Errorf("status = %d。**2xx や 4xx だと、画面は成功か"+
			"利用者の誤りとして扱います**", w.Code)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503（読み取り側の 54 箇所と揃えます）", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "保存していません") {
		t.Errorf("**「保存していません」と言っていません。** 状態コードだけでは、"+
			"操作が通ったのか分かりません: %s", body)
	}
	if !strings.Contains(body, "権限設定の保存") {
		t.Errorf("何ができなかったのかを言っていません: %s", body)
	}
}

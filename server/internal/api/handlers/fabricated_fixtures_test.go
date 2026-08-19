package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fixtureScanRoot — `server/internal` 全体。この検査は handlers の中に
// ありますが、**見るのはそこだけではありません。**
const fixtureScanRoot = "../.."

// 実測 (2026-08-12): `server/internal` に 700 以上の .go があります。床は下に。
const minFixtureScanFiles = 500

// **作り物を、実データとして 200 で返さないこと。**
//
// 実測 (2026-08-12): ITDR の宛先を直していて気づきました。
// `/api/v1/admin/itdr/incidents` は DB を1度も見ず、**その場で作った
// インシデント4件**を返します:
//
//	{"username": "admin.service", "risk_score": 9.1, "severity": "critical",
//	 "indicators": ["業務時間外の大量データアクセス", "新規デバイスからのログイン"],
//	 "detected_at": time.Now().Add(-20 * time.Minute)}
//
// **SOC の画面です。** これを見た担当者は、実在しない admin.service の
// 侵害を追います。しかも `id` は `uuid.New()` なので、**再読み込みの
// たびに別のインシデントに見えます** —— 「調査中」にすることすら
// できません。
//
// 空の画面は「まだ何も起きていない」と読まれ、501 は「この機能は
// まだ無い」と読まれます。**作り物は「起きている」と読まれます** ——
// 3つのうち、対応を誤らせるのはこれだけです。
//
// 既にある約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない
//	500       読めなかった。もう一度試す価値がある
//	501       これを作るものが無い。待っても変わらない

// fixtureSite is one handler that answers 200 with invented records.
type fixtureSite struct {
	file string
	fn   string
}

// **判定**: DB に一度も触らない file の中で、`uuid.New()` か
// `time.Now().Add(-…)` を含む合成リテラルを組み立て、200 で答える関数。
//
//	uuid.New()             record の身元をその場で作っている
//	time.Now().Add(-…)     「20分前に検知」という履歴をその場で作っている
//
// **DB に触る file を外すのは、そこが本物を混ぜているからです。**
// `auth_handler.go` の `uuid.New()` は JWT の jti で、作り物ではありません。
func fabricatedFixtureSites(t *testing.T) []fixtureSite {
	t.Helper()
	var out []fixtureSite
	fset := token.NewFileSet()
	walked := 0
	// **`internal/` を全部歩きます。** 元はこの package だけでした ——
	// HTTP に答えるのは handlers だけではありません
	// （`internal/ml/ml_handler.go`・`internal/billing/handler.go`）。
	// 別の package に作り物の handler を足せば、走査の外でした。
	err := filepath.WalkDir(fixtureScanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		walked++
		if touchesDatabase(string(src)) {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return parseErr
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), fixtureScanRoot+"/")
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if isFabricatedFixture(fn.Body) {
				out = append(out, fixtureSite{file: rel, fn: fn.Name.Name})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	// **歩いた file の数を床にします。** 違反が 0 件なので、走査が壊れても
	// 「0 件」は変わりません —— 0 が「無い」なのか「見ていない」なのかを、
	// これで分けます。
	if walked < minFixtureScanFiles {
		t.Fatalf("走査が届いていません: file が %d 個しか見えません（床 %d）",
			walked, minFixtureScanFiles)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].fn < out[j].fn
	})
	return out
}

// isFabricatedFixture — その関数が、作った record を成功として返すか。
//
// **2つの条件を1つの関数にしてあるのは、片方を外す変異が
// 「通る木では何も変わらない」からです。** 全部 501 にした後は作り物が
// 0 件なので、`answersWithSuccess` を落としても数は 0 のままでした ——
// 見本を食わせられる形にして、直接殺します。
//
// **501 で返すなら作り物ではありません。** 「これは無い」と言うために
// 作った例を返すのは、嘘ではなく説明です。
func isFabricatedFixture(body *ast.BlockStmt) bool {
	return inventsRecords(body) && answersWithSuccess(body)
}

// touchesDatabase — その file がどこかで永続化に触るか。
//
// **生の問い合わせだけでは足りませんでした。** 最初は `.Query(` /
// `.Exec(` だけを見ていて、**store 越しに書いている本物を3つ
// 「作り物」に数えました**:
//
//	reports_handler.go:Generate    `ReportStore.Insert` でジョブを保存
//	notification_handler.go:Test   `store.Get` で宛先を引いて実際に送信
//	siem_handler.go:TestForward    `Store.List` で転送先を引く
//
// どれも `uuid.New()` を**本物の新しい ID** に使っています。危うく
// **動いている機能を 501 にするところでした** —— 走査が広すぎると、
// 直す先を間違えます。
//
// 実測: 作り物の 9 file は `internal/store` を import せず、store の
// field も持ちません。本物との境目はそこです。
func touchesDatabase(src string) bool {
	for _, s := range []string{
		".Query(", ".QueryRow(", ".Exec(", ".SendBatch(", ".CopyFrom(",
		"internal/store", "store.", "Store.",
	} {
		if strings.Contains(src, s) {
			return true
		}
	}
	return false
}

// inventsRecords — `uuid.New()` か `time.Now().Add(-…)` を含むか。
func inventsRecords(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "uuid" && sel.Sel.Name == "New" {
			found = true
			return true
		}
		// time.Now().Add(-…) —— 引数が単項マイナスで始まる Add。
		if sel.Sel.Name == "Add" && len(call.Args) == 1 {
			if u, ok := call.Args[0].(*ast.UnaryExpr); ok && u.Op == token.SUB {
				found = true
			}
			if bin, ok := call.Args[0].(*ast.BinaryExpr); ok {
				if u, ok := bin.X.(*ast.UnaryExpr); ok && u.Op == token.SUB {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// **数**。実測 (2026-08-12): 12 file / 46 関数。**上限です** ——
// 増えたら止め、直したら下げてください。
//
// どれを 501 にして、どれを本当に作るのかは機能の判断なので
// `docs/判断待ちの一覧.md` に出してあります。ITDR だけ先に 501 に
// しました（宛先を直した先がここだったので、**私が作り物を画面に
// 出すところでした**）。
const (
	fabricatedFixtureFuncs = 0
	fabricatedFixtureFiles = 0
)

func TestFabricatedFixturesAreNotGrowing(t *testing.T) {
	// **0 が規則です。** 上限だけだと、上限を上げる変異が「増えていない」
	// を素通りします —— 実際にそうなりました（実測 0 に対して上限 3 は、
	// 上限として見れば真です）。規則そのものを留めます。
	if fabricatedFixtureFuncs != 0 || fabricatedFixtureFiles != 0 {
		t.Errorf("留めている数が %d 関数 / %d file です。**0 が規則です** ——"+
			"作り物を1つでも許すなら、それは 501 にしていないという意味です",
			fabricatedFixtureFuncs, fabricatedFixtureFiles)
	}

	sites := fabricatedFixtureSites(t)
	files := map[string]bool{}
	for _, s := range sites {
		files[s.file] = true
	}

	if len(sites) > fabricatedFixtureFuncs {
		for _, s := range sites {
			t.Errorf("%s:%s が作り物を 200 で返しています。**空でも 500 でもなく"+
				"「起きている」と読まれます**", s.file, s.fn)
		}
		t.Fatalf("作り物を返す関数が %d です（留めているのは %d）",
			len(sites), fabricatedFixtureFuncs)
	}
	// **0 なので「減りました」はもうありません。** 増えたときだけ挙げます
	// —— 上の分岐が t.Fatalf で止めます。
	if len(files) != fabricatedFixtureFiles {
		t.Errorf("作り物を返す file が %d です（留めているのは %d）",
			len(files), fabricatedFixtureFiles)
	}
	t.Logf("作り物を返す関数: %d / file: %d", len(sites), len(files))
	for _, s := range sites {
		t.Logf("  %s:%s", s.file, s.fn)
	}
}

// **対応の判断に使われる3つ（ITDR・CSPM・DRP）を 501 にしました。**
//
// 直した理由が普通ではありません: `/api/itdr/…` という**宛先の
// 書き間違い**を直した先が、この作り物でした。**直した瞬間に、
// 実在しないインシデントが SOC の画面に出るところでした** ——
// 404 で空だった方がまだましです。
func TestTheResponseFacingFixturesSayTheyAreUnimplemented(t *testing.T) {
	// **対応を誤らせるのはこの3つです。** ITDR は「実在しない利用者の
	// 侵害」、CSPM は「公開されていない S3 バケット」、DRP は
	// 「漏れていない認証情報」—— どれも、見た人がその場で動きます。
	// **鍵は `internal/` からの相対パスです。** 走査を `internal/` 全体に
	// 広げたとき、ここが file 名のままだと**一致しなくなり、黙って何も
	// 確かめなくなります** —— 検査が緑のまま無力になる形です。
	facing := map[string]string{
		"api/handlers/itdr_handler.go":          "ID脅威",
		"api/handlers/cspm_enhanced_handler.go": "クラウド設定の不備",
		"api/handlers/drp_handler.go":           "ダークウェブの検出",
	}
	// **走査に訊きます。** 最初はソースを `strings.Contains` で見ていて、
	// **自分が書いた「元は uuid.New() でした」という注釈に当たりました**
	// —— 直したのに落ちます。このキャンペーンで2度目です。
	// **鍵が実在すること。** 綴りを間違えると、上の map は一致せず、
	// この検査は何も確かめないまま緑になります。
	for file := range facing {
		if _, err := os.Stat(filepath.Join(fixtureScanRoot, file)); err != nil {
			t.Fatalf("%s が見つかりません: %v。**鍵が実在しないと、"+
				"この検査は何も確かめません**", file, err)
		}
	}

	for _, s := range fabricatedFixtureSites(t) {
		if what, ok := facing[s.file]; ok {
			t.Errorf("%s の %s がまだ record を作っています。"+
				"**画面はそれを実在の%sとして出します**", s.file, s.fn, what)
		}
	}

	for file := range facing {
		src, err := os.ReadFile(filepath.Join(fixtureScanRoot, file))
		if err != nil {
			t.Fatalf("%s を読めません: %v", file, err)
		}
		if !strings.Contains(string(src), "http.StatusNotImplemented") {
			t.Errorf("%s が 501 を返していません。**200+空は「まだ何も"+
				"起きていない」と読まれ、待たれます**", file)
		}
	}
}

// 走査が効くこと。**見本を食わせて確かめます** —— 通る木では
// `inventsRecords` の否定側しか通らないので、潰しても数は変わりません。
func TestTheFixtureScanRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f(c *gin.Context) {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}

	if !inventsRecords(parse(`rows := []gin.H{{"id": uuid.New()}}
		c.JSON(http.StatusOK, rows)`)) {
		t.Error("**その場で作った id を見つけられません。**")
	}
	if !inventsRecords(parse(`rows := []gin.H{{"at": time.Now().Add(-2 * time.Hour)}}
		c.JSON(http.StatusOK, rows)`)) {
		t.Error("**その場で作った履歴を見つけられません。**")
	}
	if inventsRecords(parse(`c.JSON(http.StatusOK, gin.H{"now": time.Now()})`)) {
		t.Error("いまの時刻を作り物に数えています")
	}
	if inventsRecords(parse(`exp := time.Now().Add(24 * time.Hour)
		c.JSON(http.StatusOK, gin.H{"expires": exp})`)) {
		t.Error("**未来の時刻を作り物に数えています。** " +
			"有効期限の算出は履歴の捏造ではありません")
	}

	// **501 で返す作り物は数えないこと。**
	if !isFabricatedFixture(parse(`rows := []gin.H{{"id": uuid.New()}}
		c.JSON(http.StatusOK, rows)`)) {
		t.Error("作り物を 200 で返しているのに数えていません")
	}
	if isFabricatedFixture(parse(`rows := []gin.H{{"id": uuid.New()}}
		c.JSON(http.StatusNotImplemented, gin.H{"example": rows})`)) {
		t.Error("**501 で返している例を作り物に数えています。** " +
			"「これは無い」と言うための例まで違反になります")
	}

	if touchesDatabase("h.pool.Query(ctx, `SELECT 1`)") == false {
		t.Error("DB に触る file を見分けられません")
	}
	if touchesDatabase("c.JSON(http.StatusOK, gin.H{})") {
		t.Error("DB に触らない file を「触る」と答えています")
	}
	// **store 越しの本物を見分けること。** ここが漏れていたせいで、
	// 動いている3つを作り物に数えていました。
	if !touchesDatabase(`h.ReportStore.Insert(ctx, &store.ReportJobRow{})`) {
		t.Error("**store 越しの書き込みを見落としています。** " +
			"動いている機能を 501 にする側に間違えます")
	}
	if !touchesDatabase(`import "github.com/edr-platform/server/internal/store"`) {
		t.Error("store を import している file を見落としています")
	}
}

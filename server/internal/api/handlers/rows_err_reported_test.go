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

// 書き出したファイルが、途中までであることを言わないまま手元に残る。
//
// `rows.Next()` のループを抜けたあと、`rows.Err()` には「全部読み切った
// のか、途中で切れたのか」が入っています。**そこを警告ログに落として
// そのまま 200 を返すと、途中までの中身が全件として返ります。**
//
// 実測 (2026-08-12)。監査ログの書き出し（`/api/v1/audit-logs/export`）で、
// 行の読み出しをサーバ側から中断させました:
//
//	format=json  200 / Content-Disposition: attachment / **途中までのファイル**
//	format=cef   200 / Content-Disposition: attachment / **途中までのファイル**
//
// 受け取った側に、途中で切れたことを知る手掛かりがありません。**監査ログは
// 「その期間に何も無かった」ことの証拠に使われます。** 署名付きの書き出し
// （`audit_sign_handler.go`）はさらに悪く、欠けた記録に HMAC を付けて
// 「本物である」と証明していました。
//
// ── 既にある規則との関係 ──────────────────────────────────────────
//
// `rows_err_policy_test.go` が、この package の `rows.Err()` の答え方を
// 既に決めています —— **そのハンドラ自身がクエリ失敗にどう答えるかに
// 合わせる**、です。応答せず先へ進むハンドラ（合成ページ）では、
// `rows.Err()` もログに落として進むのが正解です。だから
// 「捨てている箇所の総数」に上限を置くのは筋が悪く、ここでは置きません
// （実測はしました: `rows.Err()` は 652 箇所、うち 337 箇所が捨てて
// います）。
//
// **抜けていたのは、応答がファイルとして残る経路です。** 一覧が途中まで
// なら、画面を作り直せばもう一度取り直せます。**ファイルは手元に残り、
// そのあと誰も取り直しません。** ここはその1点だけを、上限ではなく 0 で
// 留めます。
//
// ── もう1つ、これに寄りかかっていた上限があります ────────────────
//
// `answered_with_a_value_test.go` の `continue` の上限が 0 なのは、
// **「pgx は Scan の失敗で結果セットを閉じるので、そのあとの `rows.Err()`
// が答える」**という理由で `continue` を外しているからです。その理由は、
// `rows.Err()` を報告する関数の中でしか成り立ちません —— そちらは
// あのファイルで数え直しました。

// **`internal/` だけにすると `cmd/` が落ちます。** 落ちたことは件数が
// 下がる形で現れるので、下がったことを「直った」と読み違えます。
const rowsErrRoot = "../.."

// 実測 (2026-08-12): 652 箇所。床は現在値より下に置きます ——
// ぴったりにすると、関数を1つ消しただけで落ちます。
const minRowsErrSites = 580

// rowsErrScanReached — 走査が届いたかの判定そのもの。
//
// **切り出してあるのは、この判定を潰す変異を殺せるようにするため**です。
func rowsErrScanReached(scanned, floor int) bool {
	return scanned >= floor
}

func TestTheRowsErrScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if rowsErrScanReached(0, minRowsErrSites) {
		t.Error("**0 箇所でも「届いた」と言っています。** 走査が壊れた日に、" +
			"捨てている箇所が1つも無い姿と同じ緑を返します")
	}
	if rowsErrScanReached(minRowsErrSites-1, minRowsErrSites) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !rowsErrScanReached(minRowsErrSites, minRowsErrSites) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minRowsErrSites < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}

type rowsErrSite struct {
	file      string
	fn        string
	line      int
	discarded bool
	// download: 応答が Content-Disposition を付ける関数の中にある。
	download bool
}

// rowsErrIsReported — その処理が失敗を先へ渡しているか。
//
// **切り出してあるのは、判定を緩める変更を殺せるようにするため**です。
// 「`rows.Err()` を見ている」だけでは足りません —— 見たうえでログに
// 落として先へ進むのが、まさにここで数えている形です。
func rowsErrIsReported(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	reported := false
	ast.Inspect(block, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.ReturnStmt:
			reported = true
		case *ast.FuncLit:
			// 中の関数の return は、この関数から戻ることではありません。
			return false
		}
		return !reported
	})
	return reported
}

// 報告の判定が、ログと戻りを取り違えていないこと。
func TestRowsErrIsReportedTellsLoggingFromReturning(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.BlockStmt {
		t.Helper()
		src := "package p\nfunc f() {\n" + body + "\n}\n"
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	if rowsErrIsReported(parse(t, `slog.Warn("row iteration error", "error", err)`)) {
		t.Error("**ログに書くだけを「報告した」と数えています。** " +
			"これがまさに、途中までの一覧が 200 で返る形です")
	}
	if rowsErrIsReported(parse(t, `_ = err`)) {
		t.Error("何もしないものを「報告した」と数えています")
	}
	if !rowsErrIsReported(parse(t, `c.JSON(500, gin.H{"error": "x"})
	return`)) {
		t.Error("戻っているのに「報告していない」と数えています")
	}
	if rowsErrIsReported(parse(t, `go func() { return }()`)) {
		t.Error("**中の関数の return を、この関数から戻ることと取り違えています。** " +
			"呼び出し側には何も届きません")
	}
	if rowsErrIsReported(nil) {
		t.Error("中身が無いものを「報告した」と数えています")
	}
}

// findRowsErrSites は `rows.Err()` を扱っている箇所をすべて拾います。
func findRowsErrSites(t *testing.T, root string) []rowsErrSite {
	t.Helper()
	var sites []rowsErrSite
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			t.Errorf("%s を解析できません: %v", path, parseErr)
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// この関数の応答がファイルとして落ちるか。
			download := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if strings.Contains(lit.Value, "Content-Disposition") {
						download = true
					}
				}
				return true
			})

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.IfStmt:
					as, ok := v.Init.(*ast.AssignStmt)
					if !ok || len(as.Rhs) != 1 || !isRowsErrCall(as.Rhs[0]) {
						return true
					}
					sites = append(sites, rowsErrSite{
						file: rel, fn: fn.Name.Name,
						line:      fset.Position(v.Pos()).Line,
						discarded: !rowsErrIsReported(v.Body),
						download:  download,
					})
				case *ast.AssignStmt:
					// `_ = rows.Err()` —— 見てすらいない形。
					if len(v.Lhs) == 1 && len(v.Rhs) == 1 && isRowsErrCall(v.Rhs[0]) {
						if id, ok := v.Lhs[0].(*ast.Ident); ok && id.Name == "_" {
							sites = append(sites, rowsErrSite{
								file: rel, fn: fn.Name.Name,
								line:      fset.Position(v.Pos()).Line,
								discarded: true,
								download:  download,
							})
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return sites
}

func isRowsErrCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Err" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && strings.Contains(strings.ToLower(id.Name), "rows")
}

// 書き出しは別扱いです。**上限ではなく 0 です。**
//
// 一覧が途中までなら、画面を作り直せばもう一度取り直せます。**ファイルは
// 手元に残り、そのあと誰も取り直しません。** 監査ログの書き出しは
// 「その期間に何も無かった」ことの証拠として保存されます。
//
// 流しながら書く経路（CSV）だけは、失敗した時点でヘッダも最初の行も
// 相手に渡っているので、状態コードを変えられません。そちらは
// ファイルの中に印を書きます —— 理由は下の表に。
var rowsErrDownloadReasons = map[string]string{
	"api/handlers/report_export_handler.go:ExportAlerts": "CSV を書きながら流すので、" +
		"失敗した時点で 200 とヘッダが相手に渡っています。**状態コードは" +
		"もう変えられません。** 代わりに `markCSVIncomplete` が " +
		"`#INCOMPLETE` の行をファイルの末尾に書きます。",
	"api/handlers/report_export_handler.go:ExportCompliance": "同上。" +
		"溜めてから書く形に変えるのが本筋で、件数の上限とセットの判断なので " +
		"`docs/判断待ちの一覧.md` に置いてあります。",
	"api/handlers/pdf_report_handler.go:GenerateHTML": "このハンドラは" +
		"クエリが失敗しても応答せず、欠けた節を空にしてページを組み立てます。" +
		"ここで 500 を書くと二重応答になります（`rows_err_policy_test.go`）。" +
		"**PDF は今も途中までの数字で作られます。** 直すなら「読めなかった節を" +
		"空欄ではなく『取得できず』と印刷する」形で、版面の判断なので " +
		"`docs/判断待ちの一覧.md` に置いてあります。",
}

// isSilentDownloadTruncation — 違反かどうかの判定そのもの。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするため**です。
// いま違反は 0 件なので、`if false` に潰しても挙がる件数は変わらず、
// 走査の側では気付けません（変異が生き残りました）。
func isSilentDownloadTruncation(s rowsErrSite, reasons map[string]string) bool {
	if !s.download || !s.discarded {
		return false
	}
	return reasons[s.file+":"+s.fn] == ""
}

// 違反の判定が効くこと。**違反する見本を食わせて確かめます。**
func TestSilentDownloadTruncationIsRecognised(t *testing.T) {
	reasons := map[string]string{"a/b.go:WithReason": "理由が書いてあります"}

	bad := rowsErrSite{file: "a/b.go", fn: "NoReason", download: true, discarded: true}
	if !isSilentDownloadTruncation(bad, reasons) {
		t.Error("**理由の無い書き出しの取りこぼしを、違反と見ていません。** " +
			"途中までのファイルが全件として手元に残ります")
	}

	excused := rowsErrSite{file: "a/b.go", fn: "WithReason", download: true, discarded: true}
	if isSilentDownloadTruncation(excused, reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}

	reported := rowsErrSite{file: "a/b.go", fn: "NoReason", download: true, discarded: false}
	if isSilentDownloadTruncation(reported, reasons) {
		t.Error("報告しているものを違反にしています")
	}

	notDownload := rowsErrSite{file: "a/b.go", fn: "NoReason", download: false, discarded: true}
	if isSilentDownloadTruncation(notDownload, reasons) {
		t.Error("**書き出しでないものまで違反にしています。** " +
			"一覧の話は `rows_err_policy_test.go` の担当です")
	}
}

// 書き出しの床も、別に確かめます。
//
// **総数の床とは別の定数です。** 片方だけ 0 に落とせるので、片方だけ
// 試していると気付けません（変異が生き残りました）。
func TestTheDownloadScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if rowsErrScanReached(0, minDownloadRowsErrSites) {
		t.Error("**書き出しが 0 箇所でも「届いた」と言っています。**")
	}
	if rowsErrScanReached(minDownloadRowsErrSites-1, minDownloadRowsErrSites) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !rowsErrScanReached(minDownloadRowsErrSites, minDownloadRowsErrSites) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minDownloadRowsErrSites < 1 {
		t.Fatal("書き出しの床が 0 以下です。**どんな走査も通ります**")
	}
}

// splitDownloadSites — 書き出しの箇所と、そのうちの違反を分けます。
//
// **切り出してあるのは、この振り分けを潰す変異を殺せるようにするため**
// です。違反がいま 0 件なので、`if false` に潰しても走査の結果は変わり
// ません（変異が生き残りました）。合成した見本で直接試します。
func splitDownloadSites(sites []rowsErrSite, reasons map[string]string) (downloads, bad []rowsErrSite) {
	for _, s := range sites {
		if !s.download {
			continue
		}
		downloads = append(downloads, s)
		if isSilentDownloadTruncation(s, reasons) {
			bad = append(bad, s)
		}
	}
	return downloads, bad
}

// 振り分けが効くこと。
func TestSplitDownloadSitesSeparatesTheViolations(t *testing.T) {
	reasons := map[string]string{"a/b.go:Excused": "理由が書いてあります"}
	sites := []rowsErrSite{
		{file: "a/b.go", fn: "NotADownload", download: false, discarded: true},
		{file: "a/b.go", fn: "Reported", download: true, discarded: false},
		{file: "a/b.go", fn: "Excused", download: true, discarded: true},
		{file: "a/b.go", fn: "Violation", download: true, discarded: true},
	}
	downloads, bad := splitDownloadSites(sites, reasons)
	if len(downloads) != 3 {
		t.Errorf("書き出しの箇所 = %d, want 3。**数え落とすと、床の判定も"+
			"一緒に緩みます**", len(downloads))
	}
	if len(bad) != 1 {
		t.Fatalf("違反 = %d, want 1。**違反を1件も挙げないなら、この検査は"+
			"何も留めていません**", len(bad))
	}
	if bad[0].fn != "Violation" {
		t.Errorf("挙がった違反 = %s, want Violation", bad[0].fn)
	}
}

// 実測 (2026-08-12): 8 箇所。床は現在値より下に。
const minDownloadRowsErrSites = 6

func TestDownloadsDoNotTruncateSilently(t *testing.T) {
	sites := findRowsErrSites(t, rowsErrRoot)

	downloads, bad := splitDownloadSites(sites, rowsErrDownloadReasons)

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	// 走査そのものが届いているか、と、書き出しが見えているか、を別々に。
	if !rowsErrScanReached(len(sites), minRowsErrSites) {
		t.Fatalf("走査が届いていません: `rows.Err()` が %d 箇所しか見えません"+
			"（実測 652、床 %d）", len(sites), minRowsErrSites)
	}
	// 実測 (2026-08-12): 書き出しの中の `rows.Err()` は 8 箇所。
	if !rowsErrScanReached(len(downloads), minDownloadRowsErrSites) {
		t.Fatalf("走査が届いていません: 書き出しの中の `rows.Err()` が "+
			"%d 箇所しか見えません（実測 8、床 %d）",
			len(downloads), minDownloadRowsErrSites)
	}
	t.Logf("書き出しの中の `rows.Err()`: %d 箇所（うち印で済ませているもの %d）",
		len(downloads), len(rowsErrDownloadReasons))

	sort.Slice(bad, func(i, j int) bool { return bad[i].file < bad[j].file })
	for _, s := range bad {
		t.Errorf("%s:%d %s が、行の読み出しの失敗を黙って捨てています。"+
			"**途中までのファイルが、全件として手元に残ります**", s.file, s.line, s.fn)
	}
}

// `rows.Err()` の処理が、**その場の `err` 以外のエラー変数を持ち出さない**こと。
//
// 実測 (2026-08-12)。146 箇所を「そのハンドラ自身の答え方」に揃える書き換え
// をしたとき、`taxii_handler.go` の2箇所が番人の本文をそのまま写して
// `qErr.Error()` を呼びました。**`qErr` はそこでは nil です**（クエリは
// 成功しています）。読み出しが途中で切れた瞬間に nil 参照で落ちます ——
// 途中までの一覧を返すより悪い形に、直したつもりで変えるところでした。
//
// コンパイラは通します（変数はスコープにあります）。ここで留めます。
func TestRowsErrHandlingDoesNotReachForAnotherErrorVariable(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Errorf("%s を解析できません: %v", name, perr)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			is, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			as, ok := is.Init.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !isRowsErrCall(as.Rhs[0]) {
				return true
			}
			bound, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			checked++
			ast.Inspect(is.Body, func(m ast.Node) bool {
				id, ok := m.(*ast.Ident)
				if !ok || id.Name == bound.Name {
					return true
				}
				if strings.HasSuffix(id.Name, "Err") || strings.HasSuffix(id.Name, "err") {
					t.Errorf("%s:%d `rows.Err()` の処理が %q を使っています。"+
						"**そこでは nil のはずの変数です** —— 読み出しが切れた"+
						"瞬間に nil 参照で落ちます（%q を使ってください）",
						name, fset.Position(id.Pos()).Line, id.Name, bound.Name)
				}
				return true
			})
			return true
		})
	}
	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !rowsErrScanReached(checked, minPackageRowsErrChecks) {
		t.Fatalf("走査が届いていません: `rows.Err()` の分岐が %d 個しか"+
			"見えません（床 %d）", checked, minPackageRowsErrChecks)
	}
	t.Logf("調べた `rows.Err()` の分岐: %d 個", checked)
}

// 実測 (2026-08-12): この package に 422 個。床は現在値より下に。
const minPackageRowsErrChecks = 380

package tick

import (
	"fmt"
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

// **走査が file を黙って飛ばさないこと。**
//
// このリポジトリの検査の多くは、ソースを AST で歩いて数を留めます。
// その歩き方が `parser.ParseFile` の失敗を黙って飛ばしていると、
// **その file は走査から消えます** —— 中に何が書いてあっても 0 件です。
//
// 気づいたのは変異検査です。実測 (2026-08-12):
//
//	internal/tick                元の実装に戻す変異が **3件** 生き残った
//	internal/api/handlers        同じ形で **1件**
//
// 構文を壊した file は、`go test` の対象 package でなければコンパイルも
// 走りません。**だから「壊した」ことに誰も気づかず、走査からも消えて、
// 検査は緑のまま**でした。
//
// 1本ずつ直すより、まとめて留める段階です。`server/internal` の
// `*_test.go` を歩いて、**parse の失敗を握りつぶしている箇所**を挙げます。
// 実測: 16 か所ありました（`return nil` が 12、`continue` が 4）。
//
// **読み込み（`os.ReadFile`）の失敗も同じ形**ですが、ここでは見ていません
// —— parse の失敗は「変異検査が実際に通り抜けた道」で、読み込みの失敗は
// そうではないためです。増やすなら、増やしたことが分かるようにします。

// scanHonestyRoot は `server/internal` です。
const scanHonestyRoot = ".."

// **床。** 実測 (2026-08-12): `internal` の `*_test.go` に
// `parser.ParseFile` は 97 か所。0 になったら、走査そのものが
// 動いていません。
const minParseFileCalls = 60

// 実測 (2026-08-12): 16 → 0。**0 が規則です。**
const silentParseSkips = 0

// parseSkipSite is one place a scan swallows a parse failure.
type parseSkipSite struct {
	file string
	line int
	kind string // "continue" / "return nil" / "error discarded"
}

func (s parseSkipSite) String() string {
	return fmt.Sprintf("%s:%d (%s)", s.file, s.line, s.kind)
}

// isParseFileCall reports whether n is `parser.ParseFile(…)`.
func isParseFileCall(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ParseFile" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "parser"
}

// swallowsTheParseFailure reports whether this if-body gives up quietly.
//
// **判定を分けてあります。** 実測が 0 になったので、上の走査は通る木では
// 何も返しません —— この判定を潰しても、件数は 0 のままです。
func swallowsTheParseFailure(b *ast.BlockStmt) (string, bool) {
	if b == nil || len(b.List) != 1 {
		return "", false
	}
	switch s := b.List[0].(type) {
	case *ast.BranchStmt:
		if s.Tok == token.CONTINUE {
			return "continue", true
		}
	case *ast.ReturnStmt:
		if len(s.Results) == 0 {
			return "bare return", true
		}
		if len(s.Results) == 1 {
			if id, ok := s.Results[0].(*ast.Ident); ok && id.Name == "nil" {
				return "return nil", true
			}
		}
	}
	return "", false
}

// silentParseSkipsUnder walks root and returns the swallow sites, plus how many
// `parser.ParseFile` calls it saw at all.
//
// 根を引数に取るのは、**この検査自身が壊れた file を飛ばしていないこと**を
// 確かめるためです。
func silentParseSkipsUnder(root string) ([]parseSkipSite, int, error) {
	var out []parseSkipSite
	calls := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		ast.Inspect(f, func(n ast.Node) bool {
			blk, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, st := range blk.List {
				as, ok := st.(*ast.AssignStmt)
				if !ok || len(as.Rhs) != 1 || !isParseFileCall(as.Rhs[0]) {
					continue
				}
				calls++
				if len(as.Lhs) != 2 {
					continue
				}
				ev, ok := as.Lhs[1].(*ast.Ident)
				if !ok {
					continue
				}
				if ev.Name == "_" {
					out = append(out, parseSkipSite{rel, fset.Position(as.Pos()).Line, "error discarded"})
					continue
				}
				if i+1 >= len(blk.List) {
					continue
				}
				ifs, ok := blk.List[i+1].(*ast.IfStmt)
				if !ok {
					continue
				}
				if kind, bad := swallowsTheParseFailure(ifs.Body); bad {
					out = append(out, parseSkipSite{rel, fset.Position(ifs.Pos()).Line, kind})
				}
			}
			return true
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, calls, err
}

func TestNoScanSwallowsAParseFailure(t *testing.T) {
	sites, calls, err := silentParseSkipsUnder(scanHonestyRoot)
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	if calls < minParseFileCalls {
		t.Fatalf("`parser.ParseFile` が %d か所しか見つかりません（床 %d）。"+
			"**0 件は「無い」ではなく「探していない」かもしれません**",
			calls, minParseFileCalls)
	}
	if minParseFileCalls < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
	if len(sites) != silentParseSkips {
		t.Errorf("parse の失敗を握りつぶしている走査が %d か所です"+
			"（留めているのは %d）", len(sites), silentParseSkips)
	}
	for _, s := range sites {
		t.Errorf("%s が parse の失敗を握りつぶしています。**その file は"+
			"走査から消え、中に何が書いてあっても 0 件になります** —— "+
			"歩き方なら `return <err>`、ループなら `t.Fatalf` にしてください",
			s)
	}
}

// 判定そのものが動くこと。通る木では一度も真になりません。
func TestTheParseSkipRuleActuallyFires(t *testing.T) {
	parse := func(src string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\nfor {\n"+src+"\n}\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out *ast.BlockStmt
		ast.Inspect(f, func(n ast.Node) bool {
			if ifs, ok := n.(*ast.IfStmt); ok && out == nil {
				out = ifs.Body
			}
			return true
		})
		return out
	}
	for _, c := range []struct {
		name, src, kind string
		want            bool
	}{
		{"continue", "if err != nil {\ncontinue\n}", "continue", true},
		{"return nil", "if err != nil {\nreturn nil\n}", "return nil", true},
		{"bare return", "if err != nil {\nreturn\n}", "bare return", true},
		{"error を返す", "if err != nil {\nreturn err\n}", "", false},
		{"落とす", "if err != nil {\nt.Fatalf(\"x\")\n}", "", false},
		{"何かしてから飛ばす", "if err != nil {\nt.Errorf(\"x\")\ncontinue\n}", "", false},
	} {
		kind, got := swallowsTheParseFailure(parse(c.src))
		if got != c.want || kind != c.kind {
			t.Errorf("%s: (%q, %v), want (%q, %v)", c.name, kind, got, c.kind, c.want)
		}
	}

	// 呼び出しの見分け。
	callOf := func(src string) ast.Node {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok && out == nil {
				out = ce
			}
			return true
		})
		return out
	}
	if !isParseFileCall(callOf("f, err := parser.ParseFile(fset, p, nil, 0)")) {
		t.Error("`parser.ParseFile` を見つけられません")
	}
	if isParseFileCall(callOf("f, err := other.ParseFile(fset, p, nil, 0)")) {
		t.Error("`parser` 以外の `ParseFile` を数えています")
	}
	if isParseFileCall(callOf("f, err := parser.ParseDir(fset, p, nil, 0)")) {
		t.Error("`ParseDir` を数えています")
	}
}

// **この検査自身が、壊れた file を飛ばしていないこと。**
func TestTheParseSkipScanDoesNotSkipABrokenFile(t *testing.T) {
	root := t.TempDir()
	const src = `package p

import (
	"go/parser"
	"go/token"
)

func walk(path string) error {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, nil, 0)
	if perr != nil {
		return nil
	}
	_ = f
	return nil
}
`
	if err := os.WriteFile(filepath.Join(root, "a_test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	sites, calls, err := silentParseSkipsUnder(root)
	if err != nil {
		t.Fatalf("読める木で失敗しています: %v", err)
	}
	if calls != 1 || len(sites) != 1 || sites[0].kind != "return nil" {
		t.Fatalf("見本を読めていません: calls=%d sites=%v", calls, sites)
	}

	// **error を `_` に捨てる形も挙げること。** いま木に1つも無いので、
	// 見本で確かめます —— 無いものは、見ていなくても 0 件です。
	discarded := strings.Replace(src, "f, perr := parser.ParseFile", "f, _ := parser.ParseFile", 1)
	discarded = strings.Replace(discarded, "\tif perr != nil {\n\t\treturn nil\n\t}\n", "", 1)
	if err := os.WriteFile(filepath.Join(root, "a_test.go"), []byte(discarded), 0o644); err != nil {
		t.Fatal(err)
	}
	sites, _, err = silentParseSkipsUnder(root)
	if err != nil {
		t.Fatalf("読める木で失敗しています: %v", err)
	}
	if len(sites) != 1 || sites[0].kind != "error discarded" {
		t.Errorf("`f, _ := parser.ParseFile(…)` を挙げていません: %v", sites)
	}

	if err := os.WriteFile(filepath.Join(root, "a_test.go"),
		[]byte(src+"\nfunc broken( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if sites, _, err = silentParseSkipsUnder(root); err == nil {
		t.Errorf("parse できない file を黙って飛ばしています（%d 件を"+
			"返しました）。**この検査が、まさに見張っている形をしています**",
			len(sites))
	}
}

// **`cmd/` の周期的な仕事は、走査の外にありました。**
//
// この campaign の走査はどれも `server/internal` を根にしています
// （`workerRoot = ".."`）。`cmd/` は最初から範囲の外でした。
//
// 見つけたのは、`store/live_response.go:ExpireOldSessions` を
// `metrics.BackgroundFailed` に通そうとしたときです。「報告する相手が
// いない」と分類しかけて呼び出し側を見たら、**`cmd/api/main.go` の
// 5分の ticker** でした ——「回」が無いのではなく、**誰も作っていない**
// だけです。
//
// 実測 (2026-08-12):
//
//	cmd/api/main.go        周期の枝 6、`tick.Run` 0
//	cmd/detection/main.go  周期の枝 2、`tick.Run` 0
//
// **8つとも、動いているのか一度も動いていないのかを外から区別
// できませんでした。** `internal/scheduler` の 40 個で直したのと同じ形が、
// package の外に残っていました。中身は、オンライン端末数の計測、脅威
// フィードの自動同期、スケジュールレポートの実行、ライブレスポンスの
// セッション期限切れとコマンドのタイムアウト、セッションの掃除、
// 行動ベースラインの構築、検知ルールの再読み込みです。
//
// **全部 `tick.Run` で包みました (2026-08-12)。** 0 が規則です。
//
// 数えるのは **`<-ticker.C:` の枝**で、ticker の本数ではありません ——
// 起動時に1回まわしてから ticker に入る形（`behavioral_baseline_builder`）
// では `tick.Run` の方が多くなり、本数で引くと負になります。

const cmdRoot = "../../cmd"

// 実測 (2026-08-12): 8 → **全部 `tick.Run` で包んで 0。**
const untrackedCmdTickers = 0

// cmdTickerCounts returns how many periodic branches (`<-ticker.C:`) and
// tick.Run calls cmd/ has.
func cmdTickerCounts(t *testing.T) (tickers, tracked int) {
	t.Helper()
	for _, c := range cmdTickerCountsByFile(t) {
		tickers += c.branches
		tracked += c.runs
	}
	return tickers, tracked
}

type cmdFileCount struct {
	file     string
	branches int
	runs     int
}

// **file ごとに数えます。** 合計で引くと、起動時に1回まわす形の余分な
// `tick.Run` が、別の場所の未追跡の枝を1つ肩代わりします。
func cmdTickerCountsByFile(t *testing.T) []cmdFileCount {
	t.Helper()
	var out []cmdFileCount
	err := filepath.WalkDir(cmdRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		body := stripGoLineComments(string(src))
		// **数えるのは「周期の枝」です。** ticker の本数ではありません ——
		// 1つの ticker が複数の枝を持つことも、起動時に1回まわしてから
		// ticker に入ることもあります（`cmd/detection` の
		// `behavioral_baseline_builder` がその形で、`tick.Run` が 2 回
		// 出てきます）。本数で引き算すると、そこで負になります。
		b, r := countPeriodicBranches(body)
		if b > 0 || r > 0 {
			out = append(out, cmdFileCount{filepath.ToSlash(path), b, r})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file < out[j].file })
	return out
}

// countPeriodicBranches counts `<-ticker.C:` branches and tick.Run calls.
//
// **切り出してあるのは、数え分けていることを確かめるため**です。両方を
// 同じ文字列で数えても、いま在る木ではどの file も差が 0 になり、
// 見た目が変わりません。
func countPeriodicBranches(body string) (branches, runs int) {
	return strings.Count(body, ".C:"), strings.Count(body, "tick.Run(")
}

// stripGoLineComments removes `// …` so a comment mentioning a ticker is not
// counted as one. **数えるのはコードだけです。**
func stripGoLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// untrackedBranches — file ごとに「包まれていない周期の枝」を数えます。
//
// **判定を切り出してあります。** 実測が 0 になったので、通る木では
// 一度も真になりません —— この足し算を潰しても件数は 0 のままです。
func untrackedBranches(counts []cmdFileCount) int {
	n := 0
	for _, c := range counts {
		if d := c.branches - c.runs; d > 0 {
			n += d
		}
	}
	return n
}

func TestPeriodicWorkInCmdIsNotGrowingUntracked(t *testing.T) {
	tickers, tracked := cmdTickerCounts(t)
	if tickers < 1 {
		t.Fatalf("`cmd/` に周期の枝が1つも見つかりません。**走査が届いて" +
			"いません** —— 0 件は「無い」ではなく「探していない」かもしれません")
	}
	untracked := untrackedBranches(cmdTickerCountsByFile(t))
	if untracked > untrackedCmdTickers {
		t.Errorf("`cmd/` の未追跡の周期処理が %d から %d に増えました"+
			"（ticker %d、`tick.Run` %d）。**動いているのか一度も動いて"+
			"いないのかが、外から区別できません**",
			untrackedCmdTickers, untracked, tickers, tracked)
	}
	if untracked < untrackedCmdTickers {
		t.Errorf("`cmd/` の未追跡の周期処理が %d まで減りました。"+
			"**留めている数を %d に下げてください**", untracked, untracked)
	}
	t.Logf("cmd/: 周期の枝 %d、`tick.Run` %d、未追跡 %d", tickers, tracked, untracked)
}

// 数え方が本物を見ていること。
func TestTheCmdTickerCountIgnoresComments(t *testing.T) {
	const src = "// case <-ticker.C: はコメントです\n\tcase <-ticker.C:\n\ttick.Run(ctx, \"x\", f)\n"
	body := stripGoLineComments(src)
	if strings.Count(body, ".C:") != 1 {
		t.Errorf("コメント内の周期の枝を数えています: %q", body)
	}
	if strings.Count(body, "tick.Run(") != 1 {
		t.Errorf("`tick.Run` を読めていません: %q", body)
	}

	// **枝と `tick.Run` を、別々に数えていること。**
	for _, c := range []struct {
		name           string
		src            string
		branches, runs int
	}{
		{"包んである", "case <-t.C:\n\ttick.Run(ctx, \"a\", f)\n", 1, 1},
		{"包んでいない", "case <-t.C:\n\tdoWork(ctx)\n", 1, 0},
		{"起動時にも回す", "tick.Run(ctx, \"a\", f)\ncase <-t.C:\n\ttick.Run(ctx, \"a\", f)\n", 1, 2},
		{"周期でない", "tick.Run(ctx, \"a\", f)\n", 0, 1},
	} {
		b, r := countPeriodicBranches(c.src)
		if b != c.branches || r != c.runs {
			t.Errorf("%s: 枝=%d 包み=%d, want %d/%d。**同じ文字列で"+
				"両方を数えると、どの file も差が 0 になります**",
				c.name, b, r, c.branches, c.runs)
		}
	}
	if untrackedCmdTickers < 0 {
		t.Fatal("上限が負です")
	}

	// **file ごとに数えること。** 合計で引くと、起動時に1回まわす形の
	// 余分な `tick.Run` が、別の file の未追跡の枝を肩代わりします。
	for _, c := range []struct {
		name string
		in   []cmdFileCount
		want int
	}{
		{"全部包んである", []cmdFileCount{{"a.go", 3, 3}}, 0},
		{"1つ包み忘れ", []cmdFileCount{{"a.go", 3, 2}}, 1},
		{"起動時の1回で多い", []cmdFileCount{{"a.go", 1, 2}}, 0},
		{"余分が別 file を肩代わりしない",
			[]cmdFileCount{{"a.go", 1, 2}, {"b.go", 2, 1}}, 1},
		{"何も無い", nil, 0},
	} {
		if got := untrackedBranches(c.in); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

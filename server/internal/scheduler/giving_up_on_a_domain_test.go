package scheduler

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"testing"
)

// **1つのドメインを諦めたとき、行と回の両方に出ていること。**
//
// `checkDomainCert` はドメインごとに早く戻る枝を持っています。諦めた枝は
// 2つのことをしなければなりません:
//
//	recordCertUnreachable  行に status='error' を書く（画面に出る）
//	fail                   この回を「終えられなかった」に落とす（計測に出る）
//
// **片方だけだと、画面と計測が食い違います。** 実測 (2026-08-12): 3つの
// 枝のうち2つ —— TLS の型アサーション失敗とピア証明書0件 —— は
// `slog.Warn` + `recordCertUnreachable` でした。行には error が入るので
// 画面には出ますが、**その回は成功として刻まれます**。どちらも error 値を
// 持たない失敗だったので、`fail` に渡すものが無く、そこで止まっていました。
// 名前のある error を2つ作って渡しました。
//
// 逆向きも欠陥です。`fail` だけして行を触らないと、画面はそのドメインを
// 前回の status のまま —— 多くは `valid` —— で表示し続けます。
//
// この検査は判定を `givingUpProblems` に出してあります。走査の側を骨抜きに
// しても（枝を1つも見つけられなくしても）下の件数で落ちます。

// domainBranch is one early return in checkDomainCert.
type domainBranch struct {
	line     int
	cond     string
	marksRow bool // recordCertUnreachable を呼んでいる
	failsRun bool // fail を呼んでいる
}

// gaveUp reports whether this branch is one that abandoned the domain. A branch
// that does neither is "there was nothing more to do" (`!verdict.alert`), not a
// failure.
func (b domainBranch) gaveUp() bool { return b.marksRow || b.failsRun }

// givingUpProblems is the judgement, separated from the scan so it can be
// exercised directly. Both loops below push on the failing path only, which is
// why the counts are pinned in the test as well: a scan that finds nothing
// produces an empty problem list, and that reads exactly like a healthy one.
func givingUpProblems(branches []domainBranch) []string {
	var out []string
	for _, b := range branches {
		switch {
		case b.marksRow && !b.failsRun:
			out = append(out, fmt.Sprintf(
				"%d行目 (%s) は行に status='error' を書きますが、この回を"+
					"失敗にしていません。**画面には出ますが、計測では"+
					"「回って成功した」ままです** —— `fail(ctx, err, …)` を"+
					"通してください（渡す error が無ければ、名前のある error を"+
					"1つ作ります。`errNoPeerCertificate` がその例です）",
				b.line, b.cond))
		case b.failsRun && !b.marksRow:
			out = append(out, fmt.Sprintf(
				"%d行目 (%s) はこの回を失敗にしますが、行を触っていません。"+
					"**画面はそのドメインを前回の status のまま —— 多くは "+
					"`valid` —— で表示し続けます**",
				b.line, b.cond))
		}
	}
	sort.Strings(out)
	return out
}

// domainBranchesIn reads the early returns of the named function.
func domainBranchesIn(t *testing.T, path, fn string) []domainBranch {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	return domainBranchesFrom(t, src, path, fn)
}

// domainBranchesFrom is the scan itself, taking source rather than a path so
// the two recognisers below can be fed a function that calls *something else*.
// Reading only the real file cannot tell "recognises `fail`" apart from
// "recognises any call at all" — on the passing tree every giving-up branch
// calls both, so a recogniser that matched everything would look identical.
func domainBranchesFrom(t *testing.T, src []byte, path, fn string) []domainBranch {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("%s を parse できません: %v", path, err)
	}

	var decl *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == fn {
			decl = d
		}
		return decl == nil
	})
	if decl == nil {
		t.Fatalf("%s の定義が見つかりません。**名前が変わったなら"+
			"この検査も追ってください** —— 探して無かったのと"+
			"探していないのは、ここでは同じ形になります", fn)
	}

	var out []domainBranch
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		var returns, marks, fails bool
		ast.Inspect(ifs.Body, func(m ast.Node) bool {
			switch s := m.(type) {
			case *ast.ReturnStmt:
				returns = true
			case *ast.CallExpr:
				switch f := s.Fun.(type) {
				case *ast.Ident:
					if f.Name == "fail" {
						fails = true
					}
				case *ast.SelectorExpr:
					if f.Sel.Name == "recordCertUnreachable" {
						marks = true
					}
				}
			}
			return true
		})
		if !returns {
			return true
		}
		out = append(out, domainBranch{
			line:     fset.Position(ifs.Pos()).Line,
			cond:     string(src[ifs.Cond.Pos()-file.FileStart : ifs.Cond.End()-file.FileStart]),
			marksRow: marks,
			failsRun: fails,
		})
		return true
	})
	return out
}

// 実測 (2026-08-12): 早く戻る枝は4つ。うち3つがドメインを諦めた枝
// （dial 失敗・型アサーション失敗・ピア証明書0件）、1つは
// `!verdict.alert` ——「上げるアラートが無い」で、失敗ではありません。
const (
	certGiveUpBranches   = 3
	certEarlyReturnTotal = 4
)

func TestGivingUpOnADomainShowsInBothPlaces(t *testing.T) {
	branches := domainBranchesIn(t, "cert_expiry_checker.go", "checkDomainCert")

	if len(branches) != certEarlyReturnTotal {
		t.Errorf("早く戻る枝が %d 個です（留めているのは %d）。"+
			"増えたなら、その枝が諦めた枝かどうかを見てください",
			len(branches), certEarlyReturnTotal)
	}
	gaveUp := 0
	for _, b := range branches {
		if b.gaveUp() {
			gaveUp++
		}
	}
	if gaveUp != certGiveUpBranches {
		t.Errorf("ドメインを諦めた枝が %d 個です（留めているのは %d）。"+
			"**減っているなら、どちらの報告もしない枝になっている"+
			"可能性があります** —— 黙って戻る枝はここに現れません",
			gaveUp, certGiveUpBranches)
	}
	for _, p := range givingUpProblems(branches) {
		t.Error(p)
	}
}

// 判定そのものが動くこと。上の検査は通る木では何も push しないので、
// これが無いと `givingUpProblems` を `return nil` にしても誰も気づけません。
func TestTheGivingUpRuleActuallyFires(t *testing.T) {
	for _, c := range []struct {
		name   string
		b      domainBranch
		want   int
		gaveUp bool
	}{
		{"両方している", domainBranch{marksRow: true, failsRun: true}, 0, true},
		{"行だけ", domainBranch{marksRow: true}, 1, true},
		{"回だけ", domainBranch{failsRun: true}, 1, true},
		{"どちらもしない（諦めた枝ではない）", domainBranch{}, 0, false},
	} {
		if got := givingUpProblems([]domainBranch{c.b}); len(got) != c.want {
			t.Errorf("%s: %d件 (want %d): %v", c.name, len(got), c.want, got)
		}
		// **片側だけの枝も「諦めた枝」です。** 両方している枝だけを
		// 数えると、件数の側は健全な木と半端な木を同じに見ます
		// —— 上の件数で落ちなくなる分、`givingUpProblems` 頼みに
		// なります。
		if got := c.b.gaveUp(); got != c.gaveUp {
			t.Errorf("%s: gaveUp = %v, want %v", c.name, got, c.gaveUp)
		}
	}
	// 2つの向きで文言が違うこと。同じ文言だと、どちらが欠けているのか
	// 読んだ人には分かりません。
	row := givingUpProblems([]domainBranch{{marksRow: true}})
	run := givingUpProblems([]domainBranch{{failsRun: true}})
	if len(row) != 1 || len(run) != 1 || row[0] == run[0] {
		t.Errorf("2つの向きが同じ文言になっています: %v / %v", row, run)
	}
}

// 走査が本物を読めていること。件数だけだと、`checkDomainCert` を
// 見つけられていない状態と区別がつきません（そちらは Fatal で落ちますが、
// 「4つ見つけたが中身は全部 false」は落ちません）。
func TestTheDomainBranchScannerReadsTheRealFunction(t *testing.T) {
	branches := domainBranchesIn(t, "cert_expiry_checker.go", "checkDomainCert")

	byCond := map[string]domainBranch{}
	for _, b := range branches {
		byCond[b.cond] = b
	}
	for _, want := range []string{"err != nil", "!ok", "len(peerCerts) == 0"} {
		b, ok := byCond[want]
		if !ok {
			t.Errorf("`%s` の枝を読めていません: %v", want, byCond)
			continue
		}
		if !b.marksRow {
			t.Errorf("`%s` の `recordCertUnreachable` を読めていません", want)
		}
		if !b.failsRun {
			t.Errorf("`%s` の `fail` を読めていません", want)
		}
	}
	if b, ok := byCond["!verdict.alert"]; !ok {
		t.Error("`!verdict.alert` の枝を読めていません")
	} else if b.gaveUp() {
		t.Error("`!verdict.alert` を諦めた枝として数えています")
	}
}

// 2つの見分けが、名前を見ていること。
//
// **本物のファイルだけでは確かめられません。** 通る木では諦めた枝が
// どれも両方を呼んでいるので、「`fail` を見分けている」実装と
// 「呼び出しなら何でも数える」実装が同じ答えを返します。別の関数を
// 呼ぶ枝を食わせて、初めて分かれます。
const scannerProbe = `package p

func (c *T) probe(ctx context.Context, cert certRow) {
	if onlyRow {
		slog.Warn("行だけ")
		c.recordCertUnreachable(ctx, cert)
		return
	}
	if onlyRun {
		fail(ctx, err, "回だけ")
		return
	}
	if neither {
		helper(ctx)
		c.somethingElse(ctx)
		return
	}
	if noReturn {
		c.recordCertUnreachable(ctx, cert)
	}
}
`

func TestTheTwoRecognisersLookAtTheName(t *testing.T) {
	byCond := map[string]domainBranch{}
	for _, b := range domainBranchesFrom(t, []byte(scannerProbe), "probe.go", "probe") {
		byCond[b.cond] = b
	}
	for _, c := range []struct {
		cond           string
		marks, fails   bool
		present        bool
		whatItWouldMis string
	}{
		{"onlyRow", true, false, true, "`slog.Warn` を `fail` と読んでいます"},
		{"onlyRun", false, true, true, "`fail` だけの枝で行を書いたことにしています"},
		{"neither", false, false, true,
			"`helper` / `c.somethingElse` を2つの報告と読んでいます。" +
				"**呼び出しなら何でも数える走査は、本物のファイルでは" +
				"正しい走査と見分けがつきません**"},
		{"noReturn", false, false, false, "戻らない枝を数えています"},
	} {
		b, ok := byCond[c.cond]
		if ok != c.present {
			t.Errorf("`%s` の枝: 見つかった = %v, want %v。%s",
				c.cond, ok, c.present, c.whatItWouldMis)
			continue
		}
		if !ok {
			continue
		}
		if b.marksRow != c.marks || b.failsRun != c.fails {
			t.Errorf("`%s` の枝: marksRow=%v failsRun=%v, want %v/%v。%s",
				c.cond, b.marksRow, b.failsRun, c.marks, c.fails, c.whatItWouldMis)
		}
	}
}

// **`fail` に渡す error が本物であること。**
//
// この2つは error 値を持たない失敗でした。名前を付けて渡すようにしたので、
// 中身が空になっていないことを見ます —— 空文字の error を渡すと、
// ログは「error=」で終わり、直す人には何も伝わりません。
func TestTheTwoNamedErrorsSayWhatHappened(t *testing.T) {
	for _, err := range []error{errNotATLSConn, errNoPeerCertificate} {
		if err == nil || err.Error() == "" {
			t.Errorf("中身の無い error です: %v", err)
		}
	}
	if errors.Is(errNotATLSConn, errNoPeerCertificate) {
		t.Error("2つが同じ error です。どちらが起きたのか区別できません")
	}
	// 型アサーション側は実際の型を包んで渡します。包んだあとも
	// もとの error として辿れること。
	wrapped := fmt.Errorf("%w (%T)", errNotATLSConn, struct{}{})
	if !errors.Is(wrapped, errNotATLSConn) {
		t.Error("包んだあとに元の error へ辿れません")
	}
}

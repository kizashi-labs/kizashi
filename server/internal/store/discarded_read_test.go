package store_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// **1行読みの error を捨てないこと（`api/handlers` と `internal/scheduler`
// の外）。**
//
// 実測 (2026-08-12): `server/internal` 全体で 338 か所。内訳は
// `api/handlers` 248・`internal/scheduler` 32・**その外 58**。
// 前の2つは別の検査が見ています（それぞれ 9 と 11 まで下げ、残りには
// 理由を書きました）。ここは残りの 58 を見ます。
//
// **58 → 7。** 直し方は場所によって3つでした:
//
//	api/router.go            25  `handlers.ReadOK(c, err)` ——
//	                             gin のハンドラ（クロージャ）です
//	reports/generator.go     11  error を返せるので返します。**綴じられた
//	                             報告書の 0 は、あとから「その期間は 0 件
//	                             だった」として読まれます**
//	compliance/evaluator.go   4  同上（スコアの入力）
//	audit/logger.go           4  同上（うち1つは一覧の総件数 —— ページャの
//	                             母数なので、1ページ目が「全部」に見えます）
//	behavioral / detectionmetrics / support / store / incidents  5
//	store/alerts.go           1  変更前の状態。**読めないと履歴に「何から
//	                             変わったか」の嘘が残ります**
//	store/yara_rules.go       1  既存の確認。読めないと「新規」に倒れ、
//	                             利用者には「作成しました」と返ります
//
// 残る 7 は、error を返せない関数（統計を返すだけ）か、行が無いのが
// 普通の経路です。**1つずつ理由が要ります。**

// **1行読みの error を捨ててよい箇所。** 鍵は `パス:関数名` です。
var discardedReadReasons = map[string]string{
	// ── error を返せない関数（統計だけを返します） ───────────────────
	//
	// **直すなら署名を変えることになります。** 呼び出し側はどれも
	// ハンドラ1つずつで、そこは既に `ReadOK` で答えるようになりました
	// —— 統計が 0 でも、同じ要求の中の他の読みが失敗すれば 500 に
	// なります。**署名を変えるかは判断待ちの一覧に置いてあります。**
	"cloudruntime/monitor.go:GetRuntimeStats": "コンテナ実行時統計。" +
		"error を返さない署名です。",
	"memforensics/analyzer.go:GetStats": "メモリ解析の統計。同上。",
	"watchlist/store.go:GetStats":       "ウォッチリストの統計。同上。",

	// ── 行が無いのが普通の経路 ───────────────────────────────────────
	"sync/wazuh.go:SyncVulnerabilities": "ホスト名からの引き当て。" +
		"**Wazuh 側にしかいないホストは普通にあります** —— " +
		"空なら次のホストへ進みます。",
	"watchlist/store.go:Remove": "消す前にキャッシュ鍵を引くだけ。" +
		"読めなければキャッシュに残りますが、DELETE 自体は同じ要求の中で" +
		"error を返します。",
}

// 実測 (2026-08-12): 58 → 7。
const discardedReadSites = 7

const scanRoot = ".."

// この2つは、それぞれの package の検査が見ています。
var scanSkip = []string{"api/handlers/", "scheduler/"}

func TestNoDiscardedRowReadOutsideTheTwoCoveredPackages(t *testing.T) {
	sites := discardedScanSites(t)

	if len(sites) != discardedReadSites {
		t.Errorf("捨てている1行読みが %d か所です（留めているのは %d）。"+
			"**増えたなら、その 0 が何を決めているかを読んでください。"+
			"減らしたなら数を下げてください**", len(sites), discardedReadSites)
	}
	t.Logf("捨てている1行読み（2つの package の外）: %d か所 / 理由 %d 件",
		len(sites), len(discardedReadReasons))

	seen := map[string]bool{}
	for _, s := range sites {
		key := s.file + ":" + s.fn
		seen[key] = true
		if readSiteNeedsAReason(key, discardedReadReasons) {
			t.Errorf("%s:%d %s が、1行読みの error を捨てています。"+
				"**読めなかった 0 と、本当の 0 が同じ形になります** —— "+
				"error を返せるなら返し、返せないなら理由を書いてください",
				s.file, s.line, s.fn)
		}
	}
	for _, key := range staleScanReasonKeys(discardedReadReasons, seen) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。"+
			"**消した分は理由からも消してください**", key)
	}
}

// readSiteNeedsAReason — その箇所が違反か。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま違反は 0 件なので、`if false` に潰しても挙がる件数は変わりません。
func readSiteNeedsAReason(key string, reasons map[string]string) bool {
	return reasons[key] == ""
}

func TestTheReadSiteJudgementRecognisesTheRealThing(t *testing.T) {
	reasons := map[string]string{"a/x.go:Excused": "理由が書いてあります"}
	if !readSiteNeedsAReason("a/x.go:NoReason", reasons) {
		t.Error("**理由の無い箇所を違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if readSiteNeedsAReason("a/x.go:Excused", reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}
}

// staleScanReasonKeys — 宛先の消えた理由。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
func staleScanReasonKeys(reasons map[string]string, seen map[string]bool) []string {
	var stale []string
	for key := range reasons {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return stale
}

func TestTheStaleScanReasonListRecognisesTheRealThing(t *testing.T) {
	got := staleScanReasonKeys(map[string]string{
		"a/x.go:Live": "在ります",
		"a/x.go:Gone": "**もう在りません**",
	}, map[string]bool{"a/x.go:Live": true})
	if strings.Join(got, ",") != "a/x.go:Gone" {
		t.Errorf("古い理由 = %v, want a/x.go:Gone", got)
	}
	if len(staleScanReasonKeys(map[string]string{"a/x.go:Live": "在ります"},
		map[string]bool{"a/x.go:Live": true})) != 0 {
		t.Error("**在る宛先の理由を「古い」と言っています。**")
	}
}

type scanSite struct {
	file string
	fn   string
	line int
}

func discardedScanSites(t *testing.T) []scanSite {
	t.Helper()
	fset := token.NewFileSet()
	var out []scanSite
	err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, scanRoot+string(filepath.Separator)))
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		for _, skip := range scanSkip {
			if strings.HasPrefix(rel, skip) {
				return nil
			}
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return parseErr
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || !discardsAScan(as) || isExistenceProbe(as) {
					return true
				}
				out = append(out, scanSite{rel, fn.Name.Name, fset.Position(as.Pos()).Line})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	return out
}

// discardsAScan — `_ = <なにか>.Scan(…)` か。
func discardsAScan(as *ast.AssignStmt) bool {
	if len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	id, ok := as.Lhs[0].(*ast.Ident)
	if !ok || id.Name != "_" {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Scan"
}

// isExistenceProbe — テーブル／列の存在確認か（`probe_error_test.go` が
// 0 件に留めています）。
func isExistenceProbe(n ast.Node) bool {
	var b strings.Builder
	ast.Inspect(n, func(m ast.Node) bool {
		if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			b.WriteString(strings.ToLower(lit.Value))
		}
		return true
	})
	sql := b.String()
	return strings.Contains(sql, "information_schema") || strings.Contains(sql, "pg_tables")
}

// 走査が効くこと。**違反する見本を食わせて確かめます。**
func TestTheDiscardedScanDetectorRecognisesTheRealThing(t *testing.T) {
	parse := func(src string) *ast.AssignStmt {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go",
			"package p\nfunc f() {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		var out *ast.AssignStmt
		ast.Inspect(f, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && out == nil {
				out = as
			}
			return true
		})
		return out
	}
	if !discardsAScan(parse("_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)")) {
		t.Error("**捨てている1行読みを見つけられません。**")
	}
	if discardsAScan(parse("err := p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)")) {
		t.Error("**error を受け取っているものを違反にしています。**")
	}
	if discardsAScan(parse("_, _ = p.Exec(ctx, `UPDATE alerts SET x = 1`)")) {
		t.Error("`Scan` でない呼び出しを数えています")
	}
	if !isExistenceProbe(parse("_ = p.QueryRow(ctx, `SELECT 1 FROM pg_tables`).Scan(&n)")) {
		t.Error("**存在確認を分けられていません。** 二重に挙がります")
	}
}

// 走査そのものが届いていること。**0件を検査して緑がいちばん高くつきます。**
func TestTheDiscardedScanWalkReachesTheTree(t *testing.T) {
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if _, parseErr := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly); parseErr == nil {
			files++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	if files < scanFileFloor {
		t.Fatalf("走査が届いていません: .go が %s 個しか見えません（床 %d）",
			strconv.Itoa(files), scanFileFloor)
	}
}

// 実測 (2026-08-12): `server/internal` の .go は 900 以上。
const scanFileFloor = 400

func TestTheScanFloorAndSkipListAreNotHollowedOut(t *testing.T) {
	if scanFileFloor < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
	// **外してよいのは、それぞれ専用の検査がある2つだけです。**
	// ここを増やすと「探したが無かった」が「無い」になります。
	want := "api/handlers/,scheduler/"
	if got := strings.Join(scanSkip, ","); got != want {
		t.Errorf("走査から外している package = %q, want %q。"+
			"**増やすなら、そこを見る検査を先に用意してください**", got, want)
	}
}

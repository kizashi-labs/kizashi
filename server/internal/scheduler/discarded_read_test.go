package scheduler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// **1行読みの error を捨てないこと。**
//
// `_ = pool.QueryRow(…).Scan(&n)` は、**読めなかった 0 と本当の 0 を
// 同じ形にします。** 前の回で「存在確認」の 3 か所を直しましたが、
// あれは同じ形の一部でした。
//
// 実測 (2026-08-12): `server/internal` に 338 か所、うち
// `internal/scheduler` が 32。**21 か所は、その 0 が何かを決めていました**:
//
//	compliance_scorer           6  数えられなかった 0 が、そのまま
//	                               スコアになって履歴テーブルに残ります
//	                               （あとから「その日は低かった」と読まれます）
//	daily_briefing_scheduler    5  朝のメールに「緊急アラート 0件」——
//	daily_briefing / digest /   4  **読んだ人にとって最も安心できる行**で、
//	alert_digest_sender         4  読めなかったこととは区別がつきません
//	billing_grace_worker        1  **購読数が読めないと、購読中のテナントの
//	                               ライセンスを Free に落としていました**
//	                               （戻すのは人の手です）
//	darkweb_scheduler           1  キャッシュが読めないことと「まだ無い」が
//	                               同じ形で、照合が行われません
//
// 残る 11 か所は**重複の抑止**です。読めなかった 0 は「まだ無い」に倒れ、
// **同じアラートがもう1件作られます** —— 出過ぎる方向で、しかも続く
// INSERT が同じ DB を触るので、本当に落ちていればそちらが失敗します。
// 抑止が消えて困る種類の重複ではないので、理由を書いて外します。

// **1行読みの error を捨ててよい箇所。** 鍵は `ファイル名:関数名` です。
var discardedReadReasons = map[string]string{
	// ── 重複の抑止（読めなければ「まだ無い」に倒れます） ─────────────
	"agent_health_alerter.go:maybeCreateAlert":          "重複抑止。読めなければアラートがもう1件出るだけで、消えることはありません。",
	"compliance_alerter.go:maybeCreateAlert":            "同上。",
	"mdm_credential_expiry_checker.go:maybeCreateAlert": "同上。",
	"cert_expiry_checker.go:maybeCreateCertAlert":       "同上。",
	"billing_grace_notifier.go:notify":                  "同上（23時間の再送抑止）。",
	"license_expiry_notifier.go:createAlert":            "同上。",
	"retro_ioc_hunter.go:createRetroAlert":              "同上（イベントIDでの重複抑止）。",
	"retro_rule_hunter.go:createRetroRuleAlert":         "同上（イベント×ルールでの重複抑止）。",
	"vulnerability_scanner.go:scan":                     "同上（24時間の CVE 重複抑止）。",
	"darkweb_scheduler.go:checkPostMatches":             "同上（検知行の重複抑止）。**照合対象とキャッシュの読み出しは直しました** —— あちらは読めないと照合そのものが行われません。",
	"darkweb_scheduler.go:syncRansomwareLive":           "同上。",
}

// 実測 (2026-08-12): 直したあと 11 か所。
const minDiscardedReads = 5

// **件数も留めます。** 理由の鍵は `ファイル名:関数名` なので、**同じ関数に
// もう1つ増やしても鍵は変わりません** —— 実際、`checkPostMatches` には
// 重複抑止（理由あり）とキャッシュの読み出し（直した）が同居していて、
// 後者を元に戻しても鍵の検査は通りました。数を留めると、そこが落ちます。
const discardedReadSiteCount = 11

type readSite struct {
	file string
	fn   string
	line int
}

func (s readSite) key() string { return s.file + ":" + s.fn }

func TestEveryDiscardedRowReadHasAReason(t *testing.T) {
	sites := discardedReadSites(t, schedulerDir)

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if len(sites) < minDiscardedReads {
		t.Fatalf("走査が届いていません: 捨てている1行読みが %d か所しか"+
			"見えません（実測 11、床 %d）", len(sites), minDiscardedReads)
	}
	t.Logf("捨てている1行読み: %d か所 / 理由: %d 件",
		len(sites), len(discardedReadReasons))

	for _, s := range sites {
		if discardedReadNeedsAReason(s, discardedReadReasons) {
			t.Errorf("%s:%d %s が、1行読みの error を捨てています。"+
				"**読めなかった 0 と、本当の 0 が同じ形になります** —— "+
				"その 0 が何かを決めているなら `fail(ctx, err, …)` で"+
				"落としてください。決めていないなら理由を書いてください",
				s.file, s.line, s.fn)
		}
	}

	if len(sites) != discardedReadSiteCount {
		t.Errorf("捨てている1行読みが %d か所です（留めているのは %d）。"+
			"**増えたなら、その 0 が何を決めているかを読んでください。"+
			"減らしたなら数を下げてください** —— 理由の鍵は関数までなので、"+
			"同じ関数に増えた分は鍵の検査では見えません",
			len(sites), discardedReadSiteCount)
	}

	for _, key := range staleReadReasonKeys(discardedReadReasons, sites) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。"+
			"**消した分は理由からも消してください**", key)
	}
}

// discardedReadNeedsAReason — その箇所が違反か。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
func discardedReadNeedsAReason(s readSite, reasons map[string]string) bool {
	return reasons[s.key()] == ""
}

// staleReadReasonKeys — 宛先の消えた理由。
func staleReadReasonKeys(reasons map[string]string, sites []readSite) []string {
	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.key()] = true
	}
	var stale []string
	for key := range reasons {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return stale
}

// discardedReadSites — `_ = …Scan(…)` の箇所。
//
// **存在確認は除きます。** あちらは `internal/store` の
// `TestNoExistenceProbeThrowsAwayItsError` が、`server/internal` 全体で
// 0 件に留めています。
func discardedReadSites(t *testing.T, dir string) []readSite {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Strings(files)

	var out []readSite
	for _, path := range files {
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("%s を読めません: %v", path, readErr)
		}
		f, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			// **黙って飛ばすと、その file は走査から消えます** ——
			// 中に何が書いてあっても 0 件になります。
			t.Fatalf("%s を parse できません: %v", path, parseErr)
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
				out = append(out, readSite{
					file: base,
					fn:   fn.Name.Name,
					line: fset.Position(as.Pos()).Line,
				})
				return true
			})
		}
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

// isExistenceProbe — テーブル／列の存在確認か（別の検査が見ています）。
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

// 走査と判定が効くこと。**違反する見本を食わせて確かめます。**
func TestTheDiscardedReadScanRecognisesTheRealThing(t *testing.T) {
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
		if out == nil {
			t.Fatal("代入が見つかりません")
		}
		return out
	}

	if !discardsAScan(parse("_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)")) {
		t.Error("**捨てている1行読みを見つけられません。** " +
			"見落とすと、その箇所が走査から外れます")
	}
	if discardsAScan(parse("err := p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)")) {
		t.Error("**error を受け取っているものを違反にしています。**")
	}
	if discardsAScan(parse("_, _ = p.Exec(ctx, `UPDATE alerts SET x = 1`)")) {
		t.Error("`Scan` でない呼び出しを数えています")
	}
	if !isExistenceProbe(parse("_ = p.QueryRow(ctx, `SELECT 1 FROM information_schema.columns`).Scan(&n)")) {
		t.Error("**存在確認を分けられていません。** " +
			"あちらは別の検査が見ているので、二重に挙がります")
	}
	if isExistenceProbe(parse("_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)")) {
		t.Error("普通の集計を存在確認に数えています")
	}

	reasons := map[string]string{"a.go:Excused": "理由が書いてあります"}
	if !discardedReadNeedsAReason(readSite{file: "a.go", fn: "NoReason"}, reasons) {
		t.Error("**理由の無い箇所を違反と見ていません。** " +
			"これを潰すと、この検査は何も留めません")
	}
	if discardedReadNeedsAReason(readSite{file: "a.go", fn: "Excused"}, reasons) {
		t.Error("理由が書いてあるものを違反にしています")
	}

	got := staleReadReasonKeys(map[string]string{
		"a.go:Live": "在ります",
		"a.go:Gone": "**もう在りません**",
	}, []readSite{{file: "a.go", fn: "Live"}})
	if strings.Join(got, ",") != "a.go:Gone" {
		t.Errorf("古い理由 = %v, want a.go:Gone", got)
	}
}

// 床の判定が効くこと。
func TestTheDiscardedReadFloorNoticesAnEmptyWalk(t *testing.T) {
	if minDiscardedReads < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も「届いた」と言います**")
	}
}

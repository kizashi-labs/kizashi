package handlers

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// **数えられなかった 0 が、そのまま画面のカードに出ています。**
//
// `ReadFailure` の説明にある通りです ——「空の一覧は、読んだ人にとって
// 最も安心できる形をした嘘です」。あれは**一覧**の読み取りに入れた答えで、
// **1行読み**（`_ = pool.QueryRow(…).Scan(&n)`）は手つかずでした。
//
// 実測 (2026-08-12): `internal/api/handlers` に 248 か所。**そのうち
// 223 は、読んだ値が応答に入ります**（`c.JSON` の引数、composite literal、
// あるいは `stats["x"] = n` のように応答の入れ物へ代入されているもの）。
// さらに 227 は `COUNT`/`SUM`/`MAX`/`COALESCE` の**集計**で（応答に入る
// ものとの重なりは 208）、
// **`pgx.ErrNoRows` はあり得ません** —— つまりそこで起きる error は
// どれも本当の失敗です。それを 0 として画面に出しています:
//
//	「ブロックした DNS 問い合わせ 0件」
//	「未対応の重大アラート 0件」
//	「期限切れ間近の証明書 0件」
//
// **直し方は決まっています**（`ReadFailure(c, err, 既定の形)`）。ただし
// 「本当に無いときに返す形」はハンドラごとに違うので、一括の置換では
// なく順に直します。ここはその途中経過を留める場所です ——
// **増える方向にも、黙って減る方向にも落とします。**
//
// 直したもの:
//
//	dns_security_handler.go:GetStats        6 か所（2026-08-12）
//	compliance_handler.go                  13 か所（2026-08-12）
//	compliance_evidence_handler.go:GetStats 1 か所
//	vuln_remediation_handler.go             3 か所
//	soc_metrics_handler.go                 12 か所
//	ops_report_handler.go                  10 か所
//	patch_handler.go                        6 か所
//	email_security_handler.go               6 か所
//	nta_handler.go                          6 か所
//	ztna_handler.go                         8 か所
//	shift_handler.go                        8 か所
//	gdpr_handler.go                         7 か所
//	wireless_handler.go                     6 か所
//	soar_workflows_handler.go               5 か所
//	network_anomalies_handler.go            5 か所
//	cloud_posture_handler.go                5 か所
//	ai_triage_handler.go                    5 か所
//	training / threat_fusion / pdf_report / patch_automation /
//	pam / multi_tenant / metrics_history / forensics_automation /
//	cloud_asset                     各 4 か所（計 36）
//	残り 88 か所                    （2026-08-12、一括）
//	asset_criticality_handler.go     2 か所（error を返せるので返します）
//	agents_handler.go:RiskScore      2 か所（`rows.Scan` の形。片方は
//	                                 `slog.Warn` 止まりでした —— どちらも
//	                                 **端末のリスクスコアを静かに下げます**）

// **残った 10 か所。** どれも `readOK` を置けない場所です ——
// `*gin.Context` を持たないか、値を返す関数なので裸の `return` が
// 入りません。**1つずつ理由が要ります。**
var discardedHandlerReadReasons = map[string]string{
	"chaos_handler.go:captureMetrics": "カオス実験の前後スナップショット。" +
		"読めない 0 は前後の比較を狂わせますが、**実験を回すのは管理者で、" +
		"その場で見ています**。error を返せる形にするなら呼び出し側2か所も変わります。",
	"data_retention_handler.go:relationSizeBytes": "表示用のサイズ。0 は" +
		"「不明」として出ます。",
	"ingest_handler.go:upsertAgent": "既存エージェントの id 探し。読めなければ" +
		"空になり、**新規として INSERT します** —— 重複は UNIQUE 制約が拒みます。",
	"platform_upgrade_handler.go:RecordStartup": "同じバージョンを二重に記録" +
		"しないための確認。読めなければもう1行増えるだけです。",
	"platform_upgrade_handler.go:latestAgentVersion": "エージェントの最新" +
		"バージョン。読めなければ空で、更新の案内が出ないだけです。",
}

//
// **一括で直せない、と前回書きましたが、直せます。** `ReadFailure` は
// 「本当に無いときに返す形」を引数に取るのでハンドラごとに違いますが、
// `readOK` は**既定値のまま続ける**ので、その形が要りません ——
// 42P01／行なしのときの応答は1バイトも変わりません。残りも同じ1行で
// 置き換えられます。

// **248 → 9 まで下げました。応答に入るものは 0 です。** 残る 10 は、どれも `*gin.Context` を
// 持たない（あるいは値を返す）関数の中で、1つずつ理由を書いてあります。
//
// 実測 (2026-08-12): 248 → dns_security で 242 → コンプライアンス／脆弱性の
// 17 か所で 225 → SOC 指標・運用レポート・パッチ・メール・NTA の
// 40 か所で 185 → ZTNA・シフト・GDPR・無線・SOAR・ネットワーク異常・
// クラウド構成・AI トリアージの 49 か所で 136 → 訓練・脅威統合・PDF
// レポート・パッチ自動化・PAM・マルチテナント・指標履歴・フォレンジック
// 自動化・クラウド資産の 36 か所で 100。
const discardedHandlerReads = 6

// そのうち、読んだ値が応答に入るもの。223 → 201。
const discardedHandlerReadsShown = 0

// そのうち、集計（`pgx.ErrNoRows` があり得ないもの）。227 → 205。
const discardedHandlerReadsAggregate = 4

const handlerRoot = "."

// 留めている数との突き合わせ。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま実測は留めている数とちょうど一致するので、`if false` に潰しても
// 挙がる件数は変わりません。
const (
	pinGrew   = "増えました"
	pinShrank = "減りました"
)

func pinVerdict(got, want int) string {
	switch {
	case got > want:
		return pinGrew
	case got < want:
		return pinShrank
	}
	return ""
}

func TestThePinVerdictRecognisesTheRealThing(t *testing.T) {
	for _, c := range []struct {
		got, want int
		expect    string
	}{
		{5, 5, ""},
		{6, 5, pinGrew},
		{4, 5, pinShrank},
	} {
		if got := pinVerdict(c.got, c.want); got != c.expect {
			t.Errorf("pinVerdict(%d, %d) = %q, want %q。**両方向に落ちないなら、"+
				"増えても減っても気づけません**", c.got, c.want, got, c.expect)
		}
	}
}

func TestDiscardedRowReadsInHandlersAreNotGrowing(t *testing.T) {
	total, shown, aggregate, where := discardedHandlerReadSites(t)

	for _, c := range []struct {
		what string
		got  int
		want int
	}{
		{"捨てている1行読み", total, discardedHandlerReads},
		{"うち応答に入るもの", shown, discardedHandlerReadsShown},
		{"うち集計", aggregate, discardedHandlerReadsAggregate},
	} {
		switch pinVerdict(c.got, c.want) {
		case pinGrew:
			t.Errorf("%s が %d から %d に増えました。**数えられなかった 0 が"+
				"画面に出ます** —— `ReadFailure(c, err, 既定の形)` で"+
				"答えてください:\n  %s",
				c.what, c.want, c.got, strings.Join(where, "\n  "))
		case pinShrank:
			t.Errorf("%s が %d まで減りました。**留めている数を %d に"+
				"下げてください** —— 下げないと、次に増えても気づけません",
				c.what, c.got, c.got)
		}
	}
	seen := map[string]bool{}
	for _, w := range where {
		seen[w] = true
		if discardedHandlerReadReasons[w] == "" {
			t.Errorf("%s が、1行読みの error を捨てています。"+
				"**読めなかった 0 と、本当の 0 が同じ形になります** —— "+
				"`ReadOK(c, …)` を置くか、置けない場所なら理由を"+
				"書いてください", w)
		}
	}
	for _, key := range staleHandlerReasonKeys(discardedHandlerReadReasons, seen) {
		t.Errorf("%s の理由が残っていますが、その箇所はもうありません。"+
			"**消した分は理由からも消してください**", key)
	}
	t.Logf("捨てている1行読み: %d（応答に入る %d / 集計 %d）/ 理由 %d 件",
		total, shown, aggregate, len(discardedHandlerReadReasons))
}

// discardedHandlerReadSites — `_ = …Scan(…)` の箇所と、その値の行き先。
//
// **「応答に入る」は代入をたどって決めます。** `c.JSON` の引数と
// composite literal だけを見ていたときは 156 でしたが、`stats["x"] = n` の
// 形が多く、たどると 223 でした —— **狭く探すと「出ていない」に見えます。**
func discardedHandlerReadSites(t *testing.T) (total, shown, aggregate int, where []string) {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(handlerRoot, "*.go"))
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	sort.Strings(files)

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
			reaches := valuesThatReachTheResponse(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || !discardsAScan(as) {
					return true
				}
				sql := strings.ToLower(renderNode(fset, as))
				if strings.Contains(sql, "information_schema") || strings.Contains(sql, "pg_tables") {
					return true // 存在確認は internal/store の検査が 0 件に留めています
				}
				total++
				if isAggregate(sql) {
					aggregate++
				}
				if scanDestinationReaches(as, reaches) {
					shown++
				}
				// **理由は「応答に入る」ものだけでなく、全部に要ります。**
				// 応答に入る数が 0 になった時点で、そこだけ見ていたら
				// 理由は一度も参照されなくなります —— 「理由があるから
				// 通っている」と「見ていないから通っている」が同じ形です。
				where = append(where, base+":"+fn.Name.Name)
				return true
			})
		}
	}
	sort.Strings(where)
	return total, shown, aggregate, where
}

// staleHandlerReasonKeys — 宛先の消えた理由。
//
// **切り出してあるのは、判定を潰す変異を殺せるようにするためです。**
// いま古い理由は 0 件なので、走査を潰しても挙がる件数は変わりません。
func staleHandlerReasonKeys(reasons map[string]string, seen map[string]bool) []string {
	var stale []string
	for key := range reasons {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	return stale
}

func TestTheStaleHandlerReasonScanRecognisesTheRealThing(t *testing.T) {
	got := staleHandlerReasonKeys(map[string]string{
		"a.go:Live": "在ります",
		"a.go:Gone": "**もう在りません**",
		"z.go:Gone": "同上",
	}, map[string]bool{"a.go:Live": true})
	if strings.Join(got, ",") != "a.go:Gone,z.go:Gone" {
		t.Errorf("古い理由 = %v, want a.go:Gone,z.go:Gone。**宛先の消えた"+
			"理由を挙げられないなら、次に同じ場所が生えたときに黙って"+
			"通ります**", got)
	}
	if len(staleHandlerReasonKeys(map[string]string{"a.go:Live": "在ります"},
		map[string]bool{"a.go:Live": true})) != 0 {
		t.Error("**在る宛先の理由を「古い」と言っています。**")
	}
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

// isAggregate — 集計クエリか。**集計に `pgx.ErrNoRows` はありません** ——
// そこで起きる error は「まだ無い」ではなく、本当の失敗です。
func isAggregate(sql string) bool {
	for _, f := range []string{"count(", "sum(", "avg(", "max(", "min(", "coalesce("} {
		if strings.Contains(sql, f) {
			return true
		}
	}
	return false
}

// valuesThatReachTheResponse — その関数で、応答に入る名前。
func valuesThatReachTheResponse(body *ast.BlockStmt) map[string]bool {
	reaches := map[string]bool{}
	add := func(n ast.Node) {
		ast.Inspect(n, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok {
				reaches[id.Name] = true
			}
			return true
		})
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "JSON" && sel.Sel.Name != "IndentedJSON") {
				return true
			}
			for _, a := range v.Args {
				add(a)
			}
		case *ast.CompositeLit:
			for _, el := range v.Elts {
				e := el
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					e = kv.Value
				}
				add(e)
			}
		}
		return true
	})
	// 代入をたどります: `stats["x"] = n` の n も応答に入ります。
	for i := 0; i < 5; i++ {
		grew := false
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, l := range as.Lhs {
				if r := rootIdent(l); r == "" || !reaches[r] {
					continue
				}
				for _, rhs := range as.Rhs {
					ast.Inspect(rhs, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok && !reaches[id.Name] {
							reaches[id.Name] = true
							grew = true
						}
						return true
					})
				}
			}
			return true
		})
		if !grew {
			break
		}
	}
	return reaches
}

func scanDestinationReaches(as *ast.AssignStmt, reaches map[string]bool) bool {
	call := as.Rhs[0].(*ast.CallExpr)
	for _, a := range call.Args {
		if r := rootIdent(a); r != "" && reaches[r] {
			return true
		}
	}
	return false
}

// rootIdent — `&x` → x、`&s.F` → s、`m["k"]` → m。
func rootIdent(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.UnaryExpr:
			e = v.X
		case *ast.SelectorExpr:
			e = v.X
		case *ast.IndexExpr:
			e = v.X
		case *ast.Ident:
			return v.Name
		default:
			return ""
		}
	}
}

func renderNode(fset *token.FileSet, n ast.Node) string {
	var b strings.Builder
	_ = printer.Fprint(&b, fset, n)
	return b.String()
}

// 走査が効くこと。**違反する見本を食わせて確かめます。**
func TestTheHandlerReadScanRecognisesTheRealThing(t *testing.T) {
	fset := token.NewFileSet()
	parse := func(src string) *ast.BlockStmt {
		t.Helper()
		f, err := parser.ParseFile(fset, "x.go", "package p\nfunc f(c *gin.Context) {\n"+src+"\n}\n", 0)
		if err != nil {
			t.Fatalf("見本を解析できません: %v", err)
		}
		return f.Decls[0].(*ast.FuncDecl).Body
	}
	first := func(b *ast.BlockStmt) *ast.AssignStmt {
		var out *ast.AssignStmt
		ast.Inspect(b, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && out == nil && discardsAScan(as) {
				out = as
			}
			return true
		})
		if out == nil {
			t.Fatal("捨てている1行読みが見つかりません")
		}
		return out
	}

	direct := parse("var n int\n_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)\nc.JSON(200, gin.H{\"n\": n})")
	if !scanDestinationReaches(first(direct), valuesThatReachTheResponse(direct)) {
		t.Error("**応答に入る値を見ていません。**")
	}

	// **`stats[\"x\"] = n` の形。** ここを見ないと 156 と 223 の差になります。
	viaMap := parse("stats := gin.H{}\nvar n int\n_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)\nstats[\"x\"] = n\nc.JSON(200, stats)")
	if !scanDestinationReaches(first(viaMap), valuesThatReachTheResponse(viaMap)) {
		t.Error("**入れ物への代入をたどっていません。** " +
			"`stats[\"x\"] = n` の形が多く、たどらないと「出ていない」に" +
			"見えます（実測で 156 と 223 の差）")
	}

	hidden := parse("var n int\n_ = p.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)\nif n > 0 {\n\tc.JSON(200, gin.H{\"ok\": true})\n}")
	if scanDestinationReaches(first(hidden), valuesThatReachTheResponse(hidden)) {
		t.Error("**分岐にしか使っていない値を「応答に入る」に数えています。**")
	}

	if !isAggregate("select count(*) from alerts") {
		t.Error("集計を見分けられていません")
	}
	if isAggregate("select name from alerts where id=$1") {
		t.Error("**1行の取り出しを集計に数えています。** " +
			"あちらは `pgx.ErrNoRows` が「まだ無い」を意味します")
	}
}

// **`readOK` が、答えられることだけ答えること。**
//
// 直した箇所はどれもこの1行に乗っているので、**ここが「読めた」と答えて
// しまえば、全部そのまま元に戻ります。** 逆に「本当に無い」まで 500 に
// すると、まだマイグレーションが当たっていない画面が 500 になります。
func TestReadOKAnswersOnlyWhatItCanAnswer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, c := range []struct {
		name   string
		err    error
		want   bool
		status int // 0 = 何も書かない
	}{
		{"読めた", nil, true, 0},
		{"行が無い", pgx.ErrNoRows, true, 0},
		{"テーブルがまだ無い", &pgconn.PgError{Code: "42P01"}, true, 0},
		{"読めなかった", errors.New("dial tcp: connection refused"), false, http.StatusInternalServerError},
		{"権限が無い", &pgconn.PgError{Code: "42501"}, false, http.StatusInternalServerError},
		{"時間切れ", &pgconn.PgError{Code: "57014"}, false, http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		got := ReadOK(ctx, c.err)
		if got != c.want {
			t.Errorf("%s: readOK = %v, want %v。**true を返すと、"+
				"数えられなかった 0 がそのまま画面に出ます**", c.name, got, c.want)
		}
		if c.status == 0 && w.Code != http.StatusOK {
			t.Errorf("%s: 応答を書いています (%d)。**「まだ無い」は"+
				"既定値のまま続ける約束です**", c.name, w.Code)
		}
		if c.status != 0 && w.Code != c.status {
			t.Errorf("%s: 応答 = %d, want %d", c.name, w.Code, c.status)
		}
	}
}

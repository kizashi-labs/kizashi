package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 4 表にテナント無しで届く経路の台帳。
//
// ## 数え方を一度間違えました
//
// 最初この一覧は「公開経路」で数えていました。**足りません。**
// `tenantMiddleware` は `protected` にしか付いていないので、
// **認証は通るがテナントを載せない経路**があります:
//
//	authProtected      /api/v1/auth/mfa/* — users を読み書きします
//	emailMFAProtected  /api/v1/auth/mfa/email/{enable,disable}
//	evProtected        /api/v1/auth/email-verification/{send,status}
//
// 認証済みかどうかは関係ありません。**RLS が見ているのは
// `app.tenant_id` だけ**で、それを張るのは ctx です。だからここは
// 「公開か」ではなく **「4 表にテナント無しで届くか」** で数えます。
//
// ## 届く経路の直し方は 2 通りある
//
//	テナントを張る   認証済みで、誰の要求か分かっている経路。
//	                 `tenantMiddleware` を足します。**絞る向きです。**
//	名乗る           テナントが決まらない経路（認証前、端末から、
//	                 テナントを跨ぐ集計）。`sysAccess` を足します。
//
// **名乗りは最後の手段です。** 張れるなら張ってください —— 名乗れる
// 場所が増えるほど、名乗りは既定に戻ります。
//
// ## いまエスケープ節を落とせるか —— 落とし終わりました
//
// ここには以前「落とせない。単一テナント配備の JWT は `tenant_id` を
// 持たないから」と書いてありました。**それは誤りでした。** 数え直したら、
// JWT を発行する 4 か所すべてが既に既定テナントを入れていました。
// 誤った前提のまま、この一覧は「まだ塞げない」という結論を支えていました。
//
// 4 表とも抜け道は落ちています（migration 451 / 453 / 454 / 455）。
// **この台帳は「落とすまでの作業一覧」ではなく、落ちた状態を保つための
// 台帳になりました。** 名乗り無しで 4 表に届く経路を新しく足すと、
// それは机上の心配ではなく、その場で 0 行になります。

// systemAccessRoutes は `sysAccess` を張った場所と、その理由です。
var systemAccessRoutes = map[string]string{
	// ── 認証前。テナントが決まる前に走ります（鶏と卵）──────────
	"auth":           "users。**テナントは利用者を引いて初めて決まります**",
	"invitePublic":   "users。招待の宛先を作ります",
	"pwReset":        "users。メールアドレスから利用者を引きます",
	"emailMFAPublic": "users。ログインの途中で、まだテナントが決まっていません",
	"evPublic":       "users。確認トークンから利用者を引きます",

	// ── 端末から。名乗るのは端末で、テナントではありません ──────
	"lrAgent":                       "agents",
	"ingestGroup":                   "agents / alerts。外部からの取り込み。トークン認証のみ",
	"/agents/:id/heartbeat":         "agents",
	"/agents/:id/software/report":   "agents",
	"/agents/:id/encryption/report": "agents",
	"/agents/:id/hardening/report":  "agents",
	"/agents/:id/yara-rules":        "agents",
	"/agents/:id/scan-results":      "agents / alerts",
	"/agents/:id/quarantine-result": "agents",
	"/ingest/:source_name":          "agents / alerts",
	"/enrollment/request":           "agents。登録。**この時点では行がありません**",

	// ── テナントを跨ぐ集計 ──────────────────────────────────
	"/api/v1/health/detailed": "agents / alerts / incidents の COUNT。" +
		"**公開経路ですが 4 表を数えます。** 同じハンドラ群でも " +
		"uptime / dependencies / incidents は触りません",
}

// tenantScopedGroups は `tenantMiddleware` を張ったグループです。
//
// **`sysAccess` ではなくこちらで直したもの**を、理由つきで残します。
// 認証済みの要求は誰のものか分かっているので、全テナントを配る理由が
// ありません。
var tenantScopedGroups = map[string]string{
	"protected": "認証済み API の本体。元からここだけに付いていました",
	"authProtected": "MFA の設定・解除とメール確認。**認証済みなのに" +
		"テナントを載せていませんでした** —— users をテナント無しで" +
		"読み書きしていました",
}

// dbFreeRoutes は 4 表に届かないことを確かめた経路です。
//
// **「調べていない」と「触らない」を同じ扱いにしないため**に名前で
// 残します。空欄にすると、次に読む人がもう一度全部読む羽目になります。
var dbFreeRoutes = map[string]string{
	"track":                                 "phishing_recipients のみ",
	"taxii":                                 "ioc_entries のみ",
	"installer":                             "スクリプトを組み立てて返すだけ",
	"pprofGroup":                            "ランタイムのプロファイル。DB に触りません",
	"agentsCertPublic":                      "CA 証明書の PEM を返すだけ",
	"v1":                                    "SSE。購読するだけで DB を読みません",
	"/ws/alerts":                            "notification.Hub。**DB に触りません**",
	"/ws/agents/:id/events":                 "同上",
	"/ws/cloud":                             "同上",
	"/health":                               "固定の応答",
	"/healthz":                              "固定の応答",
	"/readyz":                               "固定の応答",
	"/api/v1/status":                        "health_handler。4 表を触りません",
	"/api/v1/health/uptime":                 "4 表を触りません",
	"/api/v1/health/dependencies":           "4 表を触りません",
	"/api/v1/health/incidents":              "4 表を触りません（名前に反して incidents を読みません）",
	"/metrics":                              "promhttp",
	"/api/v1/openapi.yaml":                  "静的",
	"/api/v1/docs":                          "静的",
	"/api/v1/docs/openapi.yaml":             "静的",
	"/api/v1/agents/download":               "バイナリ",
	"/api/v1/agents/download/checksum":      "バイナリ",
	"/api/v1/agent-config/schema":           "組み込みのスキーマを返すだけ",
	"/api/v1/process-rules/agent/:agent_id": "process_block_rules のみ",
}

// routeHelpers は `*gin.RouterGroup` を受け取って経路を足す関数と、
// **呼び出し時に渡されるグループ**です。
//
// 走査は関数ごとにスコープを切るので、引数で受けたグループの素性が
// 分かりません。**ここに書かないと、その関数の経路は全部「テナント無し」
// に見えます** —— 最初それで 20 経路を誤検出しました。
var routeHelpers = map[string]string{
	"registerPlatformUpgradeRoutes": "protected",
	"darkwebRoutes":                 "protected",
}

// ── 走査 ──────────────────────────────────────────────────────────

type routeFact struct {
	fn    string
	recv  string
	path  string
	marks map[string]bool
}

// scanRoutes は router.go の経路登録を、**関数ごとに**読み解きます。
//
// 同じ名前のグループ変数が別の関数で使われています（`dw` が 2 か所、
// `v1` / `taxii` も）。ファイル全体を 1 つのスコープとして読むと、
// あとの代入が前の代入を上書きして誤判定します。
func scanRoutes(t *testing.T) []routeFact {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}

	var out []routeFact
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		parent := map[string]string{}
		marks := map[string]map[string]bool{}
		if root, viaHelper := routeHelpers[fn.Name.Name]; viaHelper {
			// 引数で受けたグループを、呼び出し側の名前に読み替えます。
			for _, p := range fn.Type.Params.List {
				for _, n := range p.Names {
					parent[n.Name] = root
				}
			}
			marks[root] = map[string]bool{"tenant": true}
		}

		mark := func(v, src string) {
			m := marks[v]
			if m == nil {
				m = map[string]bool{}
				marks[v] = m
			}
			if strings.Contains(src, "authMiddleware") || strings.Contains(src, "jwtMw") {
				m["auth"] = true
			}
			if strings.Contains(src, "tenantMiddleware") {
				m["tenant"] = true
			}
			if strings.Contains(src, "sysAccess") {
				m["sys"] = true
			}
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				// x := <recv>.Group(...)
				if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
					return true
				}
				name, ok := node.Lhs[0].(*ast.Ident)
				if !ok {
					return true
				}
				call, ok := node.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Group" {
					return true
				}
				parent[name.Name] = exprText(sel.X)
				mark(name.Name, argsText(call.Args))
			case *ast.ExprStmt:
				call, ok := node.X.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv := exprText(sel.X)
				switch sel.Sel.Name {
				case "Use":
					mark(recv, argsText(call.Args))
				case "GET", "POST", "PUT", "PATCH", "DELETE", "Any":
					if len(call.Args) == 0 {
						return true
					}
					lit, ok := call.Args[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					path, _ := strconv.Unquote(lit.Value)
					seen := map[string]bool{}
					// 経路の引数として付いた middleware（`jwtMw` や
					// `sysAccess`）。**group の `.Use` だけを見ていた頃、
					// ここを取りこぼして /ws/* を「認証なし」と読みました。**
					for k, v := range parseMarks(argsText(call.Args[1:])) {
						seen[k] = v
					}
					for v, depth := recv, 0; v != "" && depth < 16; depth++ {
						for k := range marks[v] {
							seen[k] = true
						}
						v = parent[v]
					}
					out = append(out, routeFact{fn: fn.Name.Name, recv: recv, path: path, marks: seen})
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("router.go から経路を1つも読めませんでした。**この検査は何も見ていません**")
	}
	return out
}

func parseMarks(src string) map[string]bool {
	m := map[string]bool{}
	if strings.Contains(src, "authMiddleware") || strings.Contains(src, "jwtMw") {
		m["auth"] = true
	}
	if strings.Contains(src, "tenantMiddleware") {
		m["tenant"] = true
	}
	if strings.Contains(src, "sysAccess") {
		m["sys"] = true
	}
	return m
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	}
	return ""
}

func argsText(args []ast.Expr) string {
	var b strings.Builder
	for _, a := range args {
		ast.Inspect(a, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				b.WriteString(id.Name)
				b.WriteByte(' ')
			}
			return true
		})
	}
	return b.String()
}

// ledgerKey は台帳の引き方。**グループ名でも経路でも引けます** ——
// group ごと張ったものは group 名で、1 本ずつ張ったものは経路で。
func ledgerKey(f routeFact) (string, string) {
	return f.recv, f.path
}

func inAnyLedger(f routeFact) (string, bool) {
	recv, path := ledgerKey(f)
	for _, m := range []map[string]string{systemAccessRoutes, dbFreeRoutes} {
		if _, ok := m[recv]; ok {
			return recv, true
		}
		if _, ok := m[path]; ok {
			return path, true
		}
	}
	return "", false
}

// **テナントも名乗りも無い経路は、必ず台帳にあること。**
//
// 新しく足した経路が 4 表に触ると、エスケープ節を落とした時点で 0 行に
// なります。**そのとき静かに壊れます** —— 落ちるのは検知でも隔離でも
// なく「結果が空」なので、動いているように見えます。
func TestEveryTenantlessRouteIsAccountedFor(t *testing.T) {
	var unknown []string
	for _, f := range scanRoutes(t) {
		if f.marks["tenant"] || f.marks["sys"] {
			continue
		}
		if _, ok := inAnyLedger(f); ok {
			continue
		}
		unknown = append(unknown, fmt.Sprintf("%s / %s %q", f.fn, f.recv, f.path))
	}
	sort.Strings(unknown)
	for _, u := range unknown {
		t.Errorf("%s は 4 表にテナント無しで届きます。**どちらかにしてください**:\n"+
			"    触るなら  —— 認証済みなら tenantMiddleware、そうでなければ sysAccess\n"+
			"    触らないなら —— 確かめて dbFreeRoutes に理由つきで書く", u)
	}
}

// 台帳に書いたものが、本当に張ってあること。
func TestEverySystemAccessEntryIsWired(t *testing.T) {
	wired := map[string]bool{}
	for _, f := range scanRoutes(t) {
		if !f.marks["sys"] {
			continue
		}
		recv, path := ledgerKey(f)
		wired[recv] = true
		wired[path] = true
	}
	var missing []string
	for name := range systemAccessRoutes {
		if !wired[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s を台帳に書いていますが、sysAccess が張ってありません。"+
			"**台帳にあることと、張ってあることは別です**", name)
	}
}

// 逆向き。**張ったのに書いていないものが無いこと。**
func TestEverySystemAccessIsInTheLedger(t *testing.T) {
	for _, f := range scanRoutes(t) {
		if !f.marks["sys"] {
			continue
		}
		recv, path := ledgerKey(f)
		if _, ok := systemAccessRoutes[recv]; ok {
			continue
		}
		if _, ok := systemAccessRoutes[path]; ok {
			continue
		}
		t.Errorf("%s / %q に sysAccess を張っていますが、台帳にありません。"+
			"**なぜ全テナントが要るのかを書いてください。** "+
			"書けないなら、それは張りすぎです", f.recv, f.path)
	}
}

// `tenantMiddleware` が、書いたグループに本当に付いていること。
//
// **`authProtected` はここが空でした。** 認証は通るのにテナントを
// 載せないまま users を読み書きしていて、RLS のエスケープ節が
// 通していました。
func TestTenantScopedGroupsStillCarryTheMiddleware(t *testing.T) {
	got := map[string]bool{}
	for _, f := range scanRoutes(t) {
		if f.marks["tenant"] {
			got[f.recv] = true
		}
	}
	// group から派生した経路は派生名で出るので、宣言した group 名が
	// 1 つも出ないときだけ落とします。
	for name := range tenantScopedGroups {
		found := got[name]
		if !found {
			for _, f := range scanRoutes(t) {
				if f.recv == name && f.marks["tenant"] {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("%s に tenantMiddleware が付いていません。"+
				"**認証済みでもテナントを載せなければ、RLS は絞りません**", name)
		}
	}
}

// 同じ名前が 2 つの台帳に無いこと。
func TestNoEntryIsInTwoLedgers(t *testing.T) {
	for name := range systemAccessRoutes {
		if _, ok := dbFreeRoutes[name]; ok {
			t.Errorf("%s が systemAccessRoutes と dbFreeRoutes の両方にあります。"+
				"どちらかにしてください", name)
		}
	}
}

// **`authMiddleware` は台帳の外にあります。** ここだけ別に留めます。
//
// 上の台帳は「経路に何を張ったか」を数えます。`authMiddleware` は経路では
// なく、**すべての認証済み経路の内側**で users に 2 回届きます:
//
//	FindByKey           `LEFT JOIN users` で API キーの持ち主のテナントを引く
//	UserCache.IsActive  `SELECT is_active FROM users WHERE id = $1`
//
// どちらもテナントが決まる前です（誰なのかを users に聞くまで、テナントは
// 決まりません）。migration 455 で users の抜け道が落ちたので、**この 2 本が
// 名乗らなくなった瞬間に、認証が全部壊れます** —— `IsActive` は行が無いのを
// 「削除された利用者」と読むので全員が締め出され、`FindByKey` のほうは
// 鍵が引けたまま**テナントだけが静かに落ちます**。
//
// 壊れ方は `internal/store/users_failclosed_auth_test.go` が実 DB で見せて
// います。ここが留めるのは配線のほうです。
//
// **`authCtx` が要求の ctx に戻っていないことも見ます。** 戻すと、この先の
// ハンドラが全部全テナントで走ります —— 名乗りが 2 本の道具ではなく、
// 既定になります。
func TestAuthMiddlewareClaimsOnlyForTheTwoUserLookups(t *testing.T) {
	src := funcBody(t, "authMiddleware")

	for _, want := range []string{
		"store.WithSystemAccess(c.Request.Context())",
		"FindByKey(authCtx,",
		"IsActive(authCtx,",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("authMiddleware に %q がありません。\n"+
				"    users は migration 455 で抜け道を持ちません。テナントが決まる\n"+
				"    前の users 参照は名乗りが要ります。**外すと認証が全部落ちます。**", want)
		}
	}

	if strings.Contains(src, "c.Request = c.Request.WithContext") {
		t.Error("authMiddleware が名乗りを要求の ctx に書き戻しています。\n" +
			"    **この先のハンドラが全部全テナントで走ります。**\n" +
			"    名乗るのは users を引く 2 本だけにしてください。")
	}
}

// funcBody は router.go の関数 1 本を、そのままの文字列で返します。
func funcBody(t *testing.T, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "router.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}
	raw, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("router.go を開けません: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != name {
			continue
		}
		return string(raw[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
	}
	t.Fatalf("router.go に %s がありません。**この検査は何も見ていません**", name)
	return ""
}

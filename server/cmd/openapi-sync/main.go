// openapi-sync は docs/openapi.yaml を router.go の実装に追従させる。
//
// 背景:
//
//	openapi.yaml は手書きで、実装が増えても追随しなかった。導入時点の実測で
//	ルータには 1,460 の (メソッド, パス) が登録されているのに、記載は 171 操作。
//	しかもそのうち 52 操作は**ルータに存在しない**（パス違い・メソッド違い・
//	そもそも無い）。網羅率 8% で、書いてある分の 3 割が嘘という状態だった。
//
// このツールがやること:
//
//  1. router.go から (メソッド, 絶対パス, 認証要否, パスパラメータ) を抽出する
//  2. openapi.yaml に無い操作を「自動生成スタブ」として追記する。スタブは
//     `x-generated: true` を持ち、パス・メソッド・認証・パスパラメータだけを
//     保証する。要求/応答の形状は書かない — 書けないものを書くと、この
//     ファイルが以前そうだったように「静かに嘘になる」
//  3. 手書きの記述には一切触れない。手で書き足したらそちらが勝つ
//     （同じ操作の手書きブロックがあれば、スタブは生成しない／削除する）
//  4. ルータから消えた操作のスタブを削除する
//
// -check を付けると書き換えず、差分があれば exit 1。CI はこれを使う。
//
// 検証しないもの: リクエスト/レスポンスの形状、パラメータの意味、認証以外の
// ミドルウェア。これらは実装から機械的に導けない。導けないものを自動生成で
// 埋めない、というのがこのツールの設計方針。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	check := flag.Bool("check", false, "書き換えずに差分の有無だけを判定する（差分があれば exit 1）")
	flag.Parse()

	// リポジトリルートは cwd から上へ辿って決める。以前は -root フラグでも
	// 渡せたが、あれは findRepoRoot が server/ で止まるバグの回避策だった。
	// バグを直した今は不要で、外から任意のパスを差し込める口を残す理由も無い。
	repoRoot, err := findRepoRoot()
	if err != nil {
		fail("リポジトリルートを特定できませんでした: %v", err)
	}

	routerPath := filepath.Join(repoRoot, "server", "internal", "api", "router.go")
	specPath := filepath.Join(repoRoot, "docs", "openapi.yaml")
	// API が配信する実体（server/docs/embed.go が go:embed で取り込む）。
	// go:embed はパッケージディレクトリの外を参照できないので、正本の
	// バイト単位コピーをここに置く。以前は 2 つが別々に手書きされ、
	// パス表記も内容も食い違っていた。
	embedPath := filepath.Join(repoRoot, "server", "docs", "openapi.yaml")

	// #nosec G304 -- 3 つのパスはいずれも、cwd から辿って見つけた repoRoot に
	// 固定の相対パスを繋いだもの。外部入力は一切入らない。
	routerSrc, err := os.ReadFile(routerPath)
	if err != nil {
		fail("router.go を読めませんでした: %v", err)
	}
	specSrc, err := os.ReadFile(specPath) // #nosec G304 -- 同上
	if err != nil {
		fail("openapi.yaml を読めませんでした: %v", err)
	}

	routes := CollectRoutes(string(routerSrc))
	if len(routes) < 500 {
		fail("ルート抽出に失敗した可能性があります (抽出数=%d)。router.go の書式を確認してください", len(routes))
	}

	spec, err := ParseSpec(string(specSrc))
	if err != nil {
		fail("openapi.yaml の解析に失敗しました: %v", err)
	}

	// 手書きの記述がルータに無い＝乖離。自動修正はできないので落とす。
	if drift := spec.HandwrittenDrift(routes); len(drift) > 0 {
		sort.Strings(drift)
		fmt.Fprintf(os.Stderr,
			"openapi.yaml の手書き記述 %d 件が router.go に存在しません。\n"+
				"実装に合わせて修正するか、削除してください:\n  %s\n",
			len(drift), strings.Join(drift, "\n  "))
		os.Exit(1)
	}

	out := spec.Sync(routes)

	if *check {
		if out != string(specSrc) {
			fmt.Fprintln(os.Stderr,
				"docs/openapi.yaml が実装と同期していません。"+
					"`go run ./cmd/openapi-sync` を実行して差分をコミットしてください。")
			os.Exit(1)
		}
		embedded, err := os.ReadFile(embedPath) // #nosec G304 -- 同上
		if err != nil || string(embedded) != out {
			fmt.Fprintln(os.Stderr,
				"server/docs/openapi.yaml が docs/openapi.yaml と一致しません。"+
					"`go run ./cmd/openapi-sync` を実行して差分をコミットしてください。")
			os.Exit(1)
		}
		cov, total := spec.Coverage(routes)
		fmt.Printf("openapi.yaml は同期済みです（手書き %d / 全 %d 操作 = %.1f%%）\n",
			cov, total, 100*float64(cov)/float64(total))
		return
	}

	// #nosec G703 -- 書き込み先は repoRoot + 固定の相対パスで、repoRoot は
	// cwd から上へ辿って見つけたもの。フラグにも環境変数にも由来しない。
	//
	// 0o600 は**新規作成時のみ**効く。両ファイルとも既にリポジトリに存在するので
	// 実際のモードは変わらない（git も実行ビットしか追跡しない）。
	if err := os.WriteFile(specPath, []byte(out), 0o600); err != nil {
		fail("docs/openapi.yaml を書けませんでした: %v", err)
	}
	if err := os.WriteFile(embedPath, []byte(out), 0o600); err != nil { // #nosec G703 -- 同上
		fail("server/docs/openapi.yaml を書けませんでした: %v", err)
	}
	cov, total := spec.Coverage(routes)
	fmt.Printf("docs/openapi.yaml を更新しました（手書き %d / 全 %d 操作 = %.1f%%）\n",
		cov, total, 100*float64(cov)/float64(total))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// findRepoRoot は cwd から上へ辿ってリポジトリルートを探す。
func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return repoRootFrom(wd)
}

// repoRootFrom は start から上へ辿ってリポジトリルートを返す。
//
// 目印は `docs/openapi.yaml` と `server/internal/api/router.go` の**両方**。
// 片方（docs/openapi.yaml）だけを見ると `server/` で止まってしまう
// — 配信用のコピーが server/docs/openapi.yaml にあるため。CI は
// `working-directory: server` で走らせるので、これをやると
// server/server/internal/api/router.go を開こうとして落ちる（実際に落ちた）。
func repoRootFrom(start string) (string, error) {
	for dir := start; ; {
		_, e1 := os.Stat(filepath.Join(dir, "docs", "openapi.yaml"))
		_, e2 := os.Stat(filepath.Join(dir, "server", "internal", "api", "router.go"))
		if e1 == nil && e2 == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("リポジトリルートが見つかりません (探索開始: %s)", start)
		}
		dir = parent
	}
}

// ─── router.go の走査 ────────────────────────────────────────────────────────

// Route は router.go に登録された 1 操作。
type Route struct {
	Method string // "GET" など
	Path   string // "/api/v1/agents/{id}"（OpenAPI 形式）
	Public bool   // 認証ミドルウェアを通らない
	Params []string
}

var (
	groupRe = regexp.MustCompile(`(\w+)\s*:?=\s*([\w.]+)\.Group\("([^"]*)"([^)]*)\)`)
	routeRe = regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\("([^"]*)"`)
	useRe   = regexp.MustCompile(`(\w+)\.Use\((.*)\)`)
	paramRe = regexp.MustCompile(`[:*](\w+)`)
)

type groupInfo struct {
	prefix  string
	authReq bool
}

// CollectRoutes は router.go を 1 行ずつ走査して登録済みの操作を返す。
//
// グループ変数はブレース深さでスコープを分ける。同じ変数名が別ブロックで別
// プレフィックスに再束縛されるため（実例: `ak` が `/api-keys` と `/apikeys` の
// 両方で使われている）、平坦に扱うと誤ったプレフィックスで解決してしまう。
//
// 認証要否は `Group(...)` の引数と、後続の `x.Use(authMiddleware(...))` の
// 両方から拾う。router.go は `protected := api.Group("/")` の直後に
// `protected.Use(authMiddleware(...))` と書く形なので、後者を見ないと
// 保護配下のルートが全部 public に見えてしまう。
func CollectRoutes(src string) []Route {
	scopes := []map[string]*groupInfo{{}}
	lookup := func(v string) (*groupInfo, bool) {
		if isRootRouter(v) {
			return &groupInfo{prefix: "", authReq: false}, true
		}
		for i := len(scopes) - 1; i >= 0; i-- {
			if g, ok := scopes[i][v]; ok {
				return g, true
			}
		}
		return nil, false
	}

	// ルート登録がヘルパ関数へ切り出されている場合、その仮引数は
	// ルート変数からの連鎖では解決できない。router.go には
	//   s.registerPlatformUpgradeRoutes(protected)
	//   func (s *Server) registerPlatformUpgradeRoutes(protected *gin.RouterGroup)
	// という形があり、admin/remediation・admin/platform・threat-intel/darkweb の
	// 23 登録がまるごと抽出から漏れていた（lookup 失敗は continue で捨てられる
	// ので件数にも出ない）。呼び出し側の実引数を仮引数に束縛して解決する。
	// ヘルパ関数の仮引数を束縛するとき、実引数（例: protected）は別の関数で
	// 定義されていてスコープからは消えている。ファイル全体の定義表を別に持つ。
	allGroups := map[string]*groupInfo{}
	callArg := map[string]string{}
	for _, m := range regexp.MustCompile(`s\.(\w+)\(\s*(\w+)\s*\)`).FindAllStringSubmatch(src, -1) {
		callArg[m[1]] = m[2]
	}
	funcParam := regexp.MustCompile(`^func \(s \*Server\) (\w+)\((\w+) \*gin\.RouterGroup`)

	seen := map[string]bool{}
	var out []Route
	var unresolved []string

	for _, raw := range strings.Split(src, "\n") {
		// コメントアウトされた登録を拾わない。router.go には
		// `// protected.GET("/dashboard/stats", ...)` のように寝かせた行があり、
		// これを数えると存在しないパスのスタブを生成してしまう。
		line := stripLineComment(raw)
		switch {
		case funcParam.MatchString(line):
			m := funcParam.FindStringSubmatch(line)
			if arg, ok := callArg[m[1]]; ok {
				g, ok2 := lookup(arg)
				if !ok2 {
					g, ok2 = allGroups[arg]
				}
				if ok2 {
					scopes[len(scopes)-1][m[2]] = &groupInfo{prefix: g.prefix, authReq: g.authReq}
				}
			}
		case groupRe.MatchString(line):
			m := groupRe.FindStringSubmatch(line)
			parent := m[2]
			if i := strings.LastIndex(parent, "."); i >= 0 {
				parent = parent[i+1:] // s.router → router
			}
			if pg, ok := lookup(parent); ok {
				gi := &groupInfo{
					prefix:  joinPath(pg.prefix, m[3]),
					authReq: pg.authReq || strings.Contains(m[4], "authMiddleware"),
				}
				scopes[len(scopes)-1][m[1]] = gi
				allGroups[m[1]] = gi
			}
		case useRe.MatchString(line):
			m := useRe.FindStringSubmatch(line)
			if g, ok := lookup(m[1]); ok && strings.Contains(m[2], "authMiddleware") {
				g.authReq = true
			}
		case routeRe.MatchString(line):
			m := routeRe.FindStringSubmatch(line)
			g, ok := lookup(m[1])
			if !ok {
				// 解決できない登録は「実装にあるのに仕様書に載らない」乖離を生む。
				// 黙って捨てると検査自体が嘘をつくので数える。
				unresolved = append(unresolved, m[1]+" "+m[2]+" "+m[3])
				continue
			}
			p := toOpenAPIPath(joinPath(g.prefix, m[3]))
			key := m[2] + " " + p
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Route{
				Method: m[2],
				Path:   p,
				Public: !g.authReq,
				Params: pathParams(p),
			})
		}

		// 波括弧はコードのものだけ数える。文字列やコメントの中の { } まで数えると
		// スコープがずれ、以降のグループ定義が失われる。router.go には
		// `func(c *gin.Context) { c.Set(...)` を含む文字列が 18 箇所あり、
		// admin/remediation・admin/platform・threat-intel/darkweb の 3 グループ
		// 23 登録が、この理由で丸ごと抽出から漏れていた。
		for _, c := range stripStringsAndComments(raw) {
			if c == '{' {
				scopes = append(scopes, map[string]*groupInfo{})
			} else if c == '}' && len(scopes) > 1 {
				scopes = scopes[:len(scopes)-1]
			}
		}
	}

	if len(unresolved) > 0 {
		fmt.Fprintf(os.Stderr, "!! グループを解決できず抽出から漏れた登録が %d 件あります。\n", len(unresolved))
		for _, u := range unresolved {
			fmt.Fprintf(os.Stderr, "!!   %s\n", u)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return methodOrder(out[i].Method) < methodOrder(out[j].Method)
	})
	return out
}

func isRootRouter(v string) bool { return v == "router" || v == "r" || v == "engine" }

// stripLineComment は行コメントを落とす。文字列リテラルの中の "//"（URL など）は
// 残すため、引用符の数が偶数のところに現れた "//" だけを切る。
func stripLineComment(line string) string {
	quotes := 0
	for i := 0; i+1 < len(line); i++ {
		switch line[i] {
		case '"', '`':
			quotes++
		case '/':
			if line[i+1] == '/' && quotes%2 == 0 {
				return line[:i]
			}
		}
	}
	return line
}

func joinPath(base, seg string) string {
	return strings.TrimSuffix(strings.TrimSuffix(base, "/")+"/"+strings.Trim(seg, "/"), "/")
}

// toOpenAPIPath は gin の :id / *path を OpenAPI の {id} に直す。
func toOpenAPIPath(p string) string {
	return paramRe.ReplaceAllString(p, "{$1}")
}

func pathParams(p string) []string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, strings.Trim(seg, "{}"))
		}
	}
	return out
}

var methodRank = map[string]int{"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4, "HEAD": 5, "OPTIONS": 6}

func methodOrder(m string) int {
	if r, ok := methodRank[m]; ok {
		return r
	}
	return 99
}

// stripStringsAndComments は Go ソースの 1 行から、文字列・ルーンリテラル・
// 行コメントの中身を空白に置き換える。波括弧の対応を数える対象を、コード上の
// { } だけに限るため。
func stripStringsAndComments(line string) string {
	out := make([]rune, 0, len(line))
	var quote rune
	esc := false
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if quote != 0 {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == quote:
				quote = 0
			}
			out = append(out, ' ')
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote = c
			out = append(out, ' ')
			continue
		}
		if c == '/' && i+1 < len(rs) && rs[i+1] == '/' {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

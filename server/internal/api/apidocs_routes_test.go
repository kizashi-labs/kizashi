package api

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// api-docs 画面(frontend/app/admin/api-docs/page.tsx)に載っているエンドポイントが
// 実際に router.go へ登録されているかを検証する。
//
// 背景: この手書きドキュメントは実装と乖離しても誰も気づかない。実際に
//   - GET /api/v1/agents/stats … 存在しないエンドポイント
//   - POST /api/v1/reports/generate … 実際は POST /api/v1/reports
//   - GET /api/v1/rules/:id/test … 実際は POST
//   - GET /api/v1/auth/me … 実際は /api/v1/users/me
// といった記載が長期間残っていた（P5-10 / P5-11 と同じ「静かに嘘になる」クラス）。
// パスとメソッドの一致だけは機械的に判定できるので、ここで固定する。
//
// 検証しないもの: リクエスト/レスポンスの形状、パラメータ名。
// これらは実装から機械的に導けないため、引き続き人手の突合が必要。

// collectRoutes は router.go を1行ずつ走査し、登録されている
// (メソッド, 絶対パス) の集合を返す。
//
// グループ変数はブレース深さでスコープを分けて解決する。同じ変数名が別ブロックで
// 別プレフィックスに再束縛されるため（実例: `ak` が `/api-keys` と `/apikeys` の
// 両方で使われている）、変数名を平坦に扱うと 22 経路を誤ったプレフィックスで
// 登録済みと見なしてしまい、「存在しないパス」を存在すると誤判定する。
//
// `y.Group("", middleware())` のようにミドルウェアを伴う形も拾う。ここを
// 取りこぼすと配下のルートが丸ごと「未登録」に見えてしまう。
func collectRoutes(src string) map[string]map[string]bool {
	groupRe := regexp.MustCompile(`(\w+)\s*:?=\s*([\w.]+)\.Group\("([^"]*)"[^)]*\)`)
	routeRe := regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\("([^"]*)"`)

	scopes := []map[string]string{{}}
	lookup := func(v string) (string, bool) {
		if isRootRouter(v) {
			return "", true
		}
		for i := len(scopes) - 1; i >= 0; i-- {
			if p, ok := scopes[i][v]; ok {
				return p, true
			}
		}
		return "", false
	}

	registered := map[string]map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		if m := groupRe.FindStringSubmatch(line); m != nil {
			parent := m[2]
			if i := strings.LastIndex(parent, "."); i >= 0 {
				parent = parent[i+1:] // s.router → router
			}
			if base, ok := lookup(parent); ok {
				scopes[len(scopes)-1][m[1]] = joinPath(base, m[3])
			}
		} else if m := routeRe.FindStringSubmatch(line); m != nil {
			if base, ok := lookup(m[1]); ok {
				full := normalizePath(joinPath(base, m[3]))
				if registered[full] == nil {
					registered[full] = map[string]bool{}
				}
				registered[full][m[2]] = true
			}
		}
		// 行内のブレースを反映してからスコープを進める
		for _, c := range line {
			if c == '{' {
				scopes = append(scopes, map[string]string{})
			} else if c == '}' && len(scopes) > 1 {
				scopes = scopes[:len(scopes)-1]
			}
		}
	}
	return registered
}

func isRootRouter(v string) bool {
	return v == "router" || v == "r" || v == "engine"
}

func joinPath(base, seg string) string {
	return strings.TrimSuffix(strings.TrimSuffix(base, "/")+"/"+strings.Trim(seg, "/"), "/")
}

// normalizePath は :id / {id} を同一視し、パラメータ名の差を吸収する。
var pathParamRe = regexp.MustCompile(`[:{](\w+)}?`)

func normalizePath(p string) string {
	return strings.TrimSuffix(pathParamRe.ReplaceAllString(p, ":P"), "/")
}

func TestAPIDocsEndpointsAreRegistered(t *testing.T) {
	root := repoRootFromAPIPkg(t)

	// 継ぎ目（routes_commercial.go / routes_sso.go）を展開してから走査する。
	// router.go 単体では有償ルートが映らず、「api-docs にあるが実装に無い」という
	// 逆向きの誤報になる。
	routerSrc := routerSourceWithRegistrars(t, filepath.Join(root, "server", "internal", "api"))
	docsPath := filepath.Join(root, "frontend", "app", "admin", "api-docs", "page.tsx")
	docsSrc := mustRead(t, docsPath)

	registered := collectRoutes(routerSrc)
	if len(registered) < 500 {
		t.Fatalf("ルート抽出に失敗した可能性があります (抽出数=%d)。router.go の書式が変わっていないか確認してください", len(registered))
	}

	// api-docs のエンドポイント定義。レスポンス例(JSON.stringify 内)にも
	// method/path というキーが現れるため、インデント 8 に固定して取り違えを防ぐ。
	// 改行は CRLF の場合もある（Windows チェックアウト）ので \r? を挟む。
	docRe := regexp.MustCompile(`(?m)^ {8}method: '(\w+)',\r?\n {8}path: '([^']+)'`)
	documented := docRe.FindAllStringSubmatch(docsSrc, -1)
	if len(documented) < 40 {
		t.Fatalf("api-docs の抽出に失敗した可能性があります (抽出数=%d)。page.tsx の書式が変わっていないか確認してください", len(documented))
	}

	var problems []string
	for _, m := range documented {
		method, p := m[1], m[2]
		methods, ok := registered[normalizePath(p)]
		switch {
		case !ok:
			problems = append(problems, method+" "+p+" — ルータに存在しません")
		case !methods[method]:
			problems = append(problems, method+" "+p+" — メソッドが違います (登録: "+strings.Join(sortedKeys(methods), ", ")+")")
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("api-docs の記載が実装と一致しません (%d 件)。\n"+
			"%s を実装に合わせて修正してください:\n  %s",
			len(problems), docsPath, strings.Join(problems, "\n  "))
	}
}

// ─── レスポンス形状（トップレベルのキー名）の突合 ──────────────────────────
//
// 実装から機械的に判定できるのは「そのハンドラ内で成功ステータス(200/201/202)を
// 返す c.JSON がちょうど1つで、かつ第2引数が gin.H{...} リテラル」の場合だけ。
// 構造体を返す・成功レスポンスが複数ある・ファイルを返す、といったケースは
// 静的には決められないので **明示的にスキップし、その件数を必ず出力する**。
// 「検証できなかった分」が見えないと、緑が実態より良く見えてしまう。
//
// 実際に導入時点で 31 件が判定可能で、うち 20 件が実装と食い違っていた。

// handlerFieldTypes は router.go の `type Handlers struct` から
// フィールド名 → ハンドラ型名 の対応を取る。
func handlerFieldTypes(routerSrc string) map[string]string {
	block := regexp.MustCompile(`(?s)type Handlers struct \{(.*?)\n\}`).FindStringSubmatch(routerSrc)
	if block == nil {
		return nil
	}
	fieldRe := regexp.MustCompile(`^\s*(\w+)\s+\*?(?:handlers|billing)\.(\w+)`)
	out := map[string]string{}
	for _, line := range strings.Split(block[1], "\n") {
		if m := fieldRe.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}

// collectRouteHandlers は (メソッド, 絶対パス) → ハンドラ式 を返す。
// グループのスコープ解決は collectRoutes と同じ規則。
func collectRouteHandlers(src string) map[string]string {
	groupRe := regexp.MustCompile(`(\w+)\s*:?=\s*([\w.]+)\.Group\("([^"]*)"[^)]*\)`)
	routeRe := regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE|PATCH)\("([^"]*)"\s*,(.*)\)`)

	scopes := []map[string]string{{}}
	lookup := func(v string) (string, bool) {
		if isRootRouter(v) {
			return "", true
		}
		for i := len(scopes) - 1; i >= 0; i-- {
			if p, ok := scopes[i][v]; ok {
				return p, true
			}
		}
		return "", false
	}

	out := map[string]string{}
	for _, line := range strings.Split(src, "\n") {
		if m := groupRe.FindStringSubmatch(line); m != nil {
			parent := m[2]
			if i := strings.LastIndex(parent, "."); i >= 0 {
				parent = parent[i+1:]
			}
			if base, ok := lookup(parent); ok {
				scopes[len(scopes)-1][m[1]] = joinPath(base, m[3])
			}
		} else if m := routeRe.FindStringSubmatch(line); m != nil {
			if base, ok := lookup(m[1]); ok {
				args := strings.Split(m[4], ",")
				// 最後の引数が実ハンドラ（前段はミドルウェア）
				out[m[2]+" "+normalizePath(joinPath(base, m[3]))] = strings.TrimSpace(args[len(args)-1])
			}
		}
		for _, c := range line {
			if c == '{' {
				scopes = append(scopes, map[string]string{})
			} else if c == '}' && len(scopes) > 1 {
				scopes = scopes[:len(scopes)-1]
			}
		}
	}
	return out
}

// matchBrace は s[open] の '{' に対応する '}' の位置を返す（見つからなければ -1）。
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// handlerBodies は handlers / billing パッケージから
// (型名, メソッド名) → 関数本体 を集める。
func handlerBodies(t *testing.T, root string) map[string]string {
	t.Helper()
	funcRe := regexp.MustCompile(`func \(\w+ \*(\w+)\) (\w+)\(c \*gin\.Context\) \{`)
	out := map[string]string{}
	for _, dir := range []string{
		filepath.Join(root, "server", "internal", "api", "handlers"),
		filepath.Join(root, "server", "internal", "billing"),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			src := mustRead(t, filepath.Join(dir, e.Name()))
			for _, loc := range funcRe.FindAllStringSubmatchIndex(src, -1) {
				typ := src[loc[2]:loc[3]]
				meth := src[loc[4]:loc[5]]
				open := loc[1] - 1
				if end := matchBrace(src, open); end > 0 {
					out[typ+"."+meth] = src[open : end+1]
				}
			}
		}
	}
	return out
}

// goTopKeys は gin.H{...} リテラルのトップレベルのキーを返す。
func goTopKeys(lit string) []string {
	var keys []string
	depth := 0
	for i := 0; i < len(lit); i++ {
		switch c := lit[i]; c {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case '"':
			j := strings.IndexByte(lit[i+1:], '"')
			if j < 0 {
				return keys
			}
			j += i + 1
			if depth == 1 {
				k := j + 1
				for k < len(lit) && (lit[k] == ' ' || lit[k] == '\t') {
					k++
				}
				if k < len(lit) && lit[k] == ':' {
					keys = append(keys, lit[i+1:j])
				}
			}
			i = j
		}
	}
	return keys
}

// tsTopKeys は TypeScript のオブジェクトリテラルのトップレベルのキーを返す。
// 識別子キー（data: ...）とクォート付きキー（'2.1.0': ...）の両方を拾う。
func tsTopKeys(obj string) []string {
	var keys []string
	depth := 0
	isIdent := func(c byte) bool {
		return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	for i := 0; i < len(obj); i++ {
		c := obj[i]
		switch {
		case c == '{' || c == '[' || c == '(':
			depth++
		case c == '}' || c == ']' || c == ')':
			depth--
		case c == '\'' || c == '"':
			q := c
			j := i + 1
			for j < len(obj) && obj[j] != q {
				if obj[j] == '\\' {
					j++
				}
				j++
			}
			if depth == 1 {
				k := j + 1
				for k < len(obj) && (obj[k] == ' ' || obj[k] == '\t') {
					k++
				}
				if k < len(obj) && obj[k] == ':' {
					keys = append(keys, obj[i+1:j])
				}
			}
			i = j
		case depth == 1 && (c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')):
			j := i
			for j < len(obj) && isIdent(obj[j]) {
				j++
			}
			k := j
			for k < len(obj) && (obj[k] == ' ' || obj[k] == '\t') {
				k++
			}
			if k < len(obj) && obj[k] == ':' {
				keys = append(keys, obj[i:j])
			}
			i = j - 1
		}
	}
	return keys
}

func toSet(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func diffKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func TestAPIDocsResponseShapes(t *testing.T) {
	root := repoRootFromAPIPkg(t)
	// 継ぎ目（routes_commercial.go / routes_sso.go）を展開してから走査する。
	// router.go 単体では有償ルートが映らず、「api-docs にあるが実装に無い」という
	// 逆向きの誤報になる。
	routerSrc := routerSourceWithRegistrars(t, filepath.Join(root, "server", "internal", "api"))
	docsPath := filepath.Join(root, "frontend", "app", "admin", "api-docs", "page.tsx")
	docsSrc := mustRead(t, docsPath)

	fieldTypes := handlerFieldTypes(routerSrc)
	if len(fieldTypes) < 20 {
		t.Fatalf("Handlers struct の解析に失敗した可能性があります (フィールド数=%d)", len(fieldTypes))
	}
	routeHandlers := collectRouteHandlers(routerSrc)
	bodies := handlerBodies(t, root)

	entryRe := regexp.MustCompile(`(?m)^ {8}method: '(\w+)',\r?\n {8}path: '([^']+)'`)
	entries := entryRe.FindAllStringSubmatchIndex(docsSrc, -1)
	if len(entries) < 40 {
		t.Fatalf("api-docs の抽出に失敗した可能性があります (抽出数=%d)", len(entries))
	}

	okJSONRe := regexp.MustCompile(`c\.JSON\(\s*http\.Status(?:OK|Created|Accepted)\s*,`)
	okGinRe := regexp.MustCompile(`c\.JSON\(\s*http\.Status(?:OK|Created|Accepted)\s*,\s*gin\.H\{`)
	respRe := regexp.MustCompile(`response: JSON\.stringify\(\s*\{`)
	fieldMethodRe := regexp.MustCompile(`s\.handlers\.(\w+)\.(\w+)$`)

	var problems []string
	checked := 0
	for i, e := range entries {
		method, path := docsSrc[e[2]:e[3]], docsSrc[e[4]:e[5]]

		expr, ok := routeHandlers[method+" "+normalizePath(path)]
		if !ok {
			continue // ルート不在は TestAPIDocsEndpointsAreRegistered が検出する
		}
		fm := fieldMethodRe.FindStringSubmatch(expr)
		if fm == nil {
			continue // 無名関数など
		}
		body, ok := bodies[fieldTypes[fm[1]]+"."+fm[2]]
		if !ok {
			continue
		}
		// 成功レスポンスが 1 つ、かつ gin.H リテラルのときだけ判定する
		if len(okJSONRe.FindAllString(body, -1)) != 1 {
			continue
		}
		loc := okGinRe.FindStringIndex(body)
		if loc == nil {
			continue // 構造体・変数を返している
		}
		litStart := strings.LastIndexByte(body[:loc[1]], '{')
		litEnd := matchBrace(body, litStart)
		if litEnd < 0 {
			continue
		}
		implKeys := toSet(goTopKeys(body[litStart : litEnd+1]))

		// このエントリの response: JSON.stringify({...}) を、次のエントリ開始までで探す。
		// レスポンスが文字列リテラルのエントリで次の JSON を拾わないため。
		segEnd := len(docsSrc)
		if i+1 < len(entries) {
			segEnd = entries[i+1][0]
		}
		seg := docsSrc[e[1]:segEnd]
		rm := respRe.FindStringIndex(seg)
		if rm == nil {
			continue // レスポンス例が JSON ではない（ファイル返却の説明など）
		}
		objStart := strings.LastIndexByte(seg[:rm[1]], '{')
		objEnd := matchBrace(seg, objStart)
		if objEnd < 0 {
			continue
		}
		docKeys := toSet(tsTopKeys(seg[objStart : objEnd+1]))

		checked++
		onlyDoc := diffKeys(docKeys, implKeys)
		onlyImpl := diffKeys(implKeys, docKeys)
		if len(onlyDoc) > 0 || len(onlyImpl) > 0 {
			msg := method + " " + path + " [" + fieldTypes[fm[1]] + "." + fm[2] + "]"
			if len(onlyDoc) > 0 {
				msg += "\n      docs にだけあるキー: " + strings.Join(onlyDoc, ", ")
			}
			if len(onlyImpl) > 0 {
				msg += "\n      実装にだけあるキー: " + strings.Join(onlyImpl, ", ")
			}
			problems = append(problems, msg)
		}
	}

	// 判定できた件数を必ず出す。抽出が壊れて 0 件になっても緑になってしまうため、
	// 下限も設けておく。
	t.Logf("レスポンス形状: %d 件を判定 / %d 件は静的に判定不能（構造体返却・成功レスポンス複数・ファイル返却など）",
		checked, len(entries)-checked)
	if checked < 25 {
		t.Fatalf("形状を判定できた件数が想定より少なすぎます (=%d)。抽出ロジックが壊れていないか確認してください", checked)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("api-docs のレスポンス例が実装と一致しません (%d 件)。\n"+
			"%s を修正してください:\n  %s",
			len(problems), docsPath, strings.Join(problems, "\n  "))
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("読み込みに失敗: %s: %v", path, err)
	}
	return string(b)
}

// repoRootFromAPIPkg は internal/api から見たリポジトリルート(server の親)を返す。
func repoRootFromAPIPkg(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("作業ディレクトリの取得に失敗: %v", err)
	}
	// .../server/internal/api → .../
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "frontend", "app", "admin", "api-docs", "page.tsx")); err != nil {
		t.Skipf("frontend が同梱されていないためスキップします: %v", err)
	}
	return root
}

package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// routerSourceWithRegistrars は router.go を読み、`s.registerXxx(...)` という
// 継ぎ目の呼び出しをその関数本体で置き換えた1本のソースを返す。
//
// ─── なぜ必要か ─────────────────────────────────────────────────────────
//
// この走査系テスト（api-docs 突合、レスポンス形状の突合）は router.go を
// **1ファイルだけ**読んで登録経路を数えていた。有償ルートを routes_commercial.go /
// routes_sso.go へ移した時点で、その前提は静かに崩れる——ルートは実装として存在
// するのに走査には映らず、「api-docs に書いてあるが実装に無い」という**逆向きの
// 嘘**が出る。実際 Billing の 4 経路がそう報告された。
//
// 台帳は変更に追随させる必要がある。ここでは openapi-sync と同じ解き方を使う:
// 呼び出し側の引数名で仮引数を置き換えてから本体を差し込む。こうすると
// `protected.Group("/admin/billing")` の `protected` が router.go 側の束縛で
// そのまま解決でき、走査側の変数スコープ処理に手を入れずに済む。
func routerSourceWithRegistrars(t *testing.T, apiDir string) string {
	t.Helper()

	// 継ぎ目関数の宣言を集める（router.go 以外の同パッケージのファイルから）。
	declRe := regexp.MustCompile(`(?m)^func \(s \*Server\) (register\w+)\(([^)]*)\) \{`)
	bodies := map[string]struct {
		params []string
		body   string
	}{}

	entries, err := os.ReadDir(apiDir)
	if err != nil {
		t.Fatalf("internal/api を読めません: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "router.go" {
			continue
		}
		src := mustRead(t, filepath.Join(apiDir, name))
		for _, loc := range declRe.FindAllStringSubmatchIndex(src, -1) {
			fn := src[loc[2]:loc[3]]
			params := parseGroupParams(src[loc[4]:loc[5]])
			body, ok := bodyAfter(src, loc[1]-1) // '{' の位置から
			if !ok {
				t.Fatalf("%s: %s の本体を切り出せません", name, fn)
			}
			bodies[fn] = struct {
				params []string
				body   string
			}{params, body}
		}
	}
	if len(bodies) == 0 {
		t.Fatal("継ぎ目関数が1つも見つかりません。routes_commercial.go の書式が変わっていないか確認してください")
	}

	callRe := regexp.MustCompile(`(?m)^\s*s\.(register\w+)\(([^)]*)\)\s*$`)
	out := mustRead(t, filepath.Join(apiDir, "router.go"))
	// 継ぎ目が継ぎ目を呼ぶ（registerCommercialRoutes → registerSSORoutes）ため
	// 展開は不動点まで繰り返す。上限は暴走時の保険。
	for i := 0; i < 5; i++ {
		expanded := false
		out = callRe.ReplaceAllStringFunc(out, func(call string) string {
			m := callRe.FindStringSubmatch(call)
			d, ok := bodies[m[1]]
			if !ok {
				return call
			}
			expanded = true
			args := splitArgs(m[2])
			// 公開版では継ぎ目が `func (s *Server) registerX(_, _ *gin.RouterGroup) {}`
			// という空実装に差し替わる。仮引数が全て `_` なので置換対象は無く、
			// 本体も空——引数の個数を突き合わせると公開版だけが落ちる。
			switch {
			case len(d.params) == 0:
				return "{" + d.body + "}"
			case len(args) != len(d.params):
				t.Fatalf("%s: 引数 %d 個に対し仮引数 %d 個", m[1], len(args), len(d.params))
			}
			body := d.body
			for i, p := range d.params {
				if p == args[i] {
					continue
				}
				body = regexp.MustCompile(`\b`+regexp.QuoteMeta(p)+`\b`).ReplaceAllString(body, args[i])
			}
			return "{\n" + body + "\n}"
		})
		if !expanded {
			break
		}
	}
	return out
}

// parseGroupParams は `api, protected *gin.RouterGroup` のような仮引数リストから
// *gin.RouterGroup の名前を宣言順に取り出す。
func parseGroupParams(sig string) []string {
	var names []string
	for _, part := range strings.Split(sig, "*gin.RouterGroup") {
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), ","))
		if part == "" {
			continue
		}
		for _, n := range strings.Split(part, ",") {
			if n = strings.TrimSpace(n); n != "" && n != "_" {
				names = append(names, n)
			}
		}
	}
	return names
}

func splitArgs(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// bodyAfter は open に位置する '{' に対応する '}' までの中身を返す。
func bodyAfter(src string, open int) (string, bool) {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], true
			}
		}
	}
	return "", false
}

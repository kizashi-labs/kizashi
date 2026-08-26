package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 手書き記述の網羅率の下限。実装の総操作数に対する割合(%)。
//
// 導入時点で 12.2%（手書き 178 / 全 1459）。ここは**下げない**。上げるときは
// 手書きを増やしてからこの値を引き上げる。テストカバレッジのラチェットと
// 同じ運用。自動生成スタブはこの数字に入らない — スタブは「存在すること」
// しか言っておらず、それを網羅率に数えると実態より良く見えるため。
// 2026-08-19: このリポジトリでは 11.3%（手書き 178 / 全 1570）。**手書きを減らしたのではない** —— 分子は 178 のままで、分母だけが増えている。この検査は
// 公開版（課金・MDM・SSO・AI のルートを持たない）で較正されており、そちらの
// 総操作数は 1459 だった。有償機能のルートがそのまま分母に乗るぶん、同じ
// 手書き量でも率が下がる。床は実測の少し下に置き直す。
const coverageFloorPercent = 11.0

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("作業ディレクトリの取得に失敗: %v", err)
	}
	// .../server/cmd/openapi-sync → .../
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "docs", "openapi.yaml")); err != nil {
		t.Skipf("docs/openapi.yaml が同梱されていないためスキップします: %v", err)
	}
	return root
}

// readAPIPackageForTest は internal/api の全ソースを連結して返す。
func readAPIPackageForTest(t *testing.T) string {
	t.Helper()
	src, err := readAPIPackage(filepath.Join(repoRoot(t), "server", "internal", "api"))
	if err != nil {
		t.Fatalf("internal/api を読めませんでした: %v", err)
	}
	return src
}

func load(t *testing.T) (string, []Route, *Spec, string) {
	t.Helper()
	root := repoRoot(t)
	routerSrc, err := readAPIPackage(filepath.Join(root, "server", "internal", "api"))
	if err != nil {
		t.Fatalf("internal/api を読めませんでした: %v", err)
	}
	specSrc, err := os.ReadFile(filepath.Join(root, "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("openapi.yaml を読めませんでした: %v", err)
	}
	routes := CollectRoutes(routerSrc)
	if len(routes) < minExtractedRoutes {
		t.Fatalf("抽出 %d 件（下限 %d）。internal/api の書式を確認してください", len(routes), minExtractedRoutes)
	}
	spec, err := ParseSpec(string(specSrc))
	if err != nil {
		t.Fatalf("openapi.yaml の解析に失敗しました: %v", err)
	}
	return root, routes, spec, string(specSrc)
}

// 手書きの記述が実装に存在することを固定する。
//
// 導入時点で 59 件が存在しなかった（`GET /api/v1/auth/me` は実際には
// `/api/v1/users/me`、billing と system-updates は経路そのものが無い、など）。
// 誤ったドキュメントは無いより悪い。実際に P5-16 では、この手の記述が
// 設計判断を誤らせかけている。
func TestOpenAPIHasNoDrift(t *testing.T) {
	_, routes, spec, _ := load(t)
	if drift := spec.HandwrittenDrift(routes); len(drift) > 0 {
		t.Errorf("openapi.yaml の手書き記述 %d 件が router.go に存在しません:\n  %s",
			len(drift), strings.Join(drift, "\n  "))
	}
}

// openapi.yaml が実装と同期していること（= openapi-sync の出力と一致すること）。
func TestOpenAPIIsSynced(t *testing.T) {
	_, routes, spec, src := load(t)
	if out := spec.Sync(routes); out != src {
		t.Error("docs/openapi.yaml が実装と同期していません。" +
			"`cd server && go run ./cmd/openapi-sync` を実行して差分をコミットしてください")
	}
}

// API が配信する server/docs/openapi.yaml が正本と同一であること。
//
// 以前は 2 つの仕様が別々に手書きされ、パス表記（/api/v1 を含むか）も
// 内容も食い違っていた。配信側だけに載っている記述が 26 パスあった。
func TestEmbeddedSpecMatchesCanonical(t *testing.T) {
	root := repoRoot(t)
	canonical, err := os.ReadFile(filepath.Join(root, "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("docs/openapi.yaml を読めませんでした: %v", err)
	}
	embedded, err := os.ReadFile(filepath.Join(root, "server", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("server/docs/openapi.yaml を読めませんでした: %v", err)
	}
	if string(canonical) != string(embedded) {
		t.Error("server/docs/openapi.yaml が docs/openapi.yaml と一致しません。" +
			"`cd server && go run ./cmd/openapi-sync` を実行してください")
	}
}

// 手書き網羅率のラチェット。
func TestOpenAPICoverageDoesNotRegress(t *testing.T) {
	_, routes, spec, _ := load(t)
	covered, total := spec.Coverage(routes)
	pct := 100 * float64(covered) / float64(total)
	t.Logf("手書き網羅率: %d / %d = %.1f%%（残りは自動生成スタブ）", covered, total, pct)
	if pct < coverageFloorPercent {
		t.Errorf("手書き網羅率が下限を割りました: %.1f%% < %.1f%%。"+
			"手書きの記述を消した場合は元に戻すか、意図的な削減なら "+
			"coverageFloorPercent を下げてください", pct, coverageFloorPercent)
	}
}

// 自動生成スタブが「実装の存在」以上のことを主張していないこと。
// スタブに応答形状を書き足しても次の同期で消える。書くなら手書きへ
// 移す必要があり、それを促すためにここで検出する。
func TestGeneratedStubsStayMinimal(t *testing.T) {
	_, _, spec, _ := load(t)
	for _, b := range spec.blocks {
		for _, mb := range b.methods {
			if !mb.generated {
				continue
			}
			for _, l := range mb.lines {
				if strings.Contains(l, "requestBody") || strings.Contains(l, "schemas/") {
					t.Errorf("%s %s: 自動生成ブロックに形状が書かれています。"+
						"手書きセクションへ移してください", strings.ToUpper(mb.method), b.path)
					break
				}
			}
		}
	}
}

// リポジトリルートの探索が server/ で止まらないこと。
//
// 目印を docs/openapi.yaml だけにしていたため、配信用コピーのある
// server/ をルートと誤判定していた。CI は `working-directory: server` で
// 走らせるので、server/server/internal/api/router.go を開こうとして落ちた。
// ローカルでは -root を渡していて気づけなかった。
func TestRepoRootFromServerDir(t *testing.T) {
	root := repoRoot(t)

	for _, start := range []string{
		root,
		filepath.Join(root, "server"),
		filepath.Join(root, "server", "cmd", "openapi-sync"),
		filepath.Join(root, "frontend"),
	} {
		if _, err := os.Stat(start); err != nil {
			continue
		}
		got, err := repoRootFrom(start)
		if err != nil {
			t.Errorf("repoRootFrom(%q): %v", start, err)
			continue
		}
		if got != root {
			t.Errorf("repoRootFrom(%q) = %q, want %q", start, got, root)
		}
	}
}

// 抽出から漏れた登録は、報告するだけでは足りない。
//
// 以前 23 登録がヘルパ関数へ移って解決できなくなったとき、このツールは
// その旨を stderr に出したうえで **exit 0 で成功を返した**。実測（2026-08-20）:
// 32 登録を別ファイルへ移して同期を実行すると、
//
//	docs/openapi.yaml を更新しました（全 1561 操作）   ← 1593 から 32 減
//	EXIT=0
//
// 「同期しました」と言いながら 32 エンドポイントが仕様から消える。
// 仕様に無いエンドポイントは、SDK の利用者には存在しないのと同じ。
func TestUnresolvedRegistrationsAreReported(t *testing.T) {
	// グループ変数がこのソースの中で定義されていないので解決できない。
	// 実際に起きたのは、登録がヘルパ関数へ移って呼び出し元と切れた形。
	src := `
func (s *Server) registerSomething(orphanGroup *gin.RouterGroup) {
	orphanGroup.GET("/thing", s.handlers.Thing.List)
	orphanGroup.POST("/thing", s.handlers.Thing.Create)
}
`
	routes, unresolved := CollectRoutesWithDiagnostics(src)
	if len(unresolved) == 0 {
		t.Fatal("解決できない登録が報告されていません。**抽出から漏れたことが呼び出し側に伝わりません**")
	}
	if len(routes) != 0 {
		t.Errorf("解決できていないのに %d 件が抽出されています", len(routes))
	}
}

// 通常の登録では未解決が出ないこと（上の検査が常に鳴るのでは意味がない）。
func TestResolvableRegistrationsProduceNoDiagnostics(t *testing.T) {
	src := readAPIPackageForTest(t)
	routes, unresolved := CollectRoutesWithDiagnostics(src)
	if len(unresolved) > 0 {
		t.Errorf("internal/api に解決できない登録が %d 件あります: %v", len(unresolved), unresolved)
	}
	if len(routes) < minExtractedRoutes {
		t.Errorf("抽出 %d 件（下限 %d）", len(routes), minExtractedRoutes)
	}
}

// 登録関数が複数のグループを受け取る形を解決できること。
//
// ルート登録を機能ごとに切り出すと、公開版と有償版の境目になる関数は
// `api` と `protected` の両方を受け取る。1引数しか見ていなかった頃は
// ここで解決が止まり、#840 以降はそれが中断として現れる——**登録を
// 切り出せない**。
//
// 実測（2026-08-20）: SSO の登録を専用ファイルへ移し、仮引数を呼び出し側と
// 別名（pub/adm）にすると、複数引数対応が無い状態では 9 登録が解決不能になった。
func TestMultiParamRegistrarsResolve(t *testing.T) {
	src := `
func (s *Server) SetupRouter() {
	api := r.Group("/api/v1")
	protected := api.Group("/")
	s.registerThing(api, protected)
}

func (s *Server) registerThing(pub, adm *gin.RouterGroup) {
	pub.GET("/open", s.handlers.Thing.Open)
	adm.POST("/closed", s.handlers.Thing.Closed)
}
`
	routes, unresolved := CollectRoutesWithDiagnostics(src)
	if len(unresolved) > 0 {
		t.Fatalf("複数引数の登録関数を解決できていません: %v", unresolved)
	}

	got := map[string]bool{}
	for _, r := range routes {
		got[r.Method+" "+r.Path] = true
	}
	for _, want := range []string{"GET /api/v1/open", "POST /api/v1/closed"} {
		if !got[want] {
			t.Errorf("%q が抽出されていません。抽出: %v", want, got)
		}
	}
}

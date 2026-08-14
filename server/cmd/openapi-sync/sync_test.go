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
const coverageFloorPercent = 12.0

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

func load(t *testing.T) (string, []Route, *Spec, string) {
	t.Helper()
	root := repoRoot(t)
	routerSrc, err := os.ReadFile(filepath.Join(root, "server", "internal", "api", "router.go"))
	if err != nil {
		t.Fatalf("router.go を読めませんでした: %v", err)
	}
	specSrc, err := os.ReadFile(filepath.Join(root, "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("openapi.yaml を読めませんでした: %v", err)
	}
	routes := CollectRoutes(string(routerSrc))
	if len(routes) < 500 {
		t.Fatalf("ルート抽出に失敗した可能性があります (抽出数=%d)。router.go の書式を確認してください", len(routes))
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

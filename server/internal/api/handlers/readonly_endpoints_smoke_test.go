package handlers_test

// 読み取り専用エンドポイントのスモークテスト。
//
// ここで対象にしているハンドラは、これまでテストが 1 本も無く、CI で一度も
// 実行されていなかった。SQL の列名やプレースホルダを間違えても誰も気づけない
// 状態だったため（PR #556 / #558 で実際にその種のバグが 15 件見つかっている）、
// まず「実スキーマに対してクエリが通り、期待した形の JSON を返す」ことを
// 全経路で確認する。
//
// 個々のビジネスロジックの正しさまでは踏み込まない。ここでの目的は
// 「壊れていたら CI が気づく」状態を作ることにある。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/edr-platform/server/internal/api/handlers"
)

// getJSON は GET ハンドラを 1 本叩き、ステータスとデコード済み JSON を返す。
func getJSON(t *testing.T, target string, h gin.HandlerFunc) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	h(c)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		// CSV など JSON でない応答を返すハンドラもあるため、呼び出し側が
		// 判断できるよう nil を返してステータスだけ渡す。
		return w.Code, nil
	}
	return w.Code, resp
}

// mapKeys は失敗時のメッセージにレスポンスのキー一覧を載せるための補助。
func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ── SOC メトリクス ───────────────────────────────────────────────

func TestSOCMetricsHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewSOCMetricsHandler(pool)

	t.Run("Summary", func(t *testing.T) {
		code, resp := getJSON(t, "/api/v1/soc/metrics/summary", h.Summary)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
		}
		if resp == nil {
			t.Fatal("JSON が返っていない")
		}
	})

	t.Run("ShiftHandover", func(t *testing.T) {
		code, resp := getJSON(t, "/api/v1/soc/metrics/handover", h.ShiftHandover)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
		}
	})

	t.Run("FrontendMetrics", func(t *testing.T) {
		code, resp := getJSON(t, "/api/v1/soc/metrics/frontend", h.FrontendMetrics)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
		}
	})
}

// ── コンプライアンス ─────────────────────────────────────────────

func TestComplianceHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewComplianceHandler(pool)

	cases := []struct {
		name   string
		target string
		fn     gin.HandlerFunc
	}{
		{"Summary", "/api/v1/compliance/summary", h.Summary},
		{"MITREMapping", "/api/v1/compliance/mitre", h.MITREMapping},
		{"CISControls", "/api/v1/compliance/cis", h.CISControls},
		{"NISTFramework", "/api/v1/compliance/nist", h.NISTFramework},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := getJSON(t, tc.target, tc.fn)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
			}
			if resp == nil {
				t.Fatal("JSON が返っていない")
			}
		})
	}
}

// ── メトリクス API ───────────────────────────────────────────────

func TestMetricsAPIHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewMetricsAPIHandler(pool)

	cases := []struct {
		name   string
		target string
		fn     gin.HandlerFunc
	}{
		{"AlertTrends", "/api/v1/metrics/alert-trends?days=7", h.AlertTrends},
		{"TopAgents", "/api/v1/metrics/top-agents?limit=10", h.TopAgents},
		{"DetectionStats", "/api/v1/metrics/detection-stats", h.DetectionStats},
		{"AgentStats", "/api/v1/metrics/agent-stats", h.AgentStats},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := getJSON(t, tc.target, tc.fn)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
			}
			if resp == nil {
				t.Fatal("JSON が返っていない")
			}
		})
	}
}

// ── 横断検索 ─────────────────────────────────────────────────────

func TestSearchHandler_Search(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewSearchHandler(pool)

	// 空クエリと通常クエリの両方を通す。空のときの早期リターン経路も見る。
	for _, q := range []string{"", "test", "192.168.1.1"} {
		code, resp := getJSON(t, "/api/v1/search?q="+q, h.Search)
		if code != http.StatusOK && code != http.StatusBadRequest {
			t.Fatalf("q=%q: status = %d, want 200 or 400 (body: %v)", q, code, resp)
		}
	}
}

// ── タイムライン ─────────────────────────────────────────────────

func TestTimelineHandler_GetTimeline(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewTimelineHandler(pool)

	code, resp := getJSON(t, "/api/v1/timeline?hours=24", h.GetTimeline)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}
}

// ── ソフトウェア差分 ─────────────────────────────────────────────

func TestSoftwareDiffHandler_ReadOnlyEndpoints(t *testing.T) {
	pool := testPool(t)
	h := handlers.NewSoftwareDiffHandler(pool)

	t.Run("GetDiffs", func(t *testing.T) {
		code, resp := getJSON(t, "/api/v1/software/diffs", h.GetDiffs)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
		}
	})
}

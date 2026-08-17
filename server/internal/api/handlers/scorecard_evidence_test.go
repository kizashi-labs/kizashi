package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/scorecard"
)

// The compliance scorecard used to answer 200 with a number no matter what
// happened underneath. Every evidence query threw its error away, so a dead
// database produced a NIST CSF score of 35.3 against a healthy 42.5, with
// twenty-three specific findings attached — "No hardening baselines configured".
// internal/scorecard now reports those failures; these gates cover the three
// places the handler could put the fabrication back.
//
//   - GET nist-csf / iso27001 must not serve a score built on nothing.
//   - GET summary substituted OverallScore 0 for a framework it could not
//     calculate, and the dashboard renders 0 in red as a failing posture. An
//     outage was displayed as the worst possible compliance result.
//   - top_gaps sorted worst-first over every non-compliant control, and an
//     unassessed control scores 0 — so a failed query became the customer's
//     single worst control, by name, at the top of the list.

// deadScorer returns a Scorer wired to a real pool, and a context under which
// every query it makes fails.
func deadScorer(t *testing.T) (*scorecard.Scorer, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return scorecard.NewScorer(pool), ctx
}

// callScorecard invokes a handler with a request carrying the given context.
func callScorecard(t *testing.T, fn func(*gin.Context), ctx context.Context, path string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	fn(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("レスポンスがJSONではありません: %v (%s)", err, w.Body.String())
		}
	}
	return w.Code, decoded
}

// A scorecard nothing could be measured for is an outage, not a result.
func TestAnUnmeasurableScorecardIsNotServedAsAResult(t *testing.T) {
	scorer, dead := deadScorer(t)
	h := NewScorecardHandler(scorer)

	for _, tc := range []struct {
		name string
		fn   func(*gin.Context)
		path string
	}{
		{"nist-csf", h.GetNISTCSF, "/api/v1/admin/scorecard/nist-csf"},
		{"iso27001", h.GetISO27001, "/api/v1/admin/scorecard/iso27001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := callScorecard(t, tc.fn, dead, tc.path)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("証跡が一件も読めないのに %d を返しました (期待: 503)。"+
					"監査人が根拠のないスコアを読むことになります", code)
			}
			if body["error"] == nil {
				t.Error("503 に error がありません")
			}
			if got, ok := body["assessed"].(float64); !ok || got != 0 {
				t.Errorf("assessed=%v、期待は0", body["assessed"])
			}
			if got, ok := body["total"].(float64); !ok || got == 0 {
				t.Errorf("total=%v。対象コントロール数が伝わりません", body["total"])
			}
			if _, present := body["overall_score"]; present {
				t.Errorf("評価不能な応答に overall_score が含まれています: %v", body["overall_score"])
			}
		})
	}
}

// A healthy database still gets a 200 and a score — the gate above must not be
// passing because the endpoint stopped working.
func TestAMeasurableScorecardIsStillServed(t *testing.T) {
	scorer, _ := deadScorer(t)
	h := NewScorecardHandler(scorer)

	code, body := callScorecard(t, h.GetNISTCSF, context.Background(),
		"/api/v1/admin/scorecard/nist-csf")
	if code != http.StatusOK {
		t.Fatalf("健全なDBに対して %d を返しました (期待: 200)", code)
	}
	assessed, ok := body["assessed_controls"].(float64)
	if !ok || assessed == 0 {
		t.Fatalf("assessed_controls=%v。健全なDBで何も評価できていません", body["assessed_controls"])
	}
	total, ok := body["total_controls"].(float64)
	if !ok || total < assessed {
		t.Errorf("total_controls=%v が assessed_controls=%v を下回ります", body["total_controls"], assessed)
	}
	if _, present := body["overall_score"]; !present {
		t.Error("200 応答に overall_score がありません")
	}
}

// The summary's fallback must not invent a failing posture out of an outage.
func TestTheSummaryReportsAnUnmeasurableFrameworkAsNull(t *testing.T) {
	scorer, dead := deadScorer(t)
	h := NewScorecardHandler(scorer)

	code, body := callScorecard(t, h.GetSummary, dead, "/api/v1/admin/scorecard/summary")
	if code != http.StatusOK {
		t.Fatalf("サマリが %d を返しました (期待: 200)", code)
	}
	for _, key := range []string{"nist_score", "iso_score"} {
		v, present := body[key]
		if !present {
			t.Errorf("%s がありません", key)
			continue
		}
		if v != nil {
			t.Errorf("%s=%v。評価できなかったフレームワークは null であるべきです — "+
				"0 はダッシュボード上で最悪の準拠状況として赤く描画されます", key, v)
		}
	}

	// Coverage still has to be reported, or null says nothing about why.
	for _, key := range []string{"nist_coverage", "iso_coverage"} {
		cov, ok := body[key].(map[string]interface{})
		if !ok {
			t.Errorf("%s がありません", key)
			continue
		}
		if got, _ := cov["assessed"].(float64); got != 0 {
			t.Errorf("%s.assessed=%v、期待は0", key, cov["assessed"])
		}
		if got, _ := cov["total"].(float64); got == 0 {
			t.Errorf("%s.total=%v。対象コントロール数が伝わりません", key, cov["total"])
		}
	}
}

// An unassessed control must never be presented as a gap.
func TestTopGapsExcludeControlsThatWereNotAssessed(t *testing.T) {
	scorer, dead := deadScorer(t)
	h := NewScorecardHandler(scorer)

	_, body := callScorecard(t, h.GetSummary, dead, "/api/v1/admin/scorecard/summary")
	gaps, ok := body["top_gaps"].([]interface{})
	if !ok {
		t.Fatalf("top_gaps が配列ではありません: %v", body["top_gaps"])
	}
	if len(gaps) != 0 {
		t.Errorf("何も評価できていないのに top_gaps に %d件あります: %v — "+
			"クエリの失敗が最悪のコントロールとして名指しで表示されます", len(gaps), gaps)
	}
}

// And on a healthy database top_gaps is populated, so the gate above is not
// passing because the field stopped being filled.
func TestTopGapsAreStillReportedWhenMeasured(t *testing.T) {
	scorer, _ := deadScorer(t)
	h := NewScorecardHandler(scorer)

	_, body := callScorecard(t, h.GetSummary, context.Background(),
		"/api/v1/admin/scorecard/summary")
	gaps, ok := body["top_gaps"].([]interface{})
	if !ok {
		t.Fatalf("top_gaps が配列ではありません: %v", body["top_gaps"])
	}
	if len(gaps) == 0 {
		t.Fatal("健全なDBで top_gaps が空です")
	}
	for _, g := range gaps {
		gap, ok := g.(map[string]interface{})
		if !ok {
			t.Fatalf("gap の形式が不正です: %v", g)
		}
		if gap["status"] == "not_assessed" {
			t.Errorf("未評価のコントロールが gap として報告されています: %v", gap)
		}
		if gap["status"] == "compliant" {
			t.Errorf("準拠済みのコントロールが gap として報告されています: %v", gap)
		}
	}
	if body["nist_score"] == nil {
		t.Error("健全なDBで nist_score が null です")
	}
}

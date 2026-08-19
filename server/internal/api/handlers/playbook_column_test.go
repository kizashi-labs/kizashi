package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The compliance summary counted playbooks with COUNT(*) FILTER (WHERE enabled).
// The column is is_active, so the statement was rejected with 42703 and the
// error was discarded with `_ =`. Both counts stayed 0, which the scoring code
// reads as "no playbooks configured": PCI-12 (incident response) scored on a
// playbookScore of 0 and its detail line read "有効プレイブック 0/0" no matter
// how many were configured.

// detailCountRe pulls the "有効/総数" pair out of the PCI-12 detail line.
var detailCountRe = regexp.MustCompile(`有効プレイブック (\d+)/(\d+)`)

// The headline: a configured playbook is counted, and a disabled one is not.
func TestTheComplianceSummaryCountsActivePlaybooks(t *testing.T) {
	pool := renamePool(t)
	ctx := context.Background()

	marker := "playbook-fixture-" + uuid.NewString()[:8]
	for _, active := range []bool{true, true, false} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO playbooks (name, description, conditions, actions, is_active)
			VALUES ($1, 'fixture', '{}'::jsonb, '[]'::jsonb, $2)`,
			marker+"-"+uuid.NewString()[:8], active); err != nil {
			t.Fatalf("seed playbook: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM playbooks WHERE name LIKE $1`, marker+"%")
	})

	// Through the handler, not by re-issuing its query: a test that restates the
	// statement it is checking passes whatever the handler does.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/summary", NewComplianceHandler(pool).Summary)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/summary", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Metrics struct {
			Enabled int `json:"enabled_playbooks"`
		} `json:"metrics"`
		Frameworks []struct {
			Controls []struct {
				ID     string `json:"id"`
				Detail string `json:"detail"`
			} `json:"controls"`
		} `json:"framework_details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The table is shared, so this is a floor: the fixture adds two active ones.
	if body.Metrics.Enabled < 2 {
		t.Errorf("有効プレイブック = %d, 2件以上を期待。集計クエリが実行できていません — "+
			"playbooks の有効フラグは is_active で、enabled という列はありません",
			body.Metrics.Enabled)
	}

	// PCI-12 reports the pair, which is where the filter actually shows: the
	// fixture's disabled playbook must widen the gap between the two numbers.
	var detail string
	for _, fw := range body.Frameworks {
		for _, ctrl := range fw.Controls {
			if ctrl.ID == "PCI-12" {
				detail = ctrl.Detail
			}
		}
	}
	m := detailCountRe.FindStringSubmatch(detail)
	if m == nil {
		t.Fatalf("PCI-12 の説明文からプレイブック数が読めません: %q", detail)
	}
	enabled, _ := strconv.Atoi(m[1])
	total, _ := strconv.Atoi(m[2])
	if total < 3 {
		t.Errorf("プレイブック総数 = %d, 3件以上を期待", total)
	}
	if enabled >= total {
		t.Errorf("有効数が総数と同じです (%d/%d)。FILTER が効いておらず、"+
			"無効なプレイブックも有効として数えています", enabled, total)
	}
}

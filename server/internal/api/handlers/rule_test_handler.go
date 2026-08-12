package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuleTestHandler handles detection rule dry-run / test requests.
type RuleTestHandler struct {
	pool *pgxpool.Pool
}

func NewRuleTestHandler(pool *pgxpool.Pool) *RuleTestHandler {
	return &RuleTestHandler{pool: pool}
}

type ruleTestRequest struct {
	RuleID string `json:"rule_id"`
	// OR inline rule definition for ad-hoc testing
	Name      string `json:"name,omitempty"`
	Condition string `json:"condition,omitempty"` // rule content / condition expression
	LookbackH int    `json:"lookback_hours"`
}

type ruleTestResult struct {
	RuleID        string                   `json:"rule_id,omitempty"`
	RuleName      string                   `json:"rule_name"`
	LookbackH     int                      `json:"lookback_hours"`
	TotalEvents   int                      `json:"total_events_checked"`
	Matches       int                      `json:"matches"`
	SampleMatches []map[string]interface{} `json:"sample_matches"`
	Duration      string                   `json:"duration_ms"`
	TestedAt      time.Time                `json:"tested_at"`
}

// Test handles POST /api/v1/rules/test
func (h *RuleTestHandler) Test(c *gin.Context) {
	var req ruleTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.LookbackH <= 0 {
		req.LookbackH = 24
	}
	if req.LookbackH > 168 {
		req.LookbackH = 168 // max 1 week
	}

	start := time.Now()

	// Count total events in lookback window
	// events の時刻列は `time`(`timestamp` は存在しない)。以前はこのクエリが
	// 常に失敗し、ルールテストの対象イベント数が 0 のままだった。
	//
	// 間隔は make_interval(hours => $1) で組む。`($1 || ' hours')::INTERVAL` は
	// $1 を text 推論させるため、pgx が int の LookbackH を text OID へ
	// エンコードできず実行時に失敗する
	// ("unable to encode 24 into text format for text (OID 25)")。
	// detection/anomaly.go で同じ理由により既に int 単一文脈へ統一済み。
	var totalEvents int
	if err := h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM events WHERE time >= NOW() - make_interval(hours => $1)`,
		req.LookbackH,
	).Scan(&totalEvents); err != nil {
		slog.Warn("rule test: 対象イベント数の取得に失敗", "error", err)
	}

	// If rule_id provided, try to get actual matches (simplified)
	var matches int
	var sampleMatches []map[string]interface{}

	if req.RuleID != "" {
		// Get rule details — rules table uses 'content' for the rule body
		var ruleName string
		err := h.pool.QueryRow(c.Request.Context(),
			`SELECT name FROM rules WHERE id=$1`, req.RuleID,
		).Scan(&ruleName)
		if err == nil {
			req.Name = ruleName
			// Count alerts triggered by this rule in the lookback window
			if err := h.pool.QueryRow(c.Request.Context(),
				`SELECT COUNT(*) FROM alerts WHERE rule_id=$1 AND created_at >= NOW() - make_interval(hours => $2)`,
				req.RuleID, req.LookbackH,
			).Scan(&matches); err != nil {
				slog.Warn("rule test: マッチ件数の取得に失敗", "error", err)
			}

			// Fetch sample matching alerts
			rows, err := h.pool.Query(c.Request.Context(),
				`SELECT id, title, severity, created_at FROM alerts
				 WHERE rule_id=$1 AND created_at >= NOW() - make_interval(hours => $2)
				 ORDER BY created_at DESC LIMIT 5`,
				req.RuleID, req.LookbackH,
			)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var id, title, severity string
					var createdAt time.Time
					if err := rows.Scan(&id, &title, &severity, &createdAt); err == nil {
						sampleMatches = append(sampleMatches, map[string]interface{}{
							"id": id, "title": title, "severity": severity, "created_at": createdAt,
						})
					}
				}
				if err := rows.Err(); err != nil {
					slog.Warn("row iteration error", "error", err)
				}
			}
		}
	}

	if sampleMatches == nil {
		sampleMatches = []map[string]interface{}{}
	}

	elapsed := time.Since(start)
	result := ruleTestResult{
		RuleID:        req.RuleID,
		RuleName:      req.Name,
		LookbackH:     req.LookbackH,
		TotalEvents:   totalEvents,
		Matches:       matches,
		SampleMatches: sampleMatches,
		Duration:      elapsed.String(),
		TestedAt:      time.Now(),
	}
	c.JSON(http.StatusOK, result)
}

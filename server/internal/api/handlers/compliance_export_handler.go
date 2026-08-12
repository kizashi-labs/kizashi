package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceExportHandler provides export endpoints for compliance check data.
type ComplianceExportHandler struct {
	pool *pgxpool.Pool
}

func NewComplianceExportHandler(pool *pgxpool.Pool) *ComplianceExportHandler {
	return &ComplianceExportHandler{pool: pool}
}

// Export handles GET /api/v1/compliance/export
// Query params: format=json|csv, framework=cis|nist|pci (default: all)
func (h *ComplianceExportHandler) Export(c *gin.Context) {
	format := c.DefaultQuery("format", "json")
	framework := c.DefaultQuery("framework", "")
	timestamp := time.Now().Format("20060102-150405")

	// Fetch compliance checks
	query := `SELECT id, framework, control_id, title, status, score, last_checked_at, details
              FROM compliance_checks ORDER BY framework, control_id`
	args := []interface{}{}
	if framework != "" {
		query = `SELECT id, framework, control_id, title, status, score, last_checked_at, details
                 FROM compliance_checks WHERE framework=$1 ORDER BY control_id`
		args = append(args, framework)
	}

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		// Table may not exist - return empty report
		c.JSON(http.StatusOK, gin.H{
			"exported_at": time.Now(),
			"framework":   framework,
			"checks":      []interface{}{},
			"note":        "compliance_checksテーブルが存在しないか空です",
		})
		return
	}
	defer rows.Close()

	type Check struct {
		ID            string          `json:"id"`
		Framework     string          `json:"framework"`
		ControlID     string          `json:"control_id"`
		Title         string          `json:"title"`
		Status        string          `json:"status"`
		Score         float64         `json:"score"`
		LastCheckedAt *time.Time      `json:"last_checked_at,omitempty"`
		Details       json.RawMessage `json:"details,omitempty"`
	}

	var checks []Check
	passed, failed, total := 0, 0, 0
	for rows.Next() {
		var ch Check
		if err := rows.Scan(&ch.ID, &ch.Framework, &ch.ControlID, &ch.Title, &ch.Status, &ch.Score, &ch.LastCheckedAt, &ch.Details); err != nil {
			continue
		}
		checks = append(checks, ch)
		total++
		if ch.Status == "pass" || ch.Status == "passed" {
			passed++
		} else {
			failed++
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if checks == nil {
		checks = []Check{}
	}

	scorePercent := 0.0
	if total > 0 {
		scorePercent = float64(passed) / float64(total) * 100
	}

	switch format {
	case "csv":
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="compliance-report-%s.csv"`, timestamp))
		c.Header("Content-Type", "text/csv; charset=utf-8")
		w := csv.NewWriter(c.Writer)
		_ = w.Write([]string{"framework", "control_id", "title", "status", "score", "last_checked_at"})
		for _, ch := range checks {
			ts := ""
			if ch.LastCheckedAt != nil {
				ts = ch.LastCheckedAt.Format(time.RFC3339)
			}
			_ = w.Write([]string{
				ch.Framework, ch.ControlID, ch.Title, ch.Status,
				fmt.Sprintf("%.1f", ch.Score), ts,
			})
		}
		w.Flush()
	default:
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="compliance-report-%s.json"`, timestamp))
		c.Header("Content-Type", "application/json")
		report := map[string]interface{}{
			"exported_at":   time.Now(),
			"framework":     framework,
			"total_checks":  total,
			"passed":        passed,
			"failed":        failed,
			"score_percent": scorePercent,
			"checks":        checks,
		}
		enc := json.NewEncoder(c.Writer)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	}
}

// ExportSummary handles GET /api/v1/compliance/export/summary
// Returns per-framework aggregated compliance data from compliance_checks table.
// Falls back to empty response if the table does not exist.
func (h *ComplianceExportHandler) ExportSummary(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT framework, COUNT(*) as total,
                SUM(CASE WHEN status IN ('pass','passed') THEN 1 ELSE 0 END) as passed,
                AVG(score) as avg_score
         FROM compliance_checks GROUP BY framework ORDER BY framework`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"frameworks": []interface{}{}, "note": "データなし"})
		return
	}
	defer rows.Close()
	type FrameworkSummary struct {
		Framework string  `json:"framework"`
		Total     int     `json:"total"`
		Passed    int     `json:"passed"`
		AvgScore  float64 `json:"avg_score"`
	}
	var summaries []FrameworkSummary
	for rows.Next() {
		var s FrameworkSummary
		if err := rows.Scan(&s.Framework, &s.Total, &s.Passed, &s.AvgScore); err != nil {
			continue
		}
		summaries = append(summaries, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if summaries == nil {
		summaries = []FrameworkSummary{}
	}
	c.JSON(http.StatusOK, gin.H{"frameworks": summaries})
}

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

	// Fetch compliance checks.
	//
	// 旧実装は `compliance_checks` を引いていたが、この名前のテーブルはマイグレーションの
	// どこにも作られていない。クエリは実 DB で必ずエラーになり、下の「テーブルが存在しないか
	// 空です」に落ちるため、**このエンドポイントは常に空のレポートを返していた**。
	// 監査向けのエクスポートが「該当なし」を返し続けるのは、無い証拠を出すのと同じで
	// 一番まずい壊れ方をする。
	//
	// 実在して実際に埋まっているのは `compliance_scores` (042)。
	// POST /compliance/score が agent×framework で upsert し、チェック単位の結果は
	// details JSONB の checks 配列（{id,title,severity,passed}）に入る。横持ちなので
	// LATERAL で展開してからチェック単位の行にする。
	//
	// 出力の粒度が agent×control になるため、行に agent_id が増えている。旧実装の
	// `id`（行の UUID）は展開後の行に対応するものが無いので落とした。**この変更で
	// 壊れる利用側は無い** — このエンドポイントは一度も中身を返したことがない。
	const checkRows = `
		SELECT cs.agent_id,
		       cs.framework,
		       COALESCE(NULLIF(chk->>'id',''), '(unknown)')            AS control_id,
		       COALESCE(NULLIF(chk->>'title',''), chk->>'id', '')      AS title,
		       CASE WHEN (chk->>'passed')::boolean THEN 'pass' ELSE 'fail' END AS status,
		       CASE WHEN (chk->>'passed')::boolean THEN 100 ELSE 0 END::float8 AS score,
		       cs.computed_at,
		       chk AS details
		FROM compliance_scores cs,
		     LATERAL jsonb_array_elements(COALESCE(cs.details->'checks', '[]'::jsonb)) AS chk
		WHERE jsonb_typeof(COALESCE(cs.details->'checks', '[]'::jsonb)) = 'array'
		  AND chk->>'passed' IS NOT NULL`

	query := checkRows + ` ORDER BY cs.framework, cs.agent_id, control_id`
	args := []interface{}{}
	if framework != "" {
		query = checkRows + ` AND cs.framework = $1 ORDER BY cs.agent_id, control_id`
		args = append(args, framework)
	}

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		// 「テーブルが存在しないか空です」は2つの別々のことを1つにまとめて
		// いました。前者は本当に対象が無く、後者は読めなかっただけです。
		// これは監査に提出される書き出しなので、後者を空のレポートとして
		// 出すと、統制が0件だったという記録が残ります。
		ReadFailure(c, err, gin.H{
			"exported_at": time.Now(),
			"framework":   framework,
			"checks":      []interface{}{},
			"note":        "compliance_checks テーブルがまだ作成されていません",
		})
		return
	}
	defer rows.Close()

	type Check struct {
		AgentID       string          `json:"agent_id"`
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
		if err := rows.Scan(&ch.AgentID, &ch.Framework, &ch.ControlID, &ch.Title, &ch.Status, &ch.Score, &ch.LastCheckedAt, &ch.Details); err != nil {
			// pgx は Scan の失敗で Rows を fatal 化して閉じる。continue しても残りは
			// 読めないので、切り詰めたレポートを完全なものとして出さないよう抜ける。
			slog.Error("コンプライアンス行の走査に失敗しました（レポートは不完全）", "error", err)
			break
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
		// 書き出しが途中で切れたら、短いファイルを渡しません。
		// **統制が「未確認」なのか「読めなかった」のか、ファイルからは
		// 区別できません。**
		slog.Error("compliance export: rows.Err", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コンプライアンス結果の読み出しが途中で失敗しました。書き出しは中止します"})
		return
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
		_ = w.Write([]string{"agent_id", "framework", "control_id", "title", "status", "score", "last_checked_at"})
		for _, ch := range checks {
			ts := ""
			if ch.LastCheckedAt != nil {
				ts = ch.LastCheckedAt.Format(time.RFC3339)
			}
			_ = w.Write([]string{
				ch.AgentID, ch.Framework, ch.ControlID, ch.Title, ch.Status,
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
// Returns per-framework aggregated compliance data from compliance_scores.
func (h *ComplianceExportHandler) ExportSummary(c *gin.Context) {
	// Export と同じ理由で `compliance_checks` から `compliance_scores` へ差し替える
	// （旧テーブルは実在せず、この集計は常に空だった）。旧実装の AVG(score) は
	// コントロール単位のスコア平均で、展開後の 100/0 の平均は合格率に一致する。
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT cs.framework,
		        COUNT(*)                                                        AS total,
		        SUM(CASE WHEN (chk->>'passed')::boolean THEN 1 ELSE 0 END)      AS passed,
		        AVG(CASE WHEN (chk->>'passed')::boolean THEN 100 ELSE 0 END)::float8 AS avg_score
		 FROM compliance_scores cs,
		      LATERAL jsonb_array_elements(COALESCE(cs.details->'checks', '[]'::jsonb)) AS chk
		 WHERE jsonb_typeof(COALESCE(cs.details->'checks', '[]'::jsonb)) = 'array'
		   AND chk->>'passed' IS NOT NULL
		 GROUP BY cs.framework ORDER BY cs.framework`)
	if err != nil {
		ReadFailure(c, err, gin.H{"frameworks": []interface{}{},
			"note": "compliance_checks テーブルがまだ作成されていません"})
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
			slog.Error("コンプライアンス集計の走査に失敗しました（集計は不完全）", "error", err)
			break
		}
		summaries = append(summaries, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("compliance summary: rows.Err", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コンプライアンス集計の読み出しが途中で失敗しました"})
		return
	}
	if summaries == nil {
		summaries = []FrameworkSummary{}
	}
	c.JSON(http.StatusOK, gin.H{"frameworks": summaries})
}

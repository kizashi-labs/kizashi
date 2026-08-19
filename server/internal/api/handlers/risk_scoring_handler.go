package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RiskScoringHandler struct{ pool *pgxpool.Pool }

func NewRiskScoringHandler(pool *pgxpool.Pool) *RiskScoringHandler {
	return &RiskScoringHandler{pool: pool}
}

func (h *RiskScoringHandler) ListModels(c *gin.Context) {
	models := []gin.H{
		{"id": uuid.New(), "name": "エンドポイントリスクモデル", "entity_type": "endpoint", "version": "2.3", "active": true, "factors": []string{"脆弱性スコア", "パッチ状態", "マルウェア検出履歴", "設定不備"}},
		{"id": uuid.New(), "name": "ユーザーリスクモデル", "entity_type": "user", "version": "1.8", "active": true, "factors": []string{"行動異常", "特権アクセス", "認証失敗", "データアクセスパターン"}},
		{"id": uuid.New(), "name": "ネットワークリスクモデル", "entity_type": "network", "version": "1.2", "active": true, "factors": []string{"異常トラフィック", "C2通信", "ポートスキャン", "データ流出"}},
	}
	c.JSON(http.StatusOK, gin.H{"models": models, "total": len(models)})
}

func (h *RiskScoringHandler) GetScores(c *gin.Context) {
	ctx := c.Request.Context()
	entityType := c.Query("entity_type")

	exists := tableIsThere(ctx, h.pool, "risk_scores")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"scores": []interface{}{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT entity_id, entity_name, entity_type, score, previous_score, risk_level, trend, calculated_at FROM risk_scores WHERE ($1 = '' OR entity_type = $1) ORDER BY score DESC LIMIT 100`,
		entityType,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var scores []gin.H
	for rows.Next() {
		var entityID, entityName, eType, riskLevel, trend string
		var score, previousScore float64
		var calculatedAt time.Time
		if err := rows.Scan(&entityID, &entityName, &eType, &score, &previousScore, &riskLevel, &trend, &calculatedAt); err != nil {
			continue
		}
		scores = append(scores, gin.H{
			"entity_id":      entityID,
			"entity_name":    entityName,
			"entity_type":    eType,
			"score":          score,
			"previous_score": previousScore,
			"risk_level":     riskLevel,
			"trend":          trend,
			"calculated_at":  calculatedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if scores == nil {
		scores = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"scores": scores, "total": len(scores)})
}

func (h *RiskScoringHandler) RecalculateScores(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "リスクスコア再計算を開始しました", "started_at": time.Now(), "estimated_seconds": 30})
}

func (h *RiskScoringHandler) GetOrganizationRisk(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "risk_scores")
	if !exists {
		c.JSON(http.StatusOK, gin.H{
			"overall_risk_score": 0,
			"risk_level":         "unknown",
			"trend":              "stable",
			"by_entity_type":     []interface{}{},
			"top_risks":          []interface{}{},
			"calculated_at":      time.Now().Format(time.RFC3339),
		})
		return
	}

	var overallScore float64
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COALESCE(AVG(score), 0) FROM risk_scores`).Scan(&overallScore)) {
		return
	}

	riskLevel := "low"
	if overallScore >= 80 {
		riskLevel = "critical"
	} else if overallScore >= 60 {
		riskLevel = "high"
	} else if overallScore >= 30 {
		riskLevel = "medium"
	}

	rows, err := h.pool.Query(ctx, `
		SELECT entity_type,
		       COALESCE(AVG(score), 0) AS avg_score,
		       COUNT(*) FILTER (WHERE risk_level = 'critical') AS critical,
		       COUNT(*) FILTER (WHERE risk_level = 'high') AS high,
		       COUNT(*) FILTER (WHERE risk_level = 'medium') AS medium,
		       COUNT(*) FILTER (WHERE risk_level = 'low') AS low
		FROM risk_scores
		GROUP BY entity_type
	`)
	var byEntityType []gin.H
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var eType string
			var avgScore float64
			var crit, hi, med, lo int
			if err := rows.Scan(&eType, &avgScore, &crit, &hi, &med, &lo); err != nil {
				continue
			}
			byEntityType = append(byEntityType, gin.H{
				"type": eType, "avg_score": avgScore,
				"critical": crit, "high": hi, "medium": med, "low": lo,
			})
		}
		if err := rows.Err(); err != nil {
			slog.Warn("risk_scoring byEntityType iteration failed", "error", err)
		}
	}
	if byEntityType == nil {
		byEntityType = []gin.H{}
	}

	topRows, err := h.pool.Query(ctx, `SELECT entity_name, score, risk_level FROM risk_scores ORDER BY score DESC LIMIT 3`)
	var topRisks []gin.H
	if err == nil {
		defer topRows.Close()
		for topRows.Next() {
			var name, level string
			var score float64
			if err := topRows.Scan(&name, &score, &level); err != nil {
				continue
			}
			topRisks = append(topRisks, gin.H{"entity": name, "score": score, "risk_level": level})
		}
		if err := topRows.Err(); err != nil {
			slog.Warn("risk_scoring topRisks iteration failed", "error", err)
		}
	}
	if topRisks == nil {
		topRisks = []gin.H{}
	}

	c.JSON(http.StatusOK, gin.H{
		"overall_risk_score": overallScore,
		"risk_level":         riskLevel,
		"trend":              "stable",
		"by_entity_type":     byEntityType,
		"top_risks":          topRisks,
		"calculated_at":      time.Now().Format(time.RFC3339),
	})
}

func (h *RiskScoringHandler) GetMetrics(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "risk_score_history")

	if !exists {
		// Fall back to risk_scores aggregated by date if history table absent
		scoresExists := tableIsThere(ctx, h.pool, "risk_scores")
		if !scoresExists {
			c.JSON(http.StatusOK, gin.H{"metrics": []interface{}{}})
			return
		}
		rows, err := h.pool.Query(ctx, `
			SELECT DATE(calculated_at) AS day,
			       COALESCE(AVG(score), 0),
			       COUNT(*) FILTER (WHERE risk_level = 'critical'),
			       COUNT(*) FILTER (WHERE risk_level = 'high')
			FROM risk_scores
			WHERE calculated_at >= NOW() - INTERVAL '30 days'
			GROUP BY day
			ORDER BY day ASC
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
			return
		}
		defer rows.Close()
		var metrics []gin.H
		for rows.Next() {
			var day time.Time
			var avgScore float64
			var critCount, highCount int
			if err := rows.Scan(&day, &avgScore, &critCount, &highCount); err != nil {
				continue
			}
			metrics = append(metrics, gin.H{
				"date":           day.Format("2006-01-02"),
				"avg_score":      avgScore,
				"critical_count": critCount,
				"high_count":     highCount,
			})
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		if metrics == nil {
			metrics = []gin.H{}
		}
		c.JSON(http.StatusOK, gin.H{"metrics": metrics})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT DATE(recorded_at) AS day,
		       COALESCE(AVG(score), 0),
		       COUNT(*) FILTER (WHERE risk_level = 'critical'),
		       COUNT(*) FILTER (WHERE risk_level = 'high')
		FROM risk_score_history
		WHERE recorded_at >= NOW() - INTERVAL '30 days'
		GROUP BY day
		ORDER BY day ASC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
		return
	}
	defer rows.Close()
	var metrics []gin.H
	for rows.Next() {
		var day time.Time
		var avgScore float64
		var critCount, highCount int
		if err := rows.Scan(&day, &avgScore, &critCount, &highCount); err != nil {
			continue
		}
		metrics = append(metrics, gin.H{
			"date":           day.Format("2006-01-02"),
			"avg_score":      avgScore,
			"critical_count": critCount,
			"high_count":     highCount,
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if metrics == nil {
		metrics = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}

// scoreToRiskLevel はリスクスコア (0–100) をリスクレベル文字列に変換する純粋関数。
// critical: >=80, high: >=60, medium: >=30, low: <30
func scoreToRiskLevel(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

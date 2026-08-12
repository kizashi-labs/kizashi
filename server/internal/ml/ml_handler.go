package ml

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MLHandler exposes ML analytics via REST.
type MLHandler struct {
	engine *BehavioralEngine
}

// NewMLHandler creates a new MLHandler.
func NewMLHandler(engine *BehavioralEngine) *MLHandler {
	return &MLHandler{engine: engine}
}

// GetUEBAScores handles GET /api/v1/admin/ml/ueba-scores
func (h *MLHandler) GetUEBAScores(c *gin.Context) {
	top := h.engine.UEBA.GetTopRiskyEntities(20)
	type Score struct {
		EntityID       string  `json:"entity_id"`
		EntityType     string  `json:"entity_type"`
		RiskScore      float64 `json:"risk_score"`
		AlertCount     int     `json:"alert_count"`
		FailedLogins   int     `json:"failed_logins"`
		DataTransferGB float64 `json:"data_transfer_gb"`
	}
	scores := make([]Score, len(top))
	for i, p := range top {
		scores[i] = Score{
			EntityID:       p.EntityID,
			EntityType:     p.EntityType,
			RiskScore:      p.RiskScore,
			AlertCount:     p.AlertCount,
			FailedLogins:   p.FailedLogins,
			DataTransferGB: p.DataTransferGB,
		}
	}
	c.JSON(http.StatusOK, gin.H{"scores": scores, "total": len(scores)})
}

// AnalyzeProcessLineage handles POST /api/v1/admin/ml/analyze-lineage
func (h *MLHandler) AnalyzeProcessLineage(c *gin.Context) {
	var req struct {
		AgentID    string `json:"agent_id"`
		ParentProc string `json:"parent_process" binding:"required"`
		ChildProc  string `json:"child_process" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	detections := h.engine.ProcessEvent(req.AgentID, req.ParentProc, req.ChildProc, 0, 0, "")
	c.JSON(http.StatusOK, gin.H{
		"suspicious": len(detections) > 0,
		"detections": detections,
	})
}

// AnomalyScore handles POST /api/v1/admin/ml/anomaly-score
func (h *MLHandler) AnomalyScore(c *gin.Context) {
	var req struct {
		Features []float64 `json:"features" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	score := h.engine.Forest.Score(req.Features)
	c.JSON(http.StatusOK, gin.H{
		"score":      score,
		"is_anomaly": score > 0.6,
	})
}

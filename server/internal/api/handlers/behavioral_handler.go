package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/behavioral"
	"github.com/gin-gonic/gin"
)

type BehavioralHandler struct {
	engine *behavioral.Engine
}

func NewBehavioralHandler(engine *behavioral.Engine) *BehavioralHandler {
	return &BehavioralHandler{engine: engine}
}

// BuildBaseline builds a behavioral baseline for an agent
// POST /api/v1/admin/behavioral/baselines/:agent_id
func (h *BehavioralHandler) BuildBaseline(c *gin.Context) {
	agentID := c.Param("agent_id")
	days, _ := strconv.Atoi(c.DefaultQuery("days", "14"))

	baseline, err := h.engine.BuildBaseline(c.Request.Context(), agentID, days)
	if err != nil {
		// **端末が無いことは、障害ではありません。** 以前はどちらも 500 と
		// 「データベース操作に失敗しました」で、ID を打ち間違えた人は
		// サーバが壊れたと読みます。
		if errors.Is(err, behavioral.ErrAgentNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, baseline)
}

// GetBaseline returns the baseline for an agent
// GET /api/v1/admin/behavioral/baselines/:agent_id
func (h *BehavioralHandler) GetBaseline(c *gin.Context) {
	agentID := c.Param("agent_id")
	baseline, ok := h.engine.GetBaseline(agentID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "ベースラインが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, baseline)
}

// GetAllBaselines returns all baselines
// GET /api/v1/admin/behavioral/baselines
func (h *BehavioralHandler) GetAllBaselines(c *gin.Context) {
	baselines := h.engine.GetAllBaselines()
	c.JSON(http.StatusOK, gin.H{"baselines": baselines, "count": len(baselines)})
}

// GetAnomalies returns recent behavioral anomalies
// GET /api/v1/admin/behavioral/anomalies
func (h *BehavioralHandler) GetAnomalies(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	anomalies := h.engine.GetRecentAnomalies(limit)
	c.JSON(http.StatusOK, gin.H{"anomalies": anomalies, "count": len(anomalies)})
}

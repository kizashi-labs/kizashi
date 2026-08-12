package handlers

import (
	"errors"
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EndpointBaselineHandler は /api/v1/endpoints/baselines を処理する。
type EndpointBaselineHandler struct {
	bStore *store.BehavioralBaselineStore
}

// NewEndpointBaselineHandler creates a new EndpointBaselineHandler.
func NewEndpointBaselineHandler(pool *pgxpool.Pool) *EndpointBaselineHandler {
	return &EndpointBaselineHandler{
		bStore: store.NewBehavioralBaselineStore(pool),
	}
}

// ListBaselines GET /api/v1/endpoints/baselines
func (h *EndpointBaselineHandler) ListBaselines(c *gin.Context) {
	baselines, err := h.bStore.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if baselines == nil {
		baselines = []*store.EndpointBaseline{}
	}
	c.JSON(http.StatusOK, baselines)
}

// GetBaseline GET /api/v1/endpoints/baselines/:id
func (h *EndpointBaselineHandler) GetBaseline(c *gin.Context) {
	id := c.Param("id")
	b, err := h.bStore.GetByAgentID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "baseline not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, b)
}

// GetConfig GET /api/v1/endpoints/baselines/config
func (h *EndpointBaselineHandler) GetConfig(c *gin.Context) {
	cfg, err := h.bStore.GetConfig(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// SaveConfig PUT /api/v1/endpoints/baselines/config
func (h *EndpointBaselineHandler) SaveConfig(c *gin.Context) {
	var req store.BaselineConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.LearningPeriodDays < 7 || req.LearningPeriodDays > 90 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "learning_period_days must be between 7 and 90"})
		return
	}
	if err := h.bStore.SaveConfig(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, req)
}

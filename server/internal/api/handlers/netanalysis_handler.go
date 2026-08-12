package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/netanalysis"
	"github.com/gin-gonic/gin"
)

// NetAnalysisHandler exposes network traffic analysis endpoints.
type NetAnalysisHandler struct {
	analyzer *netanalysis.Analyzer
}

// NewNetAnalysisHandler creates a NetAnalysisHandler.
func NewNetAnalysisHandler(analyzer *netanalysis.Analyzer) *NetAnalysisHandler {
	return &NetAnalysisHandler{analyzer: analyzer}
}

// TopConnections handles GET /api/v1/admin/network/top-connections
func (h *NetAnalysisHandler) TopConnections(c *gin.Context) {
	hours, limit := parseHoursLimit(c, 24, 20)
	conns, err := h.analyzer.GetTopConnections(c.Request.Context(), hours, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "接続情報の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"connections": conns, "total": len(conns)})
}

// PortAnalysis handles GET /api/v1/admin/network/port-analysis
func (h *NetAnalysisHandler) PortAnalysis(c *gin.Context) {
	hours, _ := parseHoursLimit(c, 24, 0)
	ports, err := h.analyzer.GetPortAnalysis(c.Request.Context(), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポート分析の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ports": ports, "total": len(ports)})
}

// BeaconingDetection handles GET /api/v1/admin/network/beaconing
func (h *NetAnalysisHandler) BeaconingDetection(c *gin.Context) {
	hours, _ := parseHoursLimit(c, 24, 0)
	candidates, err := h.analyzer.GetBeaconingDetection(c.Request.Context(), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ビーコン検出の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"candidates": candidates, "total": len(candidates)})
}

// NetworkStats handles GET /api/v1/admin/network/stats
func (h *NetAnalysisHandler) NetworkStats(c *gin.Context) {
	hours, _ := parseHoursLimit(c, 24, 0)
	stats, err := h.analyzer.GetNetworkStats(c.Request.Context(), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ネットワーク統計の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// parseHoursLimit extracts ?hours= and ?limit= query parameters with defaults.
func parseHoursLimit(c *gin.Context, defaultHours, defaultLimit int) (int, int) {
	hours, err := strconv.Atoi(c.DefaultQuery("hours", strconv.Itoa(defaultHours)))
	if err != nil || hours <= 0 || hours > 720 {
		hours = defaultHours
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", strconv.Itoa(defaultLimit)))
	if err != nil || limit <= 0 || limit > 200 {
		limit = defaultLimit
	}
	return hours, limit
}

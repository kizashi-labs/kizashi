package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/geoip"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GeoIPHandler provides threat map and IP lookup endpoints.
type GeoIPHandler struct {
	locator *geoip.Locator
	pool    *pgxpool.Pool
}

// NewGeoIPHandler creates a new GeoIPHandler.
func NewGeoIPHandler(pool *pgxpool.Pool) *GeoIPHandler {
	return &GeoIPHandler{
		locator: geoip.NewLocator(),
		pool:    pool,
	}
}

// GetThreatMapData handles GET /api/v1/threat-map/data?hours=24.
func (h *GeoIPHandler) GetThreatMapData(c *gin.Context) {
	hours := 24
	if v := c.Query("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720 {
			hours = n
		}
	}
	entries, err := h.locator.GetThreatMapData(c.Request.Context(), h.pool, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get threat map data"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": entries, "hours": hours})
}

// GetTopThreats handles GET /api/v1/threat-map/top-threats.
func (h *GeoIPHandler) GetTopThreats(c *gin.Context) {
	threats, err := h.locator.GetTopThreats(c.Request.Context(), h.pool)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get top threats"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"threats": threats})
}

// LookupIP handles POST /api/v1/threat-map/lookup.
func (h *GeoIPHandler) LookupIP(c *gin.Context) {
	var req struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	loc := h.locator.Lookup(req.IP)
	c.JSON(http.StatusOK, loc)
}

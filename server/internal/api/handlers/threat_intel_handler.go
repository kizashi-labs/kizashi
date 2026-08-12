package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/threatintel"
	"github.com/gin-gonic/gin"
)

// ThreatIntelHandler provides endpoints for managing threat intelligence feeds and IOC lookups.
type ThreatIntelHandler struct {
	manager *threatintel.FeedManager
}

// NewThreatIntelHandler creates a new ThreatIntelHandler.
func NewThreatIntelHandler(manager *threatintel.FeedManager) *ThreatIntelHandler {
	return &ThreatIntelHandler{manager: manager}
}

// ListFeeds returns all configured threat intelligence feeds.
// GET /api/v1/admin/threat-intel/feeds
func (h *ThreatIntelHandler) ListFeeds(c *gin.Context) {
	feeds := h.manager.GetAllFeeds()
	c.JSON(http.StatusOK, gin.H{"feeds": feeds, "total": len(feeds)})
}

// AddFeed creates a new threat intelligence feed.
// POST /api/v1/admin/threat-intel/feeds
func (h *ThreatIntelHandler) AddFeed(c *gin.Context) {
	var req struct {
		Name             string `json:"name"              binding:"required"`
		Type             string `json:"type"              binding:"required"`
		URL              string `json:"url"`
		APIKey           string `json:"api_key"`
		Enabled          bool   `json:"enabled"`
		FetchIntervalMin int    `json:"fetch_interval_min"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	feed := &threatintel.Feed{
		Name:             req.Name,
		Type:             req.Type,
		URL:              req.URL,
		APIKey:           req.APIKey,
		Enabled:          req.Enabled,
		FetchIntervalMin: req.FetchIntervalMin,
	}
	if err := h.manager.AddFeed(feed); err != nil {
		slog.Error("threat_intel: failed to add feed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add feed"})
		return
	}
	c.JSON(http.StatusCreated, feed)
}

// UpdateFeed updates an existing feed (enable/disable, change interval, etc.).
// PUT /api/v1/admin/threat-intel/feeds/:id
func (h *ThreatIntelHandler) UpdateFeed(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name             string `json:"name"`
		URL              string `json:"url"`
		APIKey           string `json:"api_key"`
		Enabled          bool   `json:"enabled"`
		FetchIntervalMin int    `json:"fetch_interval_min"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := &threatintel.Feed{
		Name:             req.Name,
		URL:              req.URL,
		APIKey:           req.APIKey,
		Enabled:          req.Enabled,
		FetchIntervalMin: req.FetchIntervalMin,
	}
	updated, err := h.manager.UpdateFeed(id, updates)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// RemoveFeed deletes a feed by ID.
// DELETE /api/v1/admin/threat-intel/feeds/:id
func (h *ThreatIntelHandler) RemoveFeed(c *gin.Context) {
	id := c.Param("id")
	if err := h.manager.RemoveFeed(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// SyncFeed triggers a manual synchronization of a specific feed.
// POST /api/v1/admin/threat-intel/feeds/:id/sync
func (h *ThreatIntelHandler) SyncFeed(c *gin.Context) {
	id := c.Param("id")
	start := time.Now()
	synced, err := h.manager.FetchFeed(c.Request.Context(), id)
	if err != nil {
		slog.Warn("threat_intel: manual sync failed", "feed_id", id, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	duration := time.Since(start)
	c.JSON(http.StatusOK, gin.H{
		"synced":   synced,
		"duration": duration.String(),
	})
}

// ListIOCs returns a paginated list of IOCs with optional type filter.
// GET /api/v1/admin/threat-intel/iocs?limit=50&offset=0&type=ip
func (h *ThreatIntelHandler) ListIOCs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	iocType := c.Query("type")
	var iocs []*threatintel.IOC
	var total int

	if iocType != "" {
		iocs, total = h.manager.GetIOCsByType(iocType, limit, offset)
	} else {
		iocs, total = h.manager.GetAllIOCs(limit, offset)
	}

	c.JSON(http.StatusOK, gin.H{
		"iocs":   iocs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// LookupIOC looks up a value against all IOC types.
// POST /api/v1/admin/threat-intel/lookup
// Body: {"value": "1.2.3.4"}
func (h *ThreatIntelHandler) LookupIOC(c *gin.Context) {
	var req struct {
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Try all IOC types in order
	if ioc := h.manager.LookupIP(req.Value); ioc != nil {
		c.JSON(http.StatusOK, gin.H{"found": true, "ioc": ioc})
		return
	}
	if ioc := h.manager.LookupDomain(req.Value); ioc != nil {
		c.JSON(http.StatusOK, gin.H{"found": true, "ioc": ioc})
		return
	}
	if ioc := h.manager.LookupHash(req.Value); ioc != nil {
		c.JSON(http.StatusOK, gin.H{"found": true, "ioc": ioc})
		return
	}
	if ioc := h.manager.LookupURL(req.Value); ioc != nil {
		c.JSON(http.StatusOK, gin.H{"found": true, "ioc": ioc})
		return
	}

	c.JSON(http.StatusOK, gin.H{"found": false})
}

// GetStats returns aggregate statistics about feeds and IOCs.
// GET /api/v1/admin/threat-intel/stats
func (h *ThreatIntelHandler) GetStats(c *gin.Context) {
	stats := h.manager.GetStats()
	c.JSON(http.StatusOK, stats)
}

// SyncPublicFeeds triggers a manual sync of all public (no-auth) threat intel feeds.
// POST /api/v1/admin/threat-intel/sync-public
func (h *ThreatIntelHandler) SyncPublicFeeds(c *gin.Context) {
	abuseKey := c.Query("abuseipdb_key")

	total, sources := threatintel.SyncAllPublicFeeds(c.Request.Context(), h.manager, abuseKey)

	sourceList := make([]string, 0, len(sources))
	for src := range sources {
		sourceList = append(sourceList, src)
	}

	c.JSON(http.StatusOK, gin.H{
		"synced":  total,
		"sources": sourceList,
		"details": sources,
	})
}

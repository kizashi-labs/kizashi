package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/edr-platform/server/internal/watchlist"
	"github.com/gin-gonic/gin"
)

// WatchlistHandler exposes CRUD + check endpoints for the alert watchlist.
type WatchlistHandler struct {
	store *watchlist.Store
}

// NewWatchlistHandler creates a WatchlistHandler.
func NewWatchlistHandler(store *watchlist.Store) *WatchlistHandler {
	return &WatchlistHandler{store: store}
}

// List handles GET /api/v1/admin/watchlist
func (h *WatchlistHandler) List(c *gin.Context) {
	entityType := c.Query("type")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	search := c.Query("search")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	entries, total, err := h.store.List(c.Request.Context(), entityType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ウォッチリストの取得に失敗しました"})
		return
	}

	// Apply search filter and manual pagination in-process
	if search != "" {
		filtered := entries[:0]
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.EntityValue), strings.ToLower(search)) || strings.Contains(strings.ToLower(e.Label), strings.ToLower(search)) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
		total = len(filtered)
	}

	if offset >= len(entries) {
		entries = nil
	} else {
		end := offset + limit
		if end > len(entries) {
			end = len(entries)
		}
		entries = entries[offset:end]
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// Add handles POST /api/v1/admin/watchlist
func (h *WatchlistHandler) Add(c *gin.Context) {
	var entry watchlist.WatchlistEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if entry.EntityType == "" || entry.EntityValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity_type と entity_value は必須です"})
		return
	}
	entry.AddedBy = c.GetString("user_id")
	entry.Enabled = true

	created, err := h.store.Add(c.Request.Context(), &entry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エントリの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// Remove handles DELETE /api/v1/admin/watchlist/:id
func (h *WatchlistHandler) Remove(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Remove(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エントリの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// Update handles PUT /api/v1/admin/watchlist/:id
func (h *WatchlistHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var entry watchlist.WatchlistEntry
	if err := c.ShouldBindJSON(&entry); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.store.Update(c.Request.Context(), id, &entry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エントリの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// Check handles POST /api/v1/admin/watchlist/check
func (h *WatchlistHandler) Check(c *gin.Context) {
	var req struct {
		Type  string `json:"type" binding:"required"`
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	entry, found := h.store.Check(req.Type, req.Value)
	if !found {
		c.JSON(http.StatusOK, gin.H{"found": false, "entry": nil})
		return
	}
	// Record the hit asynchronously
	h.store.RecordHit(c.Request.Context(), entry.ID)
	c.JSON(http.StatusOK, gin.H{"found": true, "entry": entry})
}

// Stats handles GET /api/v1/admin/watchlist/stats
func (h *WatchlistHandler) Stats(c *gin.Context) {
	stats := h.store.GetStats(c.Request.Context())
	c.JSON(http.StatusOK, stats)
}

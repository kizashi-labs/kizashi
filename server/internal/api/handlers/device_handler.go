package handlers

// DeviceHandler provides REST endpoints for USB/external device events.
// Events are ingested by the gRPC layer when an agent reports a
// "device_event:<uuid>:<json>" envelope; this handler exposes them for
// the dashboard and security investigations.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// DeviceHandler handles device event API requests.
type DeviceHandler struct {
	store *store.DeviceEventStore
}

// NewDeviceHandler creates a new DeviceHandler.
func NewDeviceHandler(s *store.DeviceEventStore) *DeviceHandler {
	return &DeviceHandler{store: s}
}

// List returns device events with pagination and optional filtering.
// GET /api/v1/device-events
//
// Query parameters:
//
//	agent_id   — filter by agent
//	action     — "connected" or "disconnected"
//	type       — device_type (e.g. "usb", "storage")
//	since      — RFC3339 lower bound on created_at
//	until      — RFC3339 upper bound on created_at
//	limit      — page size (default 50, max 500)
//	offset     — row offset (default 0)
//	page       — 1-based page number (alternative to offset)
func (h *DeviceHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page > 1 && offset == 0 {
		offset = (page - 1) * limit
	}

	f := store.DeviceEventFilter{
		AgentID:    c.Query("agent_id"),
		Action:     c.Query("action"),
		DeviceType: c.Query("type"),
		Limit:      limit,
		Offset:     offset,
	}

	if raw := c.Query("since"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			f.Since = &t
		}
	}
	if raw := c.Query("until"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			f.Until = &t
		}
	}

	events, total, err := h.store.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "デバイスイベント一覧の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     events,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// Stats returns device event counts grouped by action and device_type for the
// last 24 hours (or a custom window via the ?hours= query parameter).
// GET /api/v1/device-events/stats
//
// Query parameters:
//
//	hours — look-back window in hours (default 24)
func (h *DeviceHandler) Stats(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours <= 0 || hours > 720 {
		hours = 24
	}

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	rows, err := h.store.Stats(c.Request.Context(), since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "デバイス統計の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  rows,
		"since": since.Format(time.RFC3339),
		"hours": hours,
	})
}

package handlers

import (
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// MaintenanceWindowHandler provides maintenance window management endpoints.
type MaintenanceWindowHandler struct {
	store *store.MaintenanceWindowStore
}

// NewMaintenanceWindowHandler creates a new MaintenanceWindowHandler.
func NewMaintenanceWindowHandler(s *store.MaintenanceWindowStore) *MaintenanceWindowHandler {
	return &MaintenanceWindowHandler{store: s}
}

// List returns all maintenance windows.
// GET /api/v1/admin/maintenance-windows
func (h *MaintenanceWindowHandler) List(c *gin.Context) {
	windows, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "メンテナンスウィンドウ一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": windows, "total": len(windows)})
}

// Create adds a new maintenance window.
// POST /api/v1/admin/maintenance-windows
func (h *MaintenanceWindowHandler) Create(c *gin.Context) {
	var req struct {
		Name                  string   `json:"name"                   binding:"required"`
		Description           string   `json:"description"`
		StartTime             string   `json:"start_time"             binding:"required"`
		EndTime               string   `json:"end_time"               binding:"required"`
		Recurring             bool     `json:"recurring"`
		RecurrencePattern     string   `json:"recurrence_pattern"`
		SuppressAlerts        bool     `json:"suppress_alerts"`
		SuppressNotifications bool     `json:"suppress_notifications"`
		AffectedAgents        []string `json:"affected_agents"`
		AffectedGroups        []string `json:"affected_groups"`
		Enabled               *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, start_time, end_time は必須です"})
		return
	}

	startTime, err := time.Parse(time.RFC3339, req.StartTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start_time の形式が不正です（RFC3339形式）"})
		return
	}
	endTime, err := time.Parse(time.RFC3339, req.EndTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "end_time の形式が不正です（RFC3339形式）"})
		return
	}
	if !endTime.After(startTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "end_time は start_time より後である必要があります"})
		return
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	suppressAlerts := true
	if !req.SuppressAlerts {
		suppressAlerts = req.SuppressAlerts
	}
	suppressNotifications := true
	if !req.SuppressNotifications {
		suppressNotifications = req.SuppressNotifications
	}

	w := &store.MaintenanceWindow{
		Name:                  req.Name,
		Description:           req.Description,
		StartTime:             startTime,
		EndTime:               endTime,
		Recurring:             req.Recurring,
		RecurrencePattern:     req.RecurrencePattern,
		SuppressAlerts:        suppressAlerts,
		SuppressNotifications: suppressNotifications,
		AffectedAgents:        req.AffectedAgents,
		AffectedGroups:        req.AffectedGroups,
		Enabled:               enabled,
		CreatedBy:             &uid,
	}

	created, err := h.store.Create(c.Request.Context(), w)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "メンテナンスウィンドウの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// Get retrieves a maintenance window by ID.
// GET /api/v1/admin/maintenance-windows/:id
func (h *MaintenanceWindowHandler) Get(c *gin.Context) {
	id := c.Param("id")
	w, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "メンテナンスウィンドウが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, w)
}

// Update modifies a maintenance window.
// PUT /api/v1/admin/maintenance-windows/:id
func (h *MaintenanceWindowHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name                  string   `json:"name"                   binding:"required"`
		Description           string   `json:"description"`
		StartTime             string   `json:"start_time"             binding:"required"`
		EndTime               string   `json:"end_time"               binding:"required"`
		Recurring             bool     `json:"recurring"`
		RecurrencePattern     string   `json:"recurrence_pattern"`
		SuppressAlerts        bool     `json:"suppress_alerts"`
		SuppressNotifications bool     `json:"suppress_notifications"`
		AffectedAgents        []string `json:"affected_agents"`
		AffectedGroups        []string `json:"affected_groups"`
		Enabled               bool     `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, start_time, end_time は必須です"})
		return
	}

	startTime, err := time.Parse(time.RFC3339, req.StartTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start_time の形式が不正です（RFC3339形式）"})
		return
	}
	endTime, err := time.Parse(time.RFC3339, req.EndTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "end_time の形式が不正です（RFC3339形式）"})
		return
	}
	if !endTime.After(startTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "end_time は start_time より後である必要があります"})
		return
	}

	w := &store.MaintenanceWindow{
		Name:                  req.Name,
		Description:           req.Description,
		StartTime:             startTime,
		EndTime:               endTime,
		Recurring:             req.Recurring,
		RecurrencePattern:     req.RecurrencePattern,
		SuppressAlerts:        req.SuppressAlerts,
		SuppressNotifications: req.SuppressNotifications,
		AffectedAgents:        req.AffectedAgents,
		AffectedGroups:        req.AffectedGroups,
		Enabled:               req.Enabled,
	}

	updated, err := h.store.Update(c.Request.Context(), id, w)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "メンテナンスウィンドウが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// Delete removes a maintenance window.
// DELETE /api/v1/admin/maintenance-windows/:id
func (h *MaintenanceWindowHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "メンテナンスウィンドウが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "メンテナンスウィンドウを削除しました", "id": id})
}

// GetStatus returns whether any maintenance window is currently active.
// GET /api/v1/admin/maintenance-windows/status
func (h *MaintenanceWindowHandler) GetStatus(c *gin.Context) {
	active, err := h.store.IsActive(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータスの取得に失敗しました"})
		return
	}

	var currentWindow interface{}
	if active {
		windows, err := h.store.ListActive(c.Request.Context())
		if err == nil && len(windows) > 0 {
			currentWindow = windows[0]
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"active":         active,
		"current_window": currentWindow,
	})
}

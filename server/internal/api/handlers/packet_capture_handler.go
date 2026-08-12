package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// PacketCaptureHandler handles packet capture API endpoints.
type PacketCaptureHandler struct {
	store *store.PacketCaptureStore
}

// NewPacketCaptureHandler creates a new PacketCaptureHandler.
func NewPacketCaptureHandler(s *store.PacketCaptureStore) *PacketCaptureHandler {
	return &PacketCaptureHandler{store: s}
}

// List handles GET /api/v1/packet-captures?agent_id=...
func (h *PacketCaptureHandler) List(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_idは必須です"})
		return
	}

	captures, err := h.store.List(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パケットキャプチャ一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": captures, "total": len(captures)})
}

// Create handles POST /api/v1/packet-captures
func (h *PacketCaptureHandler) Create(c *gin.Context) {
	var req struct {
		AgentID         string `json:"agent_id"`
		Name            string `json:"name" binding:"required"`
		Filter          string `json:"filter"`
		InterfaceName   string `json:"interface_name"`
		MaxPackets      int    `json:"max_packets"`
		MaxSizeMB       int    `json:"max_size_mb"`
		DurationSeconds int    `json:"duration_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_idは必須です"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameは必須です"})
		return
	}

	// Apply defaults
	if req.MaxPackets <= 0 {
		req.MaxPackets = 10000
	}
	if req.MaxSizeMB <= 0 {
		req.MaxSizeMB = 100
	}
	if req.DurationSeconds <= 0 {
		req.DurationSeconds = 300
	}

	userID := c.GetString("user_id")
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	pc := store.PacketCapture{
		AgentID:         req.AgentID,
		Name:            req.Name,
		Status:          "pending",
		Filter:          req.Filter,
		InterfaceName:   req.InterfaceName,
		MaxPackets:      req.MaxPackets,
		MaxSizeMB:       req.MaxSizeMB,
		DurationSeconds: req.DurationSeconds,
		CreatedBy:       createdBy,
	}

	created, err := h.store.Create(c.Request.Context(), pc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パケットキャプチャの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// Get handles GET /api/v1/packet-captures/:id
func (h *PacketCaptureHandler) Get(c *gin.Context) {
	id := c.Param("id")
	pc, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "パケットキャプチャが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, pc)
}

// Cancel handles POST /api/v1/packet-captures/:id/cancel
func (h *PacketCaptureHandler) Cancel(c *gin.Context) {
	id := c.Param("id")
	pc, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "パケットキャプチャが見つかりません"})
		return
	}
	if pc.Status != "pending" && pc.Status != "running" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "キャンセルできない状態です"})
		return
	}
	if err := h.store.UpdateStatus(c.Request.Context(), id, "cancelled", nil, nil, nil, nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "キャンセルに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "パケットキャプチャをキャンセルしました"})
}

// Download handles GET /api/v1/packet-captures/:id/download
func (h *PacketCaptureHandler) Download(c *gin.Context) {
	id := c.Param("id")
	pc, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "パケットキャプチャが見つかりません"})
		return
	}
	if pc.FilePath == nil || *pc.FilePath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "キャプチャファイルが存在しません"})
		return
	}
	filePath := *pc.FilePath
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "ファイルが見つかりません"})
		return
	}
	fileName := filepath.Base(filePath)
	c.Header("Content-Disposition", "attachment; filename="+fileName)
	c.Header("Content-Type", "application/vnd.tcpdump.pcap")
	c.File(filePath)
}

// Delete handles DELETE /api/v1/packet-captures/:id
func (h *PacketCaptureHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "パケットキャプチャが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "パケットキャプチャを削除しました"})
}

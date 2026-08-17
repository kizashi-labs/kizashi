package handlers

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// QuarantineHandler manages quarantined file endpoints.
type QuarantineHandler struct {
	Store     *store.QuarantineStore
	Commander *store.CommandStore
}

func NewQuarantineHandler(s *store.QuarantineStore, cmd *store.CommandStore) *QuarantineHandler {
	return &QuarantineHandler{Store: s, Commander: cmd}
}

// List returns quarantined files with optional agent filter.
// GET /api/v1/quarantine?agent_id=xxx&search=xxx&status=quarantined|restored&page=1&per_page=20
func (h *QuarantineHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	f := store.QuarantineFilter{
		AgentID: c.Query("agent_id"),
		Search:  c.Query("search"),
		Status:  c.Query("status"),
	}
	files, total, err := h.Store.List(c.Request.Context(), f, perPage, (page-1)*perPage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "検疫ファイル一覧の取得に失敗しました"})
		return
	}
	if files == nil {
		files = []*store.QuarantinedFile{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     files,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Restore sends a restore command and marks the record as restored.
// POST /api/v1/quarantine/:id/restore
func (h *QuarantineHandler) Restore(c *gin.Context) {
	id := c.Param("id")

	// agent_id and restore_path are optional. The bulk-release UI fires
	// /:id/release without a body, so we look up agent_id from the
	// quarantine record itself when omitted.
	var req struct {
		AgentID     string `json:"agent_id"`
		RestorePath string `json:"restore_path"`
	}
	_ = c.ShouldBindJSON(&req) // body may be empty; ignore parse errors

	if req.AgentID == "" {
		aid, err := h.Store.GetAgentID(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "検疫レコードが見つかりません"})
			return
		}
		req.AgentID = aid
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	// The agent indexes quarantined files by its own local ID, not the
	// server-side UUID. Look that up before issuing the NATS command;
	// without it the agent's Restore handler returns "quarantine ID not found".
	agentQID, err := h.Store.GetAgentQuarantineID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "検疫レコードが見つかりません"})
		return
	}
	if agentQID == "" {
		c.JSON(http.StatusConflict, gin.H{
			"error": "agent側の検疫IDが記録されていません (古いレコードのため復元不可)",
			"id":    id,
			"hint":  "古い検疫レコードはエンドポイントで手動復元してください",
		})
		return
	}

	if h.Commander != nil {
		_ = h.Commander.RestoreFile(c.Request.Context(), req.AgentID, agentQID, req.RestorePath, "")
	}

	if err := h.Store.MarkRestored(c.Request.Context(), id, by); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "検疫レコードが見つからないか、既に復元済みです"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ファイルを復元しました", "id": id})
}

// Delete removes a quarantine record.
// DELETE /api/v1/quarantine/:id
func (h *QuarantineHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "検疫レコードの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "検疫レコードを削除しました", "id": id})
}

// Record creates a quarantine record (typically called by the agent event pipeline).
// POST /api/v1/quarantine
func (h *QuarantineHandler) Record(c *gin.Context) {
	var req struct {
		AgentID           string `json:"agent_id" binding:"required"`
		AlertID           string `json:"alert_id"`
		Path              string `json:"path" binding:"required"`
		FileSize          *int64 `json:"file_size"`
		MD5               string `json:"hash_md5"`
		SHA256            string `json:"hash_sha256"`
		AgentQuarantineID string `json:"quarantine_id"` // agent-local ID, needed for Restore
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_idとpathが必要です"})
		return
	}

	f, err := h.Store.Record(c.Request.Context(), req.AgentID, req.AlertID, req.Path, req.FileSize, req.MD5, req.SHA256, req.AgentQuarantineID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "検疫レコードの作成に失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, f)
}

package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// validatePlaybookActionCount はアクション0件を弾きます。空文字は「問題なし」。
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 検査ファイルに同じ判定の写しが置いてあり、そちらだけが試されて
// いました。
func validatePlaybookActionCount(count int) string {
	if count == 0 {
		return "1つ以上のアクションが必要です"
	}
	return ""
}

// PlaybookHandler provides response playbook endpoints.
type PlaybookHandler struct {
	Store *store.PlaybookStore
}

func NewPlaybookHandler(s *store.PlaybookStore) *PlaybookHandler {
	return &PlaybookHandler{Store: s}
}

// List returns all playbooks.
// GET /api/v1/playbooks?active=true
func (h *PlaybookHandler) List(c *gin.Context) {
	activeOnly := c.Query("active") == "true"
	playbooks, err := h.Store.List(c.Request.Context(), activeOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プレイブック一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": playbooks, "total": len(playbooks)})
}

// Get returns a single playbook with its recent run history.
// GET /api/v1/playbooks/:id
func (h *PlaybookHandler) Get(c *gin.Context) {
	id := c.Param("id")
	pb, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "プレイブックが見つかりません"})
		return
	}
	runs, err := h.Store.ListRuns(c.Request.Context(), id, 20)
	if err != nil {
		// 実行履歴が空だと「一度も動いていない」と読めます。
		ReadFailure(c, err, gin.H{"playbook": pb, "runs": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"playbook": pb, "runs": runs})
}

// Create adds a new playbook.
// POST /api/v1/playbooks
func (h *PlaybookHandler) Create(c *gin.Context) {
	var req struct {
		Name        string                   `json:"name"       binding:"required"`
		Description string                   `json:"description"`
		Conditions  store.PlaybookConditions `json:"conditions"`
		Actions     []store.PlaybookAction   `json:"actions"    binding:"required"`
		IsActive    bool                     `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name と actions は必須です"})
		return
	}
	if msg := validatePlaybookActionCount(len(req.Actions)); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	isActive := req.IsActive
	if !isActive {
		isActive = true // default active
	}

	pb := &store.Playbook{
		Name:        req.Name,
		Description: req.Description,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		IsActive:    isActive,
		CreatedBy:   &uid,
	}
	id, err := h.Store.Insert(c.Request.Context(), pb)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プレイブックの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "プレイブックを作成しました", "id": id})
}

// Update replaces a playbook.
// PUT /api/v1/playbooks/:id
func (h *PlaybookHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        string                   `json:"name"       binding:"required"`
		Description string                   `json:"description"`
		Conditions  store.PlaybookConditions `json:"conditions"`
		Actions     []store.PlaybookAction   `json:"actions"`
		IsActive    bool                     `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if req.Actions == nil {
		req.Actions = []store.PlaybookAction{}
	}
	pb := &store.Playbook{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		IsActive:    req.IsActive,
	}
	if err := h.Store.Update(c.Request.Context(), pb); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プレイブックの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "プレイブックを更新しました", "id": id})
}

// Delete removes a playbook.
// DELETE /api/v1/playbooks/:id
func (h *PlaybookHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "プレイブックが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "プレイブックを削除しました", "id": id})
}

// Toggle enables or disables a playbook.
// PUT /api/v1/playbooks/:id/toggle
func (h *PlaybookHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if err := h.Store.SetActive(c.Request.Context(), id, req.IsActive); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プレイブックの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "プレイブックを更新しました", "id": id, "is_active": req.IsActive})
}

// Runs returns recent execution history for a playbook.
// GET /api/v1/playbooks/:id/runs
func (h *PlaybookHandler) Runs(c *gin.Context) {
	id := c.Param("id")
	runs, err := h.Store.ListRuns(c.Request.Context(), id, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "実行履歴の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": runs, "total": len(runs)})
}

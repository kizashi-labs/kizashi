package handlers

import (
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// AlertCommentsHandler provides endpoints for alert comments.
type AlertCommentsHandler struct {
	store *store.AlertCommentStore
}

// NewAlertCommentsHandler creates a new AlertCommentsHandler.
func NewAlertCommentsHandler(s *store.AlertCommentStore) *AlertCommentsHandler {
	return &AlertCommentsHandler{store: s}
}

// List handles GET /api/v1/alerts/:id/comments
func (h *AlertCommentsHandler) List(c *gin.Context) {
	alertID := c.Param("id")
	comments, err := h.store.List(c.Request.Context(), alertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメント一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"comments": comments})
}

// Add handles POST /api/v1/alerts/:id/comments
func (h *AlertCommentsHandler) Add(c *gin.Context) {
	alertID := c.Param("id")
	var req struct {
		Content string `json:"content" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contentは必須です"})
		return
	}
	authorID := c.GetString("user_id")
	authorName := c.GetString("username")
	if authorName == "" {
		authorName = authorID
	}
	comment, err := h.store.Add(c.Request.Context(), alertID, authorID, authorName, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, comment)
}

// Delete handles DELETE /api/v1/alerts/:id/comments/:comment_id
func (h *AlertCommentsHandler) Delete(c *gin.Context) {
	commentID := c.Param("comment_id")
	requesterID := c.GetString("user_id")
	role := c.GetString("role")
	isAdmin := role == "admin"
	if err := h.store.Delete(c.Request.Context(), commentID, requesterID, isAdmin); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "コメントが見つかりません"})
		} else if strings.Contains(err.Error(), "forbidden") {
			c.JSON(http.StatusForbidden, gin.H{"error": "このコメントを削除する権限がありません"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの削除に失敗しました"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "コメントを削除しました"})
}

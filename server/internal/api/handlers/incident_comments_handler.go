package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// IncidentCommentHandler provides endpoints for incident comments.
type IncidentCommentHandler struct {
	Store *store.IncidentCommentStore
}

// NewIncidentCommentHandler creates a new IncidentCommentHandler.
func NewIncidentCommentHandler(s *store.IncidentCommentStore) *IncidentCommentHandler {
	return &IncidentCommentHandler{Store: s}
}

// List returns all comments for an incident.
// GET /api/v1/incidents/:id/comments
func (h *IncidentCommentHandler) List(c *gin.Context) {
	incidentID := c.Param("id")
	comments, err := h.Store.List(c.Request.Context(), incidentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": comments})
}

// Add creates a new comment on an incident.
// POST /api/v1/incidents/:id/comments
func (h *IncidentCommentHandler) Add(c *gin.Context) {
	incidentID := c.Param("id")
	var req struct {
		Body string `json:"body" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body は必須です"})
		return
	}
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}
	comment, err := h.Store.Add(c.Request.Context(), incidentID, uid, req.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, comment)
}

// Delete removes a comment (only the author may delete).
// DELETE /api/v1/incidents/:id/comments/:comment_id
func (h *IncidentCommentHandler) Delete(c *gin.Context) {
	commentID := c.Param("comment_id")
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
		return
	}
	if err := h.Store.Delete(c.Request.Context(), commentID, uid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "コメントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "コメントを削除しました"})
}

package handlers

import (
	"net/http"
	"strings"
	"unicode/utf8"

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

// maxCommentBodyLength はインシデントコメント本文の最大文字数です。
// カラムは TEXT で上限が無く、**そのまま入ります。**
const maxCommentBodyLength = 10_000

// validateCommentBody はコメント本文を検証します。空文字列・空白のみ・
// 上限超過を拒否し、問題が無ければ空文字列を返します。
//
// 数えるのはルーン数です。**バイト数で数えると、日本語のコメントが
// 3分の1の長さで弾かれます。**
func validateCommentBody(body string) string {
	if strings.TrimSpace(body) == "" {
		return "コメント本文は必須です"
	}
	if utf8.RuneCountInString(body) > maxCommentBodyLength {
		return "コメント本文は 10,000 文字以内で指定してください"
	}
	return ""
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
	// **`binding:"required"` は空文字列しか弾きません。** 空白だけの本文は
	// 通り、長さの上限もありませんでした。`internal/store` の検査には
	// 「空白のみは無効」「10,000 文字超は無効」を検証する `isValidCommentBody`
	// というヘルパーが置いてありましたが、**製品にその規則はありません**
	// でした —— 検査は、存在しない約束を確かめていました。規則の方を
	// 足します。
	if msg := validateCommentBody(req.Body); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
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

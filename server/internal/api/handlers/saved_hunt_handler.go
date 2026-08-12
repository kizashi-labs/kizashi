package handlers

import (
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// SavedHuntHandler handles CRUD for saved_hunt_queries.
type SavedHuntHandler struct {
	store *store.SavedHuntStore
}

// NewSavedHuntHandler creates a SavedHuntHandler.
func NewSavedHuntHandler(s *store.SavedHuntStore) *SavedHuntHandler {
	return &SavedHuntHandler{store: s}
}

// List handles GET /api/v1/hunt/saved
func (h *SavedHuntHandler) List(c *gin.Context) {
	userID := c.GetString("user_id")
	includeShared := c.DefaultQuery("shared", "true") == "true"
	queries, err := h.store.List(c.Request.Context(), userID, includeShared)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存済みクエリの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"queries": queries})
}

// Create handles POST /api/v1/hunt/saved
func (h *SavedHuntHandler) Create(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		Query       string   `json:"query"`
		QueryType   string   `json:"query_type"`
		Tags        []string `json:"tags"`
		IsShared    bool     `json:"is_shared"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Query) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameとqueryは必須です"})
		return
	}
	if req.QueryType == "" {
		req.QueryType = "sql"
	}
	userID := c.GetString("user_id")
	q, err := h.store.Create(c.Request.Context(), req.Name, req.Description, req.Query, req.QueryType, req.Tags, userID, req.IsShared)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "クエリの保存に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, q)
}

// Update handles PUT /api/v1/hunt/saved/:id
func (h *SavedHuntHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Query       string   `json:"query"`
		Tags        []string `json:"tags"`
		IsShared    bool     `json:"is_shared"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	q, err := h.store.Update(c.Request.Context(), id, req.Name, req.Description, req.Query, req.Tags, req.IsShared)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "保存済みクエリが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, q)
}

// Delete handles DELETE /api/v1/hunt/saved/:id
func (h *SavedHuntHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "保存済みクエリが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "クエリを削除しました"})
}

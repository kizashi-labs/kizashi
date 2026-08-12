package handlers

import (
	"net/http"
	"strings"
	"unicode"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// maxTagNameLength はエージェントタグ名の最大文字数です。
const maxTagNameLength = 64

// validateTagName はエージェントタグ名を検証します。
// タグ名は空でなく、最大 64 文字、英数字・ハイフン・アンダースコア・ドットのみ使用可能です。
func validateTagName(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "タグ名は必須です"
	}
	if len(tag) > maxTagNameLength {
		return "タグ名は 64 文字以内で指定してください"
	}
	for _, r := range tag {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return "タグ名に使用できない文字が含まれています（英数字・ハイフン・アンダースコア・ドットのみ使用可能）"
		}
	}
	return ""
}

// normalizeTagName はタグ名を正規化します。
// 前後の空白を除去し、小文字に変換します。
func normalizeTagName(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}

// deduplicateTags はタグリストから重複を除去します。順序は保持されます。
func deduplicateTags(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	result := make([]string, 0, len(tags))
	for _, t := range tags {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			result = append(result, t)
		}
	}
	return result
}

// containsTag はタグリストに指定したタグが含まれるか判定します。
func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

// AgentTagHandler provides agent tag management endpoints.
type AgentTagHandler struct {
	store *store.AgentTagStore
}

// NewAgentTagHandler constructs an AgentTagHandler.
func NewAgentTagHandler(s *store.AgentTagStore) *AgentTagHandler {
	return &AgentTagHandler{store: s}
}

// ListTags returns all tags for a specific agent.
// GET /api/v1/agents/:id/tags
func (h *AgentTagHandler) ListTags(c *gin.Context) {
	agentID := c.Param("id")
	tags, err := h.store.ListByAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "タグの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// AddTag adds a tag to an agent.
// POST /api/v1/agents/:id/tags
// Body: {"tag": "production"}
func (h *AgentTagHandler) AddTag(c *gin.Context) {
	agentID := c.Param("id")
	var req struct {
		Tag string `json:"tag" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tag は必須です"})
		return
	}
	if err := h.store.Add(c.Request.Context(), agentID, req.Tag); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "タグの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "タグを追加しました", "tag": req.Tag})
}

// RemoveTag removes a tag from an agent.
// DELETE /api/v1/agents/:id/tags/:tag
func (h *AgentTagHandler) RemoveTag(c *gin.Context) {
	agentID := c.Param("id")
	tag := c.Param("tag")
	if err := h.store.Remove(c.Request.Context(), agentID, tag); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "タグの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "タグを削除しました", "tag": tag})
}

// ListAllTags returns all distinct tags across all agents.
// GET /api/v1/agent-tags
func (h *AgentTagHandler) ListAllTags(c *gin.Context) {
	tags, err := h.store.AllTags(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "タグ一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// ListByTag returns agent IDs that have the given tag.
// GET /api/v1/agent-tags/:tag/agents
func (h *AgentTagHandler) ListByTag(c *gin.Context) {
	tag := c.Param("tag")
	agentIDs, err := h.store.ListByTag(c.Request.Context(), tag)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェント一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tag": tag, "agents": agentIDs})
}

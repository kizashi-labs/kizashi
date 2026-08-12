package handlers

import (
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// softwareVulnerableKeywords は既知の脆弱なソフトウェアに関連するキーワードの一覧です。
// フィルタリングやリスク評価に使用されます。
var softwareVulnerableKeywords = []string{
	"log4j", "openssl", "curl", "libssl", "apache httpd",
	"nginx", "openssh", "python", "nodejs", "java runtime",
}

// normalizeSoftwareName はソフトウェア名を正規化します。
// 前後の空白を除去し、小文字に変換します。
func normalizeSoftwareName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// validateSoftwareEntry はソフトウェアエントリの必須フィールドを検証します。
// name が空の場合はエラーメッセージを返します。
func validateSoftwareEntry(name, version string) string {
	if strings.TrimSpace(name) == "" {
		return "ソフトウェア名は必須です"
	}
	if len(name) > 255 {
		return "ソフトウェア名は 255 文字以内で指定してください"
	}
	if len(version) > 100 {
		return "バージョン文字列は 100 文字以内で指定してください"
	}
	return ""
}

// isSoftwareVulnerable はソフトウェア名が既知の脆弱なキーワードを含むか判定します。
// 大文字小文字を区別しません。
func isSoftwareVulnerable(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range softwareVulnerableKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// filterVulnerableSoftware はソフトウェアエントリのリストから
// 脆弱なキーワードを含むものだけを返します。
func filterVulnerableSoftware(entries []*store.SoftwareEntry) []*store.SoftwareEntry {
	var result []*store.SoftwareEntry
	for _, e := range entries {
		if isSoftwareVulnerable(e.Name) {
			result = append(result, e)
		}
	}
	return result
}

// SoftwareInventoryHandler manages endpoint software inventory.
type SoftwareInventoryHandler struct {
	Store *store.SoftwareInventoryStore
}

func NewSoftwareInventoryHandler(s *store.SoftwareInventoryStore) *SoftwareInventoryHandler {
	return &SoftwareInventoryHandler{Store: s}
}

// ListByAgent returns installed software for a specific agent.
// GET /api/v1/agents/:id/software
func (h *SoftwareInventoryHandler) ListByAgent(c *gin.Context) {
	agentID := c.Param("id")
	items, err := h.Store.ListByAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ソフトウェア一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items, "total": len(items)})
}

// Search finds software by name across all agents.
// GET /api/v1/software?q=<name>
func (h *SoftwareInventoryHandler) Search(c *gin.Context) {
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "検索クエリ q が必要です"})
		return
	}
	items, err := h.Store.SearchAcrossAgents(c.Request.Context(), q, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "検索に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items, "total": len(items)})
}

// Report accepts a software inventory report from an agent.
// POST /api/v1/agents/:id/software
func (h *SoftwareInventoryHandler) Report(c *gin.Context) {
	agentID := c.Param("id")
	var req struct {
		Software []struct {
			Name        string `json:"name" binding:"required"`
			Version     string `json:"version"`
			Vendor      string `json:"vendor"`
			InstallDate string `json:"install_date"`
			InstallPath string `json:"install_path"`
		} `json:"software"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	items := make([]*store.SoftwareEntry, 0, len(req.Software))
	for _, sw := range req.Software {
		if sw.Name == "" {
			continue
		}
		items = append(items, &store.SoftwareEntry{
			AgentID:     agentID,
			Name:        sw.Name,
			Version:     sw.Version,
			Vendor:      sw.Vendor,
			InstallDate: sw.InstallDate,
			InstallPath: sw.InstallPath,
		})
	}

	if err := h.Store.UpsertBatch(c.Request.Context(), agentID, items); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "インベントリの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "インベントリを更新しました", "count": len(items)})
}

// DeleteEntry removes a specific software entry.
// DELETE /api/v1/software/:id
func (h *SoftwareInventoryHandler) DeleteEntry(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.DeleteEntry(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました", "id": id})
}

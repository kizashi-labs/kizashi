package handlers

import (
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// IOC の深刻度は 1〜10。範囲外は既定に戻します。
const (
	iocSeverityMin     = 1
	iocSeverityMax     = 10
	defaultIOCSeverity = 7
)

// clampIOCSeverity は範囲外の深刻度を既定値に戻します。
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 同じ4行がこのファイルの中に2か所（Create と一括登録）あり、検査
// ファイルには3つ目の写しが置いてありました。試されていたのは写しの
// 方だけです。
func clampIOCSeverity(s int) int {
	if s < iocSeverityMin || s > iocSeverityMax {
		return defaultIOCSeverity
	}
	return s
}

var (
	reIPv4   = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reHash   = regexp.MustCompile(`^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	reDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$`)
)

// detectIOCType guesses the IOC type from a raw value string.
func detectIOCType(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return "url"
	}
	if reIPv4.MatchString(v) {
		return "ip"
	}
	if reHash.MatchString(v) {
		return "hash"
	}
	if strings.Contains(v, "@") {
		return "email"
	}
	if reDomain.MatchString(v) {
		return "domain"
	}
	return ""
}

// IOCPublisher signals the detection engine to reload its IOC cache.
type IOCPublisher interface {
	Publish(subject string, data []byte) error
}

// IOCHandler provides indicator-of-compromise management endpoints.
type IOCHandler struct {
	Store     *store.IOCStore
	Publisher IOCPublisher // optional; signals detection engine on IOC changes
}

func NewIOCHandler(s *store.IOCStore) *IOCHandler {
	return &IOCHandler{Store: s}
}

func (h *IOCHandler) publishInvalidate() {
	if h.Publisher != nil {
		if err := h.Publisher.Publish("ioc.invalidate", []byte("{}")); err != nil {
			slog.Warn("NATS publish failed", "subject", "ioc.invalidate", "error", err)
		}
	}
}

// List returns paginated IOC entries.
// GET /api/v1/ioc?type=ip&search=...&active=true&page=1&per_page=50
func (h *IOCHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, perPage, offset := clampPageParams(page, perPage, 50, 200)

	activeOnly := c.Query("active") == "true"

	entries, total, err := h.Store.List(
		c.Request.Context(),
		c.Query("type"),
		c.Query("search"),
		activeOnly,
		perPage, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IOC一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":     entries,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Create adds a new IOC entry.
// POST /api/v1/ioc
func (h *IOCHandler) Create(c *gin.Context) {
	var req struct {
		Type        string `json:"type"        binding:"required"`
		Value       string `json:"value"       binding:"required"`
		Description string `json:"description"`
		Severity    int    `json:"severity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type と value は必須です"})
		return
	}
	req.Severity = clampIOCSeverity(req.Severity)

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	entry := &store.IOCEntry{
		Type:        req.Type,
		Value:       req.Value,
		Description: req.Description,
		Severity:    req.Severity,
		IsActive:    true,
		AddedBy:     &uid,
	}
	if err := h.Store.Insert(c.Request.Context(), entry); err != nil {
		if isDuplicateError(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "同じタイプと値のIOCがすでに存在します"})
			return
		}
		// Invalid type / value (e.g. a type outside the CHECK set) is client
		// error → 400, not a server fault.
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "IOCのタイプまたは値が不正です"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IOCの登録に失敗しました"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusCreated, gin.H{"message": "IOCを登録しました"})
}

// Delete removes an IOC entry.
// DELETE /api/v1/ioc/:id
func (h *IOCHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IOCが見つかりません"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{"message": "IOCを削除しました", "id": id})
}

// Toggle enables or disables an IOC entry.
// PUT /api/v1/ioc/:id/toggle
func (h *IOCHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if err := h.Store.SetActive(c.Request.Context(), id, req.IsActive); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IOCの更新に失敗しました"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{"message": "IOCを更新しました", "id": id, "is_active": req.IsActive})
}

// Check looks up a single value in the IOC database.
// GET /api/v1/ioc/check?type=ip&value=1.2.3.4
func (h *IOCHandler) Check(c *gin.Context) {
	iocType := c.Query("type")
	value := c.Query("value")
	if iocType == "" || value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type と value は必須です"})
		return
	}
	entry, err := h.Store.Check(c.Request.Context(), iocType, value)
	if err != nil {
		ReadFailure(c, err, gin.H{"match": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"match": true, "entry": entry})
}

// Stats returns aggregate IOC counts for the dashboard widget.
// GET /api/v1/ioc/stats
func (h *IOCHandler) Stats(c *gin.Context) {
	stats, err := h.Store.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "統計の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// BulkImport parses a plain-text or CSV body and inserts multiple IOC entries.
//
// Accepted formats (one entry per line):
//
//	value                              → type auto-detected
//	type,value
//	type,value,description
//	type,value,description,severity
//
// Lines starting with # are ignored (comments). Empty lines are skipped.
// POST /api/v1/ioc/import
func (h *IOCHandler) BulkImport(c *gin.Context) {
	var req struct {
		Lines       string `json:"lines"`        // raw text, newline-separated
		DefaultType string `json:"default_type"` // fallback type when auto-detect fails
		Severity    int    `json:"severity"`     // default severity (1-10)
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエスト形式です"})
		return
	}

	defaultSev := clampIOCSeverity(req.Severity)

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	var entries []*store.IOCEntry
	var skipped []string
	seen := map[string]struct{}{} // deduplicate within the batch

	for _, raw := range strings.Split(req.Lines, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 4)
		var iocType, value, description string
		severity := defaultSev

		switch len(parts) {
		case 1:
			value = strings.TrimSpace(parts[0])
			iocType = detectIOCType(value)
			if iocType == "" {
				iocType = req.DefaultType
			}
		case 2:
			iocType = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
		case 3:
			iocType = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
			description = strings.TrimSpace(parts[2])
		default: // 4+
			iocType = strings.TrimSpace(parts[0])
			value = strings.TrimSpace(parts[1])
			description = strings.TrimSpace(parts[2])
			if s, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil && s >= 1 && s <= 10 {
				severity = s
			}
		}

		if value == "" || iocType == "" {
			skipped = append(skipped, line)
			continue
		}

		key := iocType + ":" + value
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		entries = append(entries, &store.IOCEntry{
			Type:        iocType,
			Value:       value,
			Description: description,
			Severity:    severity,
			AddedBy:     &uid,
		})
	}

	if len(entries) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "インポート可能なエントリがありません", "skipped": skipped})
		return
	}

	inserted, err := h.Store.BulkInsert(c.Request.Context(), entries)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{
		"inserted": inserted,
		"parsed":   len(entries),
		"skipped":  skipped,
	})
}

// TopHits returns the top IOC values that have matched the most alerts.
// GET /api/v1/ioc/top-hits
func (h *IOCHandler) TopHits(c *gin.Context) {
	if h.Store == nil {
		c.JSON(http.StatusOK, gin.H{"hits": []interface{}{}})
		return
	}

	hits, err := h.Store.TopHits(c.Request.Context(), 10)
	if err != nil {
		// Frontend falls back to mock data on empty response
		ReadFailure(c, err, gin.H{"hits": []interface{}{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"hits": hits})
}

// isDuplicateError checks for PostgreSQL unique violation error code 23505.
func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	return len(err.Error()) > 5 && (err.Error()[:5] == "ERROR" &&
		(contains(err.Error(), "23505") || contains(err.Error(), "unique")))
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

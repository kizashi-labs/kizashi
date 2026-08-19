package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	edrsync "github.com/edr-platform/server/internal/sync"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RuleChangePublisher is implemented by anything that can signal a rule set change
// (typically a *nats.Conn). The detection engine subscribes to "rules.invalidate".
type RuleChangePublisher interface {
	Publish(subject string, data []byte) error
}

// RuleHandler provides detection rule management endpoints.
type RuleHandler struct {
	Store     *store.RuleStore
	Publisher RuleChangePublisher    // optional; nil = no live-reload signal
	Syncer    *edrsync.SigmaHQSyncer // optional; nil = sync disabled
}

// NewRuleHandler creates a new RuleHandler.
func NewRuleHandler(s *store.RuleStore) *RuleHandler {
	return &RuleHandler{Store: s}
}

// publishInvalidate fires a rules.invalidate signal so the detection engine
// reloads its rule set immediately (best-effort; errors are silently ignored).
func (h *RuleHandler) publishInvalidate() {
	if h.Publisher != nil {
		if err := h.Publisher.Publish("rules.invalidate", []byte("{}")); err != nil {
			slog.Warn("NATS publish failed", "subject", "rules.invalidate", "error", err)
		}
	}
}

// List returns rules with optional filtering and pagination.
// GET /api/v1/rules?type=sigma&enabled=true&search=powershell&page=1&per_page=20
func (h *RuleHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	page, perPage, offset := clampPageParams(page, perPage, 20, 100)

	filter := store.RuleFilter{
		Type:   c.Query("type"),
		Search: c.Query("search"),
		Limit:  perPage,
		Offset: offset,
	}

	if enabledStr := c.Query("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		filter.Enabled = &enabled
	}

	rules, total, err := h.Store.List(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルール一覧の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":    rules,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Get returns a single rule by ID.
// GET /api/v1/rules/:id
func (h *RuleHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Create creates a new detection rule.
// POST /api/v1/rules
func (h *RuleHandler) Create(c *gin.Context) {
	var req struct {
		Name           string   `json:"name" binding:"required"`
		Type           string   `json:"type" binding:"required"`
		Platform       []string `json:"platform"`
		Severity       int      `json:"severity"`
		Content        string   `json:"content" binding:"required"`
		Enabled        bool     `json:"enabled"`
		Source         string   `json:"source"`
		MITRETags      []string `json:"mitre_tags"`
		AutoIsolate    bool     `json:"auto_isolate"`
		AutoKill       bool     `json:"auto_kill"`
		AutoQuarantine bool     `json:"auto_quarantine"`
		Description    *string  `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名前、タイプ、コンテンツが必要です"})
		return
	}

	if req.Severity < 1 || req.Severity > 10 {
		req.Severity = 5
	}
	if req.Source == "" {
		req.Source = "custom"
	}
	if req.Platform == nil {
		req.Platform = []string{"windows", "linux", "macos"}
	}

	rule := &store.RuleRow{
		ID:             uuid.New().String(),
		Name:           req.Name,
		Type:           req.Type,
		Platform:       req.Platform,
		Severity:       req.Severity,
		Content:        req.Content,
		Enabled:        req.Enabled,
		Source:         req.Source,
		MITRETags:      req.MITRETags,
		AutoIsolate:    req.AutoIsolate,
		AutoKill:       req.AutoKill,
		AutoQuarantine: req.AutoQuarantine,
		Description:    req.Description,
	}

	if err := h.Store.Create(c.Request.Context(), rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルールの作成に失敗しました"})
		return
	}

	created, err := h.Store.Get(c.Request.Context(), rule.ID)
	if err != nil {
		c.JSON(http.StatusCreated, rule)
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusCreated, created)
}

// Update updates an existing detection rule.
// PUT /api/v1/rules/:id
func (h *RuleHandler) Update(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ルールが見つかりません"})
		return
	}

	var req struct {
		Name              *string  `json:"name"`
		Type              *string  `json:"type"`
		Platform          []string `json:"platform"`
		Severity          *int     `json:"severity"`
		Content           *string  `json:"content"`
		Enabled           *bool    `json:"enabled"`
		Source            *string  `json:"source"`
		MITRETags         []string `json:"mitre_tags"`
		AutoIsolate       *bool    `json:"auto_isolate"`
		AutoKill          *bool    `json:"auto_kill"`
		AutoQuarantine    *bool    `json:"auto_quarantine"`
		Description       *string  `json:"description"`
		FalsePositiveRate *float64 `json:"false_positive_rate"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Type != nil {
		existing.Type = *req.Type
	}
	if req.Platform != nil {
		existing.Platform = req.Platform
	}
	if req.Severity != nil {
		existing.Severity = *req.Severity
	}
	if req.Content != nil {
		existing.Content = *req.Content
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Source != nil {
		existing.Source = *req.Source
	}
	if req.MITRETags != nil {
		existing.MITRETags = req.MITRETags
	}
	if req.AutoIsolate != nil {
		existing.AutoIsolate = *req.AutoIsolate
	}
	if req.AutoKill != nil {
		existing.AutoKill = *req.AutoKill
	}
	if req.AutoQuarantine != nil {
		existing.AutoQuarantine = *req.AutoQuarantine
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.FalsePositiveRate != nil {
		existing.FalsePositiveRate = *req.FalsePositiveRate
	}

	if err := h.Store.Update(c.Request.Context(), existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルールの更新に失敗しました"})
		return
	}

	updated, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, existing)
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, updated)
}

// Delete removes a detection rule.
// DELETE /api/v1/rules/:id
func (h *RuleHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	if _, err := h.Store.Get(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ルールが見つかりません"})
		return
	}

	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルールの削除に失敗しました"})
		return
	}

	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{"message": "ルールを削除しました", "id": id})
}

// Toggle enables or disables a rule.
// PUT /api/v1/rules/:id/toggle
func (h *RuleHandler) Toggle(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled フィールドが必要です"})
		return
	}

	if err := h.Store.Toggle(c.Request.Context(), id, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルールの切り替えに失敗しました"})
		return
	}

	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"enabled": req.Enabled,
		"message": map[bool]string{true: "ルールを有効化しました", false: "ルールを無効化しました"}[req.Enabled],
	})
}

// Test tests a rule against sample event data.
// POST /api/v1/rules/:id/test
func (h *RuleHandler) Test(c *gin.Context) {
	id := c.Param("id")

	rule, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ルールが見つかりません"})
		return
	}

	var req struct {
		SampleEvent map[string]interface{} `json:"sample_event"`
	}
	// 本文が壊れているときに既定のイベントで試しません。利用者が送った
	// イベントとは別のもので「一致しました」と答えることになります。
	if !OptionalBody(c, &req) {
		return
	}
	if req.SampleEvent == nil {
		req.SampleEvent = map[string]interface{}{"event_type": "test"}
	}

	matched, matchedTerms, note := testRuleAgainstEvent(rule, req.SampleEvent)

	c.JSON(http.StatusOK, gin.H{
		"rule_id":       id,
		"rule_name":     rule.Name,
		"rule_type":     rule.Type,
		"matched":       matched,
		"matched_terms": matchedTerms,
		"note":          note,
		"tested_at":     time.Now(),
	})
}

// testRuleAgainstEvent performs keyword-based matching for Sigma rules
// and returns match result plus which terms were found.
func testRuleAgainstEvent(rule *store.RuleRow, event map[string]interface{}) (bool, []string, string) {
	// Flatten the event to a searchable string
	eventJSON, _ := json.Marshal(event)
	eventStr := strings.ToLower(string(eventJSON))

	switch rule.Type {
	case "sigma":
		return testSigmaKeywords(rule.Content, eventStr)
	case "yara":
		return false, nil, "YARAルールのテストにはlibYARAライブラリが必要です。構文を手動で確認してください。"
	case "behavioral":
		return false, nil, "振る舞いルールはリアルタイムイベントストリームに対してテストされます。"
	default:
		return false, nil, "不明なルールタイプです"
	}
}

// testSigmaKeywords extracts detection strings from a Sigma rule's detection
// section and checks if they appear in the event JSON.
func testSigmaKeywords(content, eventStr string) (bool, []string, string) {
	// Extract values from the detection section via simple line scanning.
	// A full Sigma engine (go-sigma) would be used in production.
	var terms []string
	inDetection := false

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "detection:") {
			inDetection = true
			continue
		}
		if inDetection {
			// Stop at top-level keys that aren't indented
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && !strings.HasPrefix(trimmed, "#") {
				inDetection = false
				continue
			}
			// Extract quoted string values and bare values after ': '
			if idx := strings.Index(trimmed, ": "); idx >= 0 {
				val := strings.TrimSpace(trimmed[idx+2:])
				val = strings.Trim(val, "'\"")
				if val != "" && val != "*" && !strings.HasPrefix(val, "#") {
					terms = append(terms, strings.ToLower(val))
				}
			} else if strings.HasPrefix(trimmed, "- ") {
				val := strings.Trim(strings.TrimPrefix(trimmed, "- "), "'\"*")
				if val != "" {
					terms = append(terms, strings.ToLower(val))
				}
			}
		}
	}

	if len(terms) == 0 {
		return false, nil, "検出キーワードが見つかりませんでした。Sigmaルールの構文を確認してください。"
	}

	var matched []string
	for _, term := range terms {
		if strings.Contains(eventStr, term) {
			matched = append(matched, term)
		}
	}

	if len(matched) > 0 {
		return true, matched, "キーワードマッチング（簡易評価）。本番環境ではgo-sigmaで完全評価されます。"
	}
	return false, nil, "イベントはいずれの検出キーワードにも一致しませんでした。"
}

// Import imports a Sigma or YARA rule from a file or text.
// POST /api/v1/rules/import
func (h *RuleHandler) Import(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
		Type    string `json:"type"`
		Source  string `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ルールコンテンツが必要です"})
		return
	}

	if req.Type == "" {
		req.Type = "sigma"
	}
	if req.Source == "" {
		req.Source = "custom"
	}

	rule := &store.RuleRow{
		ID:        uuid.New().String(),
		Name:      "インポートされたルール " + time.Now().Format("2006-01-02 15:04"),
		Type:      req.Type,
		Content:   req.Content,
		Enabled:   false,
		Source:    req.Source,
		Severity:  5,
		Platform:  []string{"windows", "linux", "macos"},
		MITRETags: []string{},
	}

	if err := h.Store.Create(c.Request.Context(), rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルールのインポートに失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      rule.ID,
		"message": "ルールをインポートしました。有効化する前に内容を確認してください。",
		"rule":    rule,
	})
}

// SyncCommunity triggers an asynchronous SigmaHQ community rule sync.
// POST /api/v1/rules/sync
// Body (optional): {"auto_enable": false, "paths": ["rules/windows/process_creation"]}
func (h *RuleHandler) SyncCommunity(c *gin.Context) {
	if h.Syncer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "コミュニティルール同期が設定されていません (GITHUB_TOKEN を設定してください)",
		})
		return
	}

	if h.Syncer.IsRunning() {
		c.JSON(http.StatusConflict, gin.H{
			"error":  "同期は既に実行中です",
			"status": h.Syncer.Status(),
		})
		return
	}

	var req struct {
		AutoEnable bool     `json:"auto_enable"`
		Paths      []string `json:"paths"`
	}
	_ = c.ShouldBindJSON(&req) // optional body

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := h.Syncer.Sync(ctx, req.AutoEnable, req.Paths); err != nil {
			// error is captured in status; nothing to do here
			_ = err
		}
		// Signal detection engine to reload rules after sync
		h.publishInvalidate()
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message":    "SigmaHQコミュニティルールの同期を開始しました",
		"started_at": time.Now(),
		"status_url": "/api/v1/rules/sync/status",
	})
}

// SyncStatus returns the status of the current or last community sync.
// GET /api/v1/rules/sync/status
func (h *RuleHandler) SyncStatus(c *gin.Context) {
	if h.Syncer == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}

	st := h.Syncer.Status()
	if st == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": true,
			"running": false,
			"message": "同期はまだ実行されていません",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": true,
		"status":  st,
	})
}

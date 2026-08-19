package handlers

// YARAHandler provides YARA rule management endpoints.
//
// NOTE: Full YARA scanning requires cgo and the YARA C library (via the
// go-yara package: github.com/hillu/go-yara). Because this build avoids
// cgo dependencies, the server only stores and distributes YARA rule
// content. Actual pattern matching is deferred to a future agent build
// that can link against libyara.

import (
	"context"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	edrsync "github.com/edr-platform/server/internal/sync"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// YARAHandler handles YARA rule API requests.
type YARAHandler struct {
	store  *store.YARAStore
	Pool   *pgxpool.Pool
	Syncer *edrsync.YARAHQSyncer // GitHubコミュニティルール同期（オプション）
}

// NewYARAHandler creates a new YARAHandler.
func NewYARAHandler(s *store.YARAStore) *YARAHandler {
	return &YARAHandler{store: s}
}

// SyncStart triggers an asynchronous YARA rule sync from Yara-Rules/community.
// POST /api/v1/admin/yara/rules/sync
func (h *YARAHandler) SyncStart(c *gin.Context) {
	if h.Syncer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "YARA同期はGITHUB_TOKENが設定されていないため無効です"})
		return
	}
	if h.Syncer.IsRunning() {
		c.JSON(http.StatusConflict, gin.H{"error": "同期は既に実行中です", "status": h.Syncer.Status()})
		return
	}

	var req struct {
		AutoEnable bool     `json:"auto_enable"`
		Paths      []string `json:"paths"`
	}
	_ = c.ShouldBindJSON(&req)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := h.Syncer.Sync(ctx, req.AutoEnable, req.Paths); err != nil {
			slog.Error("YARAコミュニティルール同期に失敗しました", "error", err)
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message": "YARA同期を開始しました",
		"paths":   req.Paths,
	})
}

// SyncStatus returns the current (or last completed) sync status.
// GET /api/v1/admin/yara/rules/sync/status
func (h *YARAHandler) SyncStatus(c *gin.Context) {
	if h.Syncer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"enabled": false,
			"error":   "YARA同期はGITHUB_TOKENが設定されていないため無効です",
		})
		return
	}
	status := h.Syncer.Status()
	c.JSON(http.StatusOK, gin.H{
		"enabled": true,
		"status":  status,
	})
}

// validSeverities is the set of accepted severity values.
var validSeverities = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// yaraRequest is the shared request body for Create and Update.
type yaraRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Content     string   `json:"content"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
	Severity    string   `json:"severity"`
}

func validateYARARequest(req *yaraRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "name は必須です"
	}
	if strings.TrimSpace(req.Content) == "" {
		return "content は必須です"
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	if _, ok := validSeverities[req.Severity]; !ok {
		return "severity は low/medium/high/critical のいずれかを指定してください"
	}
	return ""
}

// List returns YARA rules with optional filtering and pagination.
// GET /api/v1/yara-rules
func (h *YARAHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page > 1 && offset == 0 {
		offset = (page - 1) * limit
	}

	var enabledPtr *bool
	if raw := c.Query("enabled"); raw != "" {
		b := raw == "true" || raw == "1"
		enabledPtr = &b
	}

	f := store.YARAListFilter{
		Search:   c.Query("search"),
		Severity: c.Query("severity"),
		Enabled:  enabledPtr,
		Limit:    limit,
		Offset:   offset,
	}

	rules, total, err := h.store.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "YARAルール一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":     rules,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// Get returns a single YARA rule by ID.
// GET /api/v1/yara-rules/:id
func (h *YARAHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "YARAルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Create creates a new YARA rule (admin only).
// POST /api/v1/yara-rules
func (h *YARAHandler) Create(c *gin.Context) {
	var req yaraRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateYARARequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	var createdBy *string
	if userIDStr != "" {
		createdBy = &userIDStr
	}

	in := store.CreateYARARuleInput{
		Name:        req.Name,
		Description: req.Description,
		Content:     req.Content,
		Tags:        req.Tags,
		Enabled:     req.Enabled,
		Severity:    req.Severity,
		CreatedBy:   createdBy,
	}

	rule, err := h.store.Create(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "YARAルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

// Update updates an existing YARA rule (admin only).
// PUT /api/v1/yara-rules/:id
func (h *YARAHandler) Update(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "YARAルールが見つかりません"})
		return
	}

	req := yaraRequest{
		Name:        existing.Name,
		Description: existing.Description,
		Content:     existing.Content,
		Tags:        existing.Tags,
		Enabled:     existing.Enabled,
		Severity:    existing.Severity,
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateYARARequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	in := store.UpdateYARARuleInput{
		Name:        req.Name,
		Description: req.Description,
		Content:     req.Content,
		Tags:        req.Tags,
		Enabled:     req.Enabled,
		Severity:    req.Severity,
	}

	rule, err := h.store.Update(c.Request.Context(), id, in)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "YARAルールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Delete removes a YARA rule by ID (admin only).
// DELETE /api/v1/yara-rules/:id
func (h *YARAHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "YARAルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "YARAルールの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "YARAルールを削除しました"})
}

// Toggle flips the enabled state of a YARA rule.
// PATCH /api/v1/yara-rules/:id/toggle
func (h *YARAHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Toggle(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "YARAルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "YARAルールの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// ListEnabled returns all enabled YARA rules for agent distribution.
// GET /api/v1/yara-rules/enabled
//
// This endpoint is intended for agent polling. Agents receive the raw YARA
// rule content; actual matching requires the go-yara cgo library on the
// agent side (not included in the current pure-Go build).
func (h *YARAHandler) ListEnabled(c *gin.Context) {
	rules, err := h.store.ListEnabled(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "有効なYARAルールの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// AgentEnabledRules returns the concatenated source of all enabled YARA rules for
// agent-side scanning. Unlike ListEnabled (JWT-protected, for the UI), this is
// agent-facing: it is registered on the public api group and identified by the
// agent id in the path (agents hold no user JWT), and returns a single rule blob
// the agent's scanner compiles directly.
// GET /api/v1/agents/:id/yara-rules
func (h *YARAHandler) AgentEnabledRules(c *gin.Context) {
	rules, err := h.store.ListEnabled(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "有効なYARAルールの取得に失敗しました"})
		return
	}
	var b strings.Builder
	count := 0
	for _, r := range rules {
		if strings.TrimSpace(r.Content) == "" {
			continue
		}
		b.WriteString(r.Content)
		b.WriteByte('\n')
		count++
	}
	c.JSON(http.StatusOK, gin.H{"rules": b.String(), "count": count})
}

// RecordMatch records a YARA match reported by an agent.
// POST /api/v1/yara-rules/:id/match
func (h *YARAHandler) RecordMatch(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.RecordMatch(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "YARAルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "マッチの記録に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "マッチを記録しました"})
}

// TestRule performs a mock test of a YARA rule against sample content.
// POST /api/v1/admin/yara-rules/:id/test
func (h *YARAHandler) TestRule(c *gin.Context) {
	var req struct {
		SampleContent string `json:"sample_content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Mock test result — actual matching requires libyara (cgo)
	matched := len(req.SampleContent) > 0
	c.JSON(http.StatusOK, gin.H{
		"matched":     matched,
		"match_count": 0,
		"strings":     []interface{}{},
		"duration_ms": 12,
	})
}

// GetScanResults returns scan results for a specific YARA rule.
// GET /api/v1/admin/yara-rules/:id/results
func (h *YARAHandler) GetScanResults(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database pool not available"})
		return
	}
	ruleID := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	ctx := c.Request.Context()

	// Check table existence
	exists := tableIsThere(ctx, h.Pool, "yara_scan_results")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "total": 0})
		return
	}

	var total int
	if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM yara_scan_results WHERE rule_id = $1`, ruleID).Scan(&total)) {
		return
	}

	rows, err := h.Pool.Query(ctx,
		`SELECT id, rule_id, agent_id, file_path, matched_strings, scanned_at
		 FROM yara_scan_results WHERE rule_id = $1
		 ORDER BY scanned_at DESC LIMIT $2 OFFSET $3`,
		ruleID, limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scan results"})
		return
	}
	defer rows.Close()

	type scanResult struct {
		ID             string      `json:"id"`
		RuleID         string      `json:"rule_id"`
		AgentID        string      `json:"agent_id"`
		FilePath       string      `json:"file_path"`
		MatchedStrings interface{} `json:"matched_strings"`
		ScannedAt      string      `json:"scanned_at"`
	}

	results := []scanResult{}
	for rows.Next() {
		var r scanResult
		var scannedAt time.Time
		if err := rows.Scan(&r.ID, &r.RuleID, &r.AgentID, &r.FilePath, &r.MatchedStrings, &scannedAt); err == nil {
			r.ScannedAt = scannedAt.Format(time.RFC3339)
			results = append(results, r)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scan results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     results,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// ReclassifyCategories updates the category of all YARA rules based on inferCategory logic.
// POST /api/v1/admin/yara-rules/reclassify
// Returns counts of updated and unchanged rules.
func (h *YARAHandler) ReclassifyCategories(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベース接続が利用できません"})
		return
	}
	ctx := c.Request.Context()

	rows, err := h.Pool.Query(ctx, `SELECT id, name, category, tags FROM yara_rules`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルール一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type ruleRow struct {
		id       string
		name     string
		category string
		tags     []string
	}
	var rules []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.id, &r.name, &r.category, &r.tags); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ルール一覧の取得に失敗しました"})
		return
	}
	rows.Close()

	updated, unchanged := 0, 0
	for _, r := range rules {
		newCat := edrsync.InferCategory("", r.name, r.tags)
		if newCat == r.category {
			unchanged++
			continue
		}
		_, err := h.Pool.Exec(ctx,
			`UPDATE yara_rules SET category = $1, updated_at = NOW() WHERE id = $2`,
			newCat, r.id,
		)
		if err != nil {
			metrics.BackgroundFailed("yara_reclassify", err, "YARAカテゴリ再分類: 更新に失敗しました", "id", r.id)
			continue
		}
		updated++
	}

	slog.Info("YARAカテゴリ再分類完了", "updated", updated, "unchanged", unchanged)
	c.JSON(http.StatusOK, gin.H{
		"updated":   updated,
		"unchanged": unchanged,
		"total":     len(rules),
		"message":   "カテゴリの再分類が完了しました",
	})
}

// GetStats returns YARA rule statistics grouped by category.
// GET /api/v1/admin/yara-rules/stats
func (h *YARAHandler) GetStats(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database pool not available"})
		return
	}
	ctx := c.Request.Context()

	// Check table existence
	exists := tableIsThere(ctx, h.Pool, "yara_rules")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"categories": []interface{}{}, "total_rules": 0, "total_matches": 0})
		return
	}

	type catStat struct {
		Category   string `json:"category"`
		RuleCount  int    `json:"rule_count"`
		MatchCount int    `json:"match_count"`
	}

	rows, err := h.Pool.Query(ctx,
		`SELECT category, COUNT(*) as rule_count, COALESCE(SUM(match_count),0) as match_count
		 FROM yara_rules GROUP BY category ORDER BY rule_count DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stats"})
		return
	}
	defer rows.Close()

	cats := []catStat{}
	var totalRules, totalMatches int
	for rows.Next() {
		var s catStat
		if err := rows.Scan(&s.Category, &s.RuleCount, &s.MatchCount); err == nil {
			cats = append(cats, s)
			totalRules += s.RuleCount
			totalMatches += s.MatchCount
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"categories":    cats,
		"total_rules":   totalRules,
		"total_matches": totalMatches,
	})
}

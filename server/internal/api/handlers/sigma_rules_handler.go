package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

// SigmaRulesHandler manages detection_rules via CRUD + import/export/test.
type SigmaRulesHandler struct {
	pool           *pgxpool.Pool
	onRulesChanged func() // called after any write; reloads the live pipeline
}

// NewSigmaRulesHandler creates a new SigmaRulesHandler.
func NewSigmaRulesHandler(pool *pgxpool.Pool) *SigmaRulesHandler {
	return &SigmaRulesHandler{pool: pool}
}

// SetReloadFunc registers a callback that is invoked after any rule write
// (create / update / delete / toggle / import) so the live detection pipeline
// can pick up the change without a server restart.
func (h *SigmaRulesHandler) SetReloadFunc(fn func()) {
	h.onRulesChanged = fn
}

func (h *SigmaRulesHandler) notifyChanged() {
	if h.onRulesChanged != nil {
		go h.onRulesChanged()
	}
}

type sigmaRuleRow struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	RuleYAML    string     `json:"rule_yaml,omitempty"`
	Tags        []string   `json:"tags"`
	Severity    int        `json:"severity"`
	Enabled     bool       `json:"enabled"`
	TestCount   int        `json:"test_count"`
	MatchCount  int        `json:"match_count"`
	LastMatched *time.Time `json:"last_matched,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type createSigmaRuleRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	RuleYAML    string   `json:"rule_yaml"`
	Tags        []string `json:"tags"`
	Severity    int      `json:"severity"`
	Enabled     *bool    `json:"enabled"`
}

// ensureTable gracefully checks the detection_rules table exists.
func (h *SigmaRulesHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "detection_rules")
}

// ListRules handles GET /api/v1/admin/sigma/rules
func (h *SigmaRulesHandler) ListRules(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "total": 0})
		return
	}

	query := `SELECT id, name, COALESCE(description,''), COALESCE(rule_yaml,''),
	                 COALESCE(tags,'{}'), severity, enabled, COALESCE(test_count,0),
	                 COALESCE(match_count,0), last_matched, created_at, updated_at
	          FROM detection_rules WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if enabled := c.Query("enabled"); enabled != "" {
		query += fmt.Sprintf(" AND enabled=$%d", argIdx)
		args = append(args, enabled == "true")
		argIdx++
	}
	if tag := c.Query("tag"); tag != "" {
		query += fmt.Sprintf(" AND $%d=ANY(tags)", argIdx)
		args = append(args, tag)
		argIdx++
	}
	if search := c.Query("search"); search != "" {
		query += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx+1)
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern)
		argIdx += 2
	}
	query += " ORDER BY created_at DESC"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		slog.Warn("sigma rules: list query failed", "error", err)
		ReadFailure(c, err, gin.H{"rules": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()

	var rules []sigmaRuleRow
	for rows.Next() {
		var r sigmaRuleRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleYAML,
			&r.Tags, &r.Severity, &r.Enabled, &r.TestCount, &r.MatchCount,
			&r.LastMatched, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("sigma rules: list query failed", "error", err)
		ReadFailure(c, err, gin.H{"rules": []interface{}{}, "total": 0})
		return
	}
	if rules == nil {
		rules = []sigmaRuleRow{}
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

// GetRule handles GET /api/v1/admin/sigma/rules/:id
func (h *SigmaRulesHandler) GetRule(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "detection_rules table not found"})
		return
	}
	id := c.Param("id")
	var r sigmaRuleRow
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, name, COALESCE(description,''), COALESCE(rule_yaml,''),
		       COALESCE(tags,'{}'), severity, enabled, COALESCE(test_count,0),
		       COALESCE(match_count,0), last_matched, created_at, updated_at
		FROM detection_rules WHERE id=$1`, id).
		Scan(&r.ID, &r.Name, &r.Description, &r.RuleYAML,
			&r.Tags, &r.Severity, &r.Enabled, &r.TestCount, &r.MatchCount,
			&r.LastMatched, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// CreateRule handles POST /api/v1/admin/sigma/rules
func (h *SigmaRulesHandler) CreateRule(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "detection_rules table not available"})
		return
	}
	var req createSigmaRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Severity == 0 {
		req.Severity = 5
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	var r sigmaRuleRow
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO detection_rules (name, description, rule_yaml, tags, severity, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, COALESCE(description,''), COALESCE(rule_yaml,''),
		          COALESCE(tags,'{}'), severity, enabled, 0, 0, NULL, created_at, updated_at`,
		req.Name, req.Description, req.RuleYAML, req.Tags, req.Severity, enabled,
	).Scan(&r.ID, &r.Name, &r.Description, &r.RuleYAML,
		&r.Tags, &r.Severity, &r.Enabled, &r.TestCount, &r.MatchCount,
		&r.LastMatched, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		slog.Error("sigma rules: create failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rule"})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusCreated, r)
}

// UpdateRule handles PUT /api/v1/admin/sigma/rules/:id
func (h *SigmaRulesHandler) UpdateRule(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "detection_rules table not available"})
		return
	}
	id := c.Param("id")
	var req createSigmaRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	var r sigmaRuleRow
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE detection_rules
		SET name=$1, description=$2, rule_yaml=$3, tags=$4, severity=$5, enabled=$6, updated_at=NOW()
		WHERE id=$7
		RETURNING id, name, COALESCE(description,''), COALESCE(rule_yaml,''),
		          COALESCE(tags,'{}'), severity, enabled, COALESCE(test_count,0),
		          COALESCE(match_count,0), last_matched, created_at, updated_at`,
		req.Name, req.Description, req.RuleYAML, req.Tags, req.Severity, enabled, id,
	).Scan(&r.ID, &r.Name, &r.Description, &r.RuleYAML,
		&r.Tags, &r.Severity, &r.Enabled, &r.TestCount, &r.MatchCount,
		&r.LastMatched, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		slog.Error("sigma rules: update failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update rule"})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusOK, r)
}

// DeleteRule handles DELETE /api/v1/admin/sigma/rules/:id
func (h *SigmaRulesHandler) DeleteRule(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "detection_rules table not available"})
		return
	}
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM detection_rules WHERE id=$1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// ToggleRule handles PUT /api/v1/admin/sigma/rules/:id/toggle
func (h *SigmaRulesHandler) ToggleRule(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "detection_rules table not available"})
		return
	}
	id := c.Param("id")
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(), `
		UPDATE detection_rules SET enabled = NOT enabled, updated_at=NOW()
		WHERE id=$1
		RETURNING enabled`, id).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}

// ImportRules handles POST /api/v1/admin/sigma/rules/import
// Accepts multipart file or raw YAML body. Parses rules separated by ---.
func (h *SigmaRulesHandler) ImportRules(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "detection_rules table not available"})
		return
	}
	var yamlContent []byte

	file, _, err := c.Request.FormFile("file")
	if err == nil {
		defer file.Close()
		yamlContent, err = io.ReadAll(io.LimitReader(file, 2*1024*1024))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read file"})
			return
		}
	} else {
		yamlContent, err = io.ReadAll(io.LimitReader(c.Request.Body, 2*1024*1024))
		if err != nil || len(yamlContent) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "YAML body required"})
			return
		}
	}

	parts := strings.Split(string(yamlContent), "\n---\n")
	imported := 0
	var errors []string

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var doc struct {
			Title       string            `yaml:"title"`
			Description string            `yaml:"description"`
			Tags        []string          `yaml:"tags"`
			Level       string            `yaml:"level"`
			Logsource   map[string]string `yaml:"logsource"`
			Detection   interface{}       `yaml:"detection"`
		}
		if err := yaml.Unmarshal([]byte(part), &doc); err != nil {
			errors = append(errors, fmt.Sprintf("rule %d: YAML parse error: %v", i+1, err))
			continue
		}
		if doc.Title == "" {
			errors = append(errors, fmt.Sprintf("rule %d: missing title", i+1))
			continue
		}

		sev := sigmaLevelToSeverityInt(doc.Level)
		if doc.Tags == nil {
			doc.Tags = []string{}
		}

		_, dbErr := h.pool.Exec(c.Request.Context(), `
			INSERT INTO detection_rules (name, description, rule_yaml, tags, severity, enabled)
			VALUES ($1, $2, $3, $4, $5, true)
			ON CONFLICT DO NOTHING`,
			doc.Title, doc.Description, part, doc.Tags, sev)
		if dbErr != nil {
			errors = append(errors, fmt.Sprintf("rule '%s': save failed: %v", doc.Title, dbErr))
			continue
		}
		imported++
	}

	if imported > 0 {
		h.notifyChanged()
	}
	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"errors":   errors,
	})
}

// ExportRules handles GET /api/v1/admin/sigma/rules/export
// Returns all enabled rules as YAML.
func (h *SigmaRulesHandler) ExportRules(c *gin.Context) {
	if !h.tableExists(c) {
		c.Data(http.StatusOK, "application/yaml", []byte("# no rules\n"))
		return
	}
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT name, COALESCE(description,''), COALESCE(rule_yaml,'')
		FROM detection_rules
		WHERE enabled = true
		ORDER BY created_at`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	var sb strings.Builder
	first := true
	for rows.Next() {
		var name, desc, ruleYAML string
		if err := rows.Scan(&name, &desc, &ruleYAML); err != nil {
			continue
		}
		if !first {
			sb.WriteString("\n---\n")
		}
		if ruleYAML != "" {
			sb.WriteString(ruleYAML)
		} else {
			sb.WriteString(fmt.Sprintf("title: %s\ndescription: %s\n", name, desc))
		}
		first = false
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.Data(http.StatusOK, "application/yaml", []byte(sb.String()))
}

// TestRule handles POST /api/v1/admin/sigma/rules/:id/test
// Tests a rule against a sample event JSON body {event: {...}}.
func (h *SigmaRulesHandler) TestRule(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "detection_rules table not available"})
		return
	}
	id := c.Param("id")

	var req struct {
		Event map[string]interface{} `json:"event"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Event == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must contain {event: {...}}"})
		return
	}

	var ruleYAML string
	var name string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT name, COALESCE(rule_yaml,'') FROM detection_rules WHERE id=$1`, id).
		Scan(&name, &ruleYAML)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	// Update test_count.
	if _, err := h.pool.Exec(c.Request.Context(),
		`UPDATE detection_rules SET test_count=COALESCE(test_count,0)+1 WHERE id=$1`, id); !WriteOK(c, err) {
		return
	}

	// Simple keyword matching: parse keywords from detection YAML and check event.
	matched, reason := sigmaRulesTestEvent(ruleYAML, req.Event)
	c.JSON(http.StatusOK, gin.H{
		"matched": matched,
		"reason":  reason,
		"rule":    name,
	})
}

// sigmaRulesTestEvent extracts detection keywords from a Sigma YAML rule
// and checks if they appear in the event fields.
func sigmaRulesTestEvent(ruleYAML string, event map[string]interface{}) (bool, string) {
	if ruleYAML == "" {
		return false, "no rule YAML stored"
	}

	var doc struct {
		Detection map[string]interface{} `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
		return false, "YAML parse error: " + err.Error()
	}

	// Collect all string values from detection as keywords.
	keywords := sigmaCollectStrings(doc.Detection)
	if len(keywords) == 0 {
		return false, "no keywords found in detection block"
	}

	// Flatten event to JSON string for simple substring search.
	eventBytes, _ := json.Marshal(event)
	eventStr := strings.ToLower(string(eventBytes))

	for _, kw := range keywords {
		kw = strings.ToLower(kw)
		if kw == "condition" || len(kw) < 2 {
			continue
		}
		if strings.Contains(eventStr, kw) {
			return true, fmt.Sprintf("keyword '%s' found in event", kw)
		}
	}
	return false, fmt.Sprintf("no detection keywords matched (checked %d keywords)", len(keywords))
}

// sigmaCollectStrings recursively extracts all string values from an interface{}.
func sigmaCollectStrings(v interface{}) []string {
	var out []string
	switch val := v.(type) {
	case string:
		out = append(out, val)
	case []interface{}:
		for _, item := range val {
			out = append(out, sigmaCollectStrings(item)...)
		}
	case map[string]interface{}:
		for _, mv := range val {
			out = append(out, sigmaCollectStrings(mv)...)
		}
	}
	return out
}

package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// validRuleTypes is the set of accepted rule type values.
var validRuleTypes = map[string]bool{
	"sigma":      true,
	"yara":       true,
	"behavioral": true,
}

// RulesIEHandler handles rule import/export endpoints.
type RulesIEHandler struct {
	ruleStore    *store.RuleStore
	processStore *store.ProcessBlockRuleStore
}

// NewRulesIEHandler creates a new RulesIEHandler.
func NewRulesIEHandler(ruleStore *store.RuleStore, processStore *store.ProcessBlockRuleStore) *RulesIEHandler {
	return &RulesIEHandler{ruleStore: ruleStore, processStore: processStore}
}

// Export handles GET /api/v1/rules/export
// Query params: format=json|csv, types=detection_rules,process_block_rules (comma-separated)
func (h *RulesIEHandler) Export(c *gin.Context) {
	format := c.DefaultQuery("format", "json")
	typesParam := c.DefaultQuery("types", "detection_rules")
	requestedTypes := strings.Split(typesParam, ",")
	typeSet := make(map[string]bool)
	for _, t := range requestedTypes {
		typeSet[strings.TrimSpace(t)] = true
	}

	export := map[string]interface{}{
		"exported_at": time.Now().Format(time.RFC3339),
		"version":     "1.0",
	}

	if typeSet["detection_rules"] {
		rules, _, err := h.ruleStore.List(c.Request.Context(), store.RuleFilter{Limit: 10000})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "検知ルールの取得に失敗しました"})
			return
		}
		export["detection_rules"] = rules
	}

	if typeSet["process_block_rules"] {
		rules, _, err := h.processStore.List(c.Request.Context(), store.ProcessBlockRuleFilter{Limit: 10000})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスブロックルールの取得に失敗しました"})
			return
		}
		export["process_block_rules"] = rules
	}

	timestamp := time.Now().Format("20060102-150405")
	switch format {
	case "csv":
		h.exportCSV(c, export, timestamp)
	default:
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="edr-rules-%s.json"`, timestamp))
		c.Header("Content-Type", "application/json")
		enc := json.NewEncoder(c.Writer)
		enc.SetIndent("", "  ")
		_ = enc.Encode(export)
	}
}

func (h *RulesIEHandler) exportCSV(c *gin.Context, export map[string]interface{}, timestamp string) {
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="edr-rules-%s.csv"`, timestamp))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"type", "id", "name", "enabled", "severity", "created_at"})
	if rules, ok := export["detection_rules"]; ok {
		data, _ := json.Marshal(rules)
		var ruleList []map[string]interface{}
		_ = json.Unmarshal(data, &ruleList)
		for _, r := range ruleList {
			_ = w.Write([]string{
				"detection_rule",
				fmt.Sprint(r["id"]),
				fmt.Sprint(r["name"]),
				fmt.Sprint(r["enabled"]),
				fmt.Sprint(r["severity"]),
				fmt.Sprint(r["created_at"]),
			})
		}
	}
	if rules, ok := export["process_block_rules"]; ok {
		data, _ := json.Marshal(rules)
		var ruleList []map[string]interface{}
		_ = json.Unmarshal(data, &ruleList)
		for _, r := range ruleList {
			_ = w.Write([]string{
				"process_block_rule",
				fmt.Sprint(r["id"]),
				fmt.Sprint(r["name"]),
				fmt.Sprint(r["enabled"]),
				fmt.Sprint(r["severity"]),
				fmt.Sprint(r["created_at"]),
			})
		}
	}
	w.Flush()
}

// Counts handles GET /api/v1/rules/counts
func (h *RulesIEHandler) Counts(c *gin.Context) {
	_, detTotal, _ := h.ruleStore.List(c.Request.Context(), store.RuleFilter{Limit: 1})
	_, procTotal, _ := h.processStore.List(c.Request.Context(), store.ProcessBlockRuleFilter{Limit: 1})
	c.JSON(http.StatusOK, gin.H{
		"detection_rules":     detTotal,
		"process_block_rules": procTotal,
	})
}

// parseImportRules reads rule objects from a bulk import request.
// It supports two input formats:
//  1. JSON body: {"rules": [...], "format": "json"}
//  2. Multipart file upload with field name "file" (JSON array or export envelope)
func parseImportRules(c *gin.Context) ([]map[string]interface{}, error) {
	contentType := c.GetHeader("Content-Type")

	// ── multipart upload ──────────────────────────────────────
	if strings.Contains(contentType, "multipart/form-data") {
		file, _, err := c.Request.FormFile("file")
		if err != nil {
			return nil, fmt.Errorf("ファイルの取得に失敗しました: %w", err)
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("ファイルの読み込みに失敗しました: %w", err)
		}
		return decodeRulePayload(data)
	}

	// ── JSON body ─────────────────────────────────────────────
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("リクエストボディの読み込みに失敗しました: %w", err)
	}
	return decodeRulePayload(data)
}

// decodeRulePayload tries to decode either:
//   - {"rules": [...], "format": "json"}  (export envelope)
//   - [...]  (bare array)
//   - {"detection_rules": [...]}  (export envelope with detection_rules key)
func decodeRulePayload(data []byte) ([]map[string]interface{}, error) {
	// Try envelope form first
	var envelope struct {
		Rules          []map[string]interface{} `json:"rules"`
		DetectionRules []map[string]interface{} `json:"detection_rules"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil {
		if len(envelope.Rules) > 0 {
			return envelope.Rules, nil
		}
		if len(envelope.DetectionRules) > 0 {
			return envelope.DetectionRules, nil
		}
	}

	// Try bare array
	var rules []map[string]interface{}
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("JSONのパースに失敗しました: %w", err)
	}
	return rules, nil
}

// validateImportRule validates a single rule map and converts it to a RuleRow.
// Returns (row, validationError string). If validationError is non-empty the row should be skipped.
func validateImportRule(raw map[string]interface{}) (*store.RuleRow, string) {
	name, _ := raw["name"].(string)
	if strings.TrimSpace(name) == "" {
		return nil, "nameが必要です"
	}
	content, _ := raw["content"].(string)
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Sprintf("ルール '%s': contentが必要です", name)
	}
	ruleType, _ := raw["type"].(string)
	if ruleType == "" {
		ruleType = "sigma"
	}
	if !validRuleTypes[ruleType] {
		return nil, fmt.Sprintf("ルール '%s': 無効なtype '%s' (sigma|yara|behavioral)", name, ruleType)
	}

	// Optional fields with defaults
	source, _ := raw["source"].(string)
	if source == "" {
		source = "import"
	}

	severity := 5
	if s, ok := raw["severity"]; ok {
		switch v := s.(type) {
		case float64:
			severity = int(v)
		case int:
			severity = v
		}
	}
	if severity < 1 || severity > 10 {
		severity = 5
	}

	enabled := false
	if e, ok := raw["enabled"].(bool); ok {
		enabled = e
	}

	platform := []string{"windows", "linux", "darwin"}
	if p, ok := raw["platform"].([]interface{}); ok && len(p) > 0 {
		platform = make([]string, 0, len(p))
		for _, v := range p {
			if s, ok := v.(string); ok {
				platform = append(platform, s)
			}
		}
	}

	var mitreTags []string
	if m, ok := raw["mitre_tags"].([]interface{}); ok {
		for _, v := range m {
			if s, ok := v.(string); ok {
				mitreTags = append(mitreTags, s)
			}
		}
	}

	var description *string
	if d, ok := raw["description"].(string); ok && d != "" {
		description = &d
	}

	autoIsolate, _ := raw["auto_isolate"].(bool)
	autoKill, _ := raw["auto_kill"].(bool)
	autoQuarantine, _ := raw["auto_quarantine"].(bool)

	falsePositiveRate := 0.0
	if f, ok := raw["false_positive_rate"].(float64); ok {
		falsePositiveRate = f
	}

	row := &store.RuleRow{
		ID:                uuid.New().String(),
		Name:              strings.TrimSpace(name),
		Type:              ruleType,
		Platform:          platform,
		Severity:          severity,
		Content:           content,
		Enabled:           enabled,
		Source:            source,
		MITRETags:         mitreTags,
		AutoIsolate:       autoIsolate,
		AutoKill:          autoKill,
		AutoQuarantine:    autoQuarantine,
		Description:       description,
		FalsePositiveRate: falsePositiveRate,
	}
	return row, ""
}

// Import handles POST /api/v1/rules/import/bulk
// Accepts JSON body {"rules": [...], "format": "json"} or multipart file upload.
// Skips rules whose name already exists in the database.
func (h *RulesIEHandler) Import(c *gin.Context) {
	ctx := c.Request.Context()

	rawRules, err := parseImportRules(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a set of existing rule names to detect duplicates.
	existing, _, err := h.ruleStore.List(ctx, store.RuleFilter{Limit: 100000})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "既存ルールの取得に失敗しました"})
		return
	}
	existingNames := make(map[string]bool, len(existing))
	for _, r := range existing {
		existingNames[r.Name] = true
	}

	var imported, skipped int
	var errs []string

	for i, raw := range rawRules {
		row, validErr := validateImportRule(raw)
		if validErr != "" {
			errs = append(errs, fmt.Sprintf("行 %d: %s", i+1, validErr))
			skipped++
			continue
		}

		if existingNames[row.Name] {
			skipped++
			continue
		}

		if err := h.ruleStore.Create(ctx, row); err != nil {
			errs = append(errs, fmt.Sprintf("ルール '%s': 保存に失敗しました: %s", row.Name, err.Error()))
			skipped++
			continue
		}

		existingNames[row.Name] = true // prevent within-batch duplicates
		imported++
	}

	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
	})
}

// ImportDryRun handles POST /api/v1/rules/import/dry-run
// Same parsing and validation as Import but does not insert any rows.
// Returns a preview of what would happen.
func (h *RulesIEHandler) ImportDryRun(c *gin.Context) {
	ctx := c.Request.Context()

	rawRules, err := parseImportRules(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a set of existing rule names.
	existing, _, err := h.ruleStore.List(ctx, store.RuleFilter{Limit: 100000})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "既存ルールの取得に失敗しました"})
		return
	}
	existingNames := make(map[string]bool, len(existing))
	for _, r := range existing {
		existingNames[r.Name] = true
	}

	var wouldImport, wouldSkip int
	var validRules []*store.RuleRow
	var errs []string
	seenNames := make(map[string]bool)

	for i, raw := range rawRules {
		row, validErr := validateImportRule(raw)
		if validErr != "" {
			errs = append(errs, fmt.Sprintf("行 %d: %s", i+1, validErr))
			wouldSkip++
			continue
		}

		if existingNames[row.Name] || seenNames[row.Name] {
			wouldSkip++
			continue
		}

		seenNames[row.Name] = true
		validRules = append(validRules, row)
		wouldImport++
	}

	// Ensure JSON encodes as [] rather than null when empty.
	if validRules == nil {
		validRules = []*store.RuleRow{}
	}
	if errs == nil {
		errs = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"would_import": wouldImport,
		"would_skip":   wouldSkip,
		"rules":        validRules,
		"errors":       errs,
	})
}

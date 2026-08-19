package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

// SigmaHandler converts Sigma rules to EDR detection rules.
// Sigma rule format: https://github.com/SigmaHQ/sigma
type SigmaHandler struct {
	pool *pgxpool.Pool
}

func NewSigmaHandler(pool *pgxpool.Pool) *SigmaHandler {
	return &SigmaHandler{pool: pool}
}

// SigmaRule represents a parsed Sigma rule (subset of full spec).
type SigmaRule struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Status         string                 `yaml:"status"`
	Description    string                 `yaml:"description"`
	Level          string                 `yaml:"level"` // informational, low, medium, high, critical
	Tags           []string               `yaml:"tags"`
	Author         string                 `yaml:"author"`
	Detection      map[string]interface{} `yaml:"detection"`
	Logsource      map[string]string      `yaml:"logsource"`
	FalsePositives []string               `yaml:"falsepositives"`
}

// sigmaPlatforms maps a Sigma rule's logsource.product to the rules.platform array.
//
// The two Sigma ingest paths disagreed. internal/sync/sigmahq.go's inferPlatforms
// has always derived platform from logsource (and the file's directory), but this
// handler — the manual `POST /rules/import/sigma` path — omitted the column
// entirely, so every rule imported through the UI took the DEFAULT
// ARRAY['windows','linux','darwin']: "runs everywhere".
//
// RuleEngine.platformMatchesEvent treats an all-OS list as universal and skips the
// gate, so a Windows-only rule (LSASS access, rundll32, registry run keys) was
// evaluated against every Linux process event. The gate exists precisely to stop
// that, and for UI-imported rules it was inert. The logsource was already parsed
// and written into content — only the column was left unset.
//
// Returning nil means "leave it to the DEFAULT", the deliberate fail-open for rules
// whose logsource names no product: SigmaHQ category-only rules (logsource:
// category: process_creation) really are cross-platform, and guessing an OS for
// them would drop real detections. Same philosophy as platformMatchesEvent — the
// gate removes clear mismatches, never real detections.
//
// Spellings match inferPlatforms so the two paths produce comparable rows;
// canonPlatform folds darwin/macos together on the read side either way.
func sigmaPlatforms(logsource map[string]string) []string {
	switch strings.ToLower(strings.TrimSpace(logsource["product"])) {
	case "windows":
		return []string{"windows"}
	case "linux":
		return []string{"linux"}
	case "macos", "darwin":
		return []string{"macos"}
	default:
		return nil
	}
}

// sigmaLevelToSeverity converts Sigma severity level to a SMALLINT (1-10).
// Schema: severity SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 10)
func sigmaLevelToSeverityInt(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 2
	}
}

// sigmaLevelToSeverityText returns a human-readable label for API responses.
func sigmaLevelToSeverityText(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// ImportSigma handles POST /api/v1/rules/import/sigma
// Accepts multipart file upload or raw YAML body.
func (h *SigmaHandler) ImportSigma(c *gin.Context) {
	var yamlContent []byte

	// Try multipart file first.
	file, _, err := c.Request.FormFile("file")
	if err == nil {
		defer file.Close()
		yamlContent, err = io.ReadAll(io.LimitReader(file, 1*1024*1024)) // 1MB max
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ファイルの読み取りに失敗しました"})
			return
		}
	} else {
		// Try raw body.
		yamlContent, err = io.ReadAll(io.LimitReader(c.Request.Body, 1*1024*1024))
		if err != nil || len(yamlContent) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SigmaルールのYAMLが必要です"})
			return
		}
	}

	// Parse one or multiple rules (separated by ---).
	parts := strings.Split(string(yamlContent), "\n---\n")
	var imported, skipped, failed int
	var errors []string
	var importedRules []map[string]interface{}

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var sigma SigmaRule
		if err := yaml.Unmarshal([]byte(part), &sigma); err != nil {
			failed++
			errors = append(errors, fmt.Sprintf("ルール%d: YAMLパースエラー: %v", i+1, err))
			continue
		}
		if sigma.Title == "" {
			skipped++
			continue
		}

		// Build description.
		description := sigma.Description
		if description == "" {
			description = fmt.Sprintf("Sigmaルール: %s", sigma.Title)
		}
		if sigma.Author != "" {
			description += fmt.Sprintf("\n作成者: %s", sigma.Author)
		}

		// Convert detection to a text blob stored in content.
		// The rules.content column stores the raw rule content as TEXT.
		contentYAML, _ := yaml.Marshal(map[string]interface{}{
			"title":     sigma.Title,
			"id":        sigma.ID,
			"level":     sigma.Level,
			"detection": sigma.Detection,
			"logsource": sigma.Logsource,
		})
		content := string(contentYAML)

		severityInt := sigmaLevelToSeverityInt(sigma.Level)
		severityText := sigmaLevelToSeverityText(sigma.Level)

		// Insert rule.
		// Schema columns: id, name, type, platform, severity (SMALLINT), content (TEXT),
		//                 enabled, source (CHECK: community|custom|threat-intel|ai-generated),
		//                 description, tags
		// 'sigma' is not a valid source value; use 'community' for imported Sigma rules.
		//
		// platform is passed as NULL when the logsource names no product, so the
		// column DEFAULT (all OSes = universal) applies. COALESCE keeps that default
		// reachable through a bound parameter.
		var ruleID string
		err := h.pool.QueryRow(c.Request.Context(),
			`INSERT INTO rules (name, type, platform, severity, content, description, enabled, source, tags)
			 VALUES ($1, 'sigma',
			         COALESCE($6::TEXT[], ARRAY['windows','linux','darwin']),
			         $2, $3, $4, true, 'community', $5)
			 RETURNING id`,
			sigma.Title, severityInt, content, description, sigma.Tags,
			sigmaPlatforms(sigma.Logsource),
		).Scan(&ruleID)

		if err != nil {
			failed++
			errors = append(errors, fmt.Sprintf("ルール '%s': 保存失敗", sigma.Title))
			slog.Error("Sigmaルール保存失敗", "title", sigma.Title, "error", err)
			continue
		}

		imported++
		importedRules = append(importedRules, map[string]interface{}{
			"id": ruleID, "name": sigma.Title, "severity": severityText,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"skipped":  skipped,
		"failed":   failed,
		"errors":   errors,
		"rules":    importedRules,
	})
}

// ParsePreview handles POST /api/v1/rules/import/sigma/preview
// Returns parsed rule info without importing.
func (h *SigmaHandler) ParsePreview(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 512*1024))
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "YAMLが必要です"})
		return
	}
	var sigma SigmaRule
	if err := yaml.Unmarshal(body, &sigma); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "YAMLパースエラー: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"title":       sigma.Title,
		"severity":    sigmaLevelToSeverityText(sigma.Level),
		"description": sigma.Description,
		"tags":        sigma.Tags,
		"author":      sigma.Author,
		"logsource":   sigma.Logsource,
		"detection":   sigma.Detection,
	})
}

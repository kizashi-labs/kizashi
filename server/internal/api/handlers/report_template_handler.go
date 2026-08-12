package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ReportTemplateHandler provides CRUD + preview endpoints for report templates.
type ReportTemplateHandler struct {
	Store *store.ReportTemplateStore
	pool  *pgxpool.Pool
}

// NewReportTemplateHandler creates a new ReportTemplateHandler.
func NewReportTemplateHandler(s *store.ReportTemplateStore, pool *pgxpool.Pool) *ReportTemplateHandler {
	return &ReportTemplateHandler{Store: s, pool: pool}
}

// List returns all report templates.
// GET /api/v1/report-templates
func (h *ReportTemplateHandler) List(c *gin.Context) {
	templates, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list report templates"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": templates, "total": len(templates)})
}

// Get returns a single report template by ID.
// GET /api/v1/report-templates/:id
func (h *ReportTemplateHandler) Get(c *gin.Context) {
	id := c.Param("id")
	t, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Report template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get report template"})
		return
	}
	c.JSON(http.StatusOK, t)
}

// Create adds a new report template.
// POST /api/v1/report-templates
func (h *ReportTemplateHandler) Create(c *gin.Context) {
	var req struct {
		Name        string                        `json:"name"        binding:"required"`
		Description string                        `json:"description"`
		Sections    []store.ReportTemplateSection `json:"sections"`
		Variables   map[string]interface{}        `json:"variables"`
		Format      string                        `json:"format"`
		Enabled     *bool                         `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	if req.Format == "" {
		req.Format = "pdf"
	}
	if req.Format != "pdf" && req.Format != "html" && req.Format != "csv" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format must be pdf, html, or csv"})
		return
	}
	if req.Sections == nil {
		req.Sections = []store.ReportTemplateSection{}
	}
	if req.Variables == nil {
		req.Variables = map[string]interface{}{}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	t := &store.ReportTemplate{
		Name:        req.Name,
		Description: req.Description,
		Sections:    req.Sections,
		Variables:   req.Variables,
		Format:      req.Format,
		Enabled:     enabled,
		CreatedBy:   &uid,
	}

	id, err := h.Store.Create(c.Request.Context(), t)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create report template"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Report template created", "id": id})
}

// Update modifies an existing report template.
// PUT /api/v1/report-templates/:id
func (h *ReportTemplateHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name        string                        `json:"name"        binding:"required"`
		Description string                        `json:"description"`
		Sections    []store.ReportTemplateSection `json:"sections"`
		Variables   map[string]interface{}        `json:"variables"`
		Format      string                        `json:"format"`
		Enabled     *bool                         `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	if req.Format == "" {
		req.Format = "pdf"
	}
	if req.Sections == nil {
		req.Sections = []store.ReportTemplateSection{}
	}
	if req.Variables == nil {
		req.Variables = map[string]interface{}{}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	t := &store.ReportTemplate{
		Name:        req.Name,
		Description: req.Description,
		Sections:    req.Sections,
		Variables:   req.Variables,
		Format:      req.Format,
		Enabled:     enabled,
	}

	if err := h.Store.Update(c.Request.Context(), id, t); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Report template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update report template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Report template updated"})
}

// Delete removes a report template.
// DELETE /api/v1/report-templates/:id
func (h *ReportTemplateHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Report template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete report template"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Report template deleted"})
}

// Preview renders a mock preview of a report template.
// POST /api/v1/report-templates/:id/preview
func (h *ReportTemplateHandler) Preview(c *gin.Context) {
	id := c.Param("id")
	t, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Report template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get report template"})
		return
	}

	preview := buildPreview(c.Request.Context(), h.pool, t)
	c.JSON(http.StatusOK, preview)
}

// ─── Preview builder ─────────────────────────────────────────────────────────

type previewSection struct {
	Type    string      `json:"type"`
	Title   string      `json:"title"`
	Content interface{} `json:"content"`
}

type previewResult struct {
	TemplateID   string           `json:"template_id"`
	TemplateName string           `json:"template_name"`
	Format       string           `json:"format"`
	GeneratedAt  time.Time        `json:"generated_at"`
	Sections     []previewSection `json:"sections"`
	Note         string           `json:"note"`
}

func buildPreview(ctx context.Context, pool *pgxpool.Pool, t *store.ReportTemplate) previewResult {
	sections := make([]previewSection, 0, len(t.Sections))
	for _, sec := range t.Sections {
		content := buildSectionContent(ctx, pool, sec)
		sections = append(sections, previewSection{
			Type:    sec.Type,
			Title:   sec.Title,
			Content: content,
		})
	}
	return previewResult{
		TemplateID:   t.ID,
		TemplateName: t.Name,
		Format:       t.Format,
		GeneratedAt:  time.Now().UTC(),
		Sections:     sections,
		Note:         "プレビューは実データから生成されます。",
	}
}

func buildSectionContent(ctx context.Context, pool *pgxpool.Pool, sec store.ReportTemplateSection) interface{} {
	now := time.Now().UTC()

	// queryInt runs a COUNT query and returns 0 on error.
	queryInt := func(sql string, args ...interface{}) int {
		if pool == nil {
			return 0
		}
		var n int
		if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			slog.Warn("report_template: queryInt failed", "sql", sql, "error", err)
		}
		return n
	}

	switch sec.Type {
	case "summary":
		total := queryInt(`SELECT COUNT(*) FROM alerts`)
		critical := queryInt(`SELECT COUNT(*) FROM alerts WHERE severity >= 9`)
		high := queryInt(`SELECT COUNT(*) FROM alerts WHERE severity >= 7 AND severity < 9`)
		medium := queryInt(`SELECT COUNT(*) FROM alerts WHERE severity >= 4 AND severity < 7`)
		low := queryInt(`SELECT COUNT(*) FROM alerts WHERE severity < 4`)
		activeAgents := queryInt(`SELECT COUNT(*) FROM agents WHERE last_seen >= NOW() - INTERVAL '10 minutes'`)
		totalAgents := queryInt(`SELECT COUNT(*) FROM agents`)
		openIncidents := queryInt(`SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')`)
		return map[string]interface{}{
			"total_alerts":    total,
			"critical_alerts": critical,
			"high_alerts":     high,
			"medium_alerts":   medium,
			"low_alerts":      low,
			"active_agents":   activeAgents,
			"offline_agents":  totalAgents - activeAgents,
			"open_incidents":  openIncidents,
			"period_start":    now.AddDate(0, 0, -30).Format(time.RFC3339),
			"period_end":      now.Format(time.RFC3339),
		}

	case "alert_table":
		var alerts []map[string]interface{}
		if pool != nil {
			rows, err := pool.Query(ctx,
				`SELECT id::text, title, severity, status, created_at
				 FROM alerts ORDER BY created_at DESC LIMIT 5`)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var id, title, status string
					var severity int
					var createdAt time.Time
					if err := rows.Scan(&id, &title, &severity, &status, &createdAt); err == nil {
						alerts = append(alerts, map[string]interface{}{
							"id": id, "title": title, "severity": severity,
							"status": status, "created_at": createdAt.Format(time.RFC3339),
						})
					}
				}
				if err := rows.Err(); err != nil {
					slog.Warn("row iteration error", "error", err)
				}
			}
		}
		if alerts == nil {
			alerts = []map[string]interface{}{}
		}
		total := queryInt(`SELECT COUNT(*) FROM alerts`)
		return map[string]interface{}{"total": total, "showing": len(alerts), "alerts": alerts}

	case "chart":
		days := 7
		if d, ok := sec.Config["days"]; ok {
			if df, ok := d.(float64); ok {
				days = int(df)
			}
		}
		points := make([]map[string]interface{}, days)
		for i := 0; i < days; i++ {
			day := now.AddDate(0, 0, -(days - 1 - i))
			dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
			dayEnd := dayStart.Add(24 * time.Hour)
			points[i] = map[string]interface{}{
				"date":     day.Format("2006-01-02"),
				"critical": queryInt(`SELECT COUNT(*) FROM alerts WHERE severity>=9 AND created_at>=$1 AND created_at<$2`, dayStart, dayEnd),
				"high":     queryInt(`SELECT COUNT(*) FROM alerts WHERE severity>=7 AND severity<9 AND created_at>=$1 AND created_at<$2`, dayStart, dayEnd),
				"medium":   queryInt(`SELECT COUNT(*) FROM alerts WHERE severity>=4 AND severity<7 AND created_at>=$1 AND created_at<$2`, dayStart, dayEnd),
				"low":      queryInt(`SELECT COUNT(*) FROM alerts WHERE severity<4 AND created_at>=$1 AND created_at<$2`, dayStart, dayEnd),
			}
		}
		return map[string]interface{}{"chart_type": "line", "days": days, "data": points}

	case "agent_overview":
		total := queryInt(`SELECT COUNT(*) FROM agents`)
		online := queryInt(`SELECT COUNT(*) FROM agents WHERE last_seen >= NOW() - INTERVAL '10 minutes'`)
		// 列名は os ではなく os_type。os は存在しないため 42703 で失敗し、
		// queryInt がエラーを握り潰すので platforms は常に 0/0/0 だった。
		windows := queryInt(`SELECT COUNT(*) FROM agents WHERE os_type='windows'`)
		linux := queryInt(`SELECT COUNT(*) FROM agents WHERE os_type='linux'`)
		macos := queryInt(`SELECT COUNT(*) FROM agents WHERE os_type='darwin'`)
		return map[string]interface{}{
			"total": total, "online": online, "offline": total - online,
			"platforms": map[string]int{"windows": windows, "linux": linux, "macos": macos},
		}

	case "threat_stats":
		var topTags []map[string]interface{}
		if pool != nil {
			rows, err := pool.Query(ctx,
				`SELECT mitre_technique as tag, COUNT(*) as cnt
				 FROM alerts WHERE mitre_technique IS NOT NULL AND mitre_technique <> ''
				 GROUP BY mitre_technique ORDER BY cnt DESC LIMIT 5`)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var tag string
					var cnt int
					if err := rows.Scan(&tag, &cnt); err == nil {
						topTags = append(topTags, map[string]interface{}{"id": tag, "count": cnt})
					}
				}
				if err := rows.Err(); err != nil {
					slog.Warn("row iteration error", "error", err)
				}
			}
		}
		if topTags == nil {
			topTags = []map[string]interface{}{}
		}
		return map[string]interface{}{"mitre_techniques": topTags}

	case "compliance_status":
		var frameworks []map[string]interface{}
		if pool != nil {
			rows, err := pool.Query(ctx,
				// 組織全体スコアは compliance_score_history にある
				// (compliance_scores はエージェント単位、migration 367 を参照)。
				`SELECT DISTINCT ON (framework) framework, score
				 FROM compliance_score_history
				 ORDER BY framework, calculated_at DESC`)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var fw string
					var score float64
					if err := rows.Scan(&fw, &score); err == nil {
						frameworks = append(frameworks, map[string]interface{}{"name": fw, "score": score})
					}
				}
				if err := rows.Err(); err != nil {
					slog.Warn("row iteration error", "error", err)
				}
			}
		}
		if frameworks == nil {
			frameworks = []map[string]interface{}{}
		}
		return map[string]interface{}{"frameworks": frameworks}

	case "incident_list":
		var incidents []map[string]interface{}
		if pool != nil {
			rows, err := pool.Query(ctx,
				`SELECT id::text, title, status, severity::text FROM incidents ORDER BY created_at DESC LIMIT 5`)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var id, title, status, severity string
					if err := rows.Scan(&id, &title, &status, &severity); err == nil {
						incidents = append(incidents, map[string]interface{}{
							"id": id, "title": title, "status": status, "severity": severity,
						})
					}
				}
				if err := rows.Err(); err != nil {
					slog.Warn("row iteration error", "error", err)
				}
			}
		}
		if incidents == nil {
			incidents = []map[string]interface{}{}
		}
		total := queryInt(`SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')`)
		return map[string]interface{}{"total": total, "incidents": incidents}

	case "custom_text":
		text := "カスタムセクションのコンテンツをここに記述してください。"
		if t, ok := sec.Config["text"]; ok {
			if ts, ok := t.(string); ok {
				text = ts
			}
		}
		return map[string]interface{}{"text": text}

	default:
		return map[string]interface{}{}
	}
}

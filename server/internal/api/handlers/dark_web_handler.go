package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DarkWebHandler provides dark web monitoring endpoints.
// GET    /api/v1/dark-web/findings
// PUT    /api/v1/dark-web/findings/:id
// GET    /api/v1/dark-web/keywords
// GET    /api/v1/dark-web/integrations
type DarkWebHandler struct {
	pool *pgxpool.Pool
}

func NewDarkWebHandler(pool *pgxpool.Pool) *DarkWebHandler {
	return &DarkWebHandler{pool: pool}
}

func (h *DarkWebHandler) tableExists(c *gin.Context, name string) bool {
	return tableIsThere(c.Request.Context(), h.pool, name)
}

// ListFindings returns dark web findings.
// GET /api/v1/dark-web/findings
func (h *DarkWebHandler) ListFindings(c *gin.Context) {
	ctx := c.Request.Context()

	type Finding struct {
		ID           string `json:"id"`
		Type         string `json:"type"`
		Title        string `json:"title"`
		Source       string `json:"source"`
		Severity     string `json:"severity"`
		Preview      string `json:"preview"`
		DiscoveredAt string `json:"discovered_at"`
		Status       string `json:"status"`
	}

	if !h.tableExists(c, "dark_web_findings") {
		c.JSON(http.StatusOK, []Finding{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, finding_type, title, source, severity,
		       COALESCE(preview,''), discovered_at, status
		FROM dark_web_findings ORDER BY discovered_at DESC LIMIT 200`)
	if err != nil {
		ReadFailure(c, err, []Finding{})
		return
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var ts time.Time
		if rows.Scan(&f.ID, &f.Type, &f.Title, &f.Source, &f.Severity,
			&f.Preview, &ts, &f.Status) == nil {
			f.DiscoveredAt = ts.Format(time.RFC3339)
			findings = append(findings, f)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListFindings: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []Finding{})
		return
	}
	if findings == nil {
		findings = []Finding{}
	}
	c.JSON(http.StatusOK, findings)
}

// UpdateFinding updates the status of a dark web finding.
// PUT /api/v1/dark-web/findings/:id
func (h *DarkWebHandler) UpdateFinding(c *gin.Context) {
	id := c.Param("id")
	var in struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.tableExists(c, "dark_web_findings") {
		if _, err := h.pool.Exec(c.Request.Context(),
			`UPDATE dark_web_findings SET status=$2, updated_at=NOW() WHERE id=$1`, id, in.Status); !WriteOK(c, err) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// ListKeywords returns monitored keywords.
// GET /api/v1/dark-web/keywords
func (h *DarkWebHandler) ListKeywords(c *gin.Context) {
	ctx := c.Request.Context()

	type Keyword struct {
		ID            string  `json:"id"`
		Keyword       string  `json:"keyword"`
		Category      string  `json:"category"`
		Enabled       bool    `json:"enabled"`
		LastMatchDate *string `json:"last_match_date"`
		MatchCount    int     `json:"match_count"`
	}

	if !h.tableExists(c, "dark_web_keywords") {
		c.JSON(http.StatusOK, []Keyword{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, keyword, COALESCE(category,'brand'), enabled,
		       last_match_date, match_count
		FROM dark_web_keywords ORDER BY created_at DESC`)
	if err != nil {
		ReadFailure(c, err, []Keyword{})
		return
	}
	defer rows.Close()

	var keywords []Keyword
	for rows.Next() {
		var k Keyword
		var lmd *time.Time
		if rows.Scan(&k.ID, &k.Keyword, &k.Category, &k.Enabled, &lmd, &k.MatchCount) == nil {
			if lmd != nil {
				s := lmd.Format(time.RFC3339)
				k.LastMatchDate = &s
			}
			keywords = append(keywords, k)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListKeywords: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []Keyword{})
		return
	}
	if keywords == nil {
		keywords = []Keyword{}
	}
	c.JSON(http.StatusOK, keywords)
}

// ListIntegrations returns configured dark web monitoring integrations.
// GET /api/v1/dark-web/integrations
func (h *DarkWebHandler) ListIntegrations(c *gin.Context) {
	// Return static list of available integrations; configuration comes from integration_configs.
	integrations := []gin.H{
		{"id": "intel471", "name": "Intel 471", "description": "企業・個人情報の漏洩監視サービス", "configured": false},
		{"id": "flashpoint", "name": "Flashpoint", "description": "ダークウェブインテリジェンスプラットフォーム", "configured": false},
		{"id": "recorded_future", "name": "Recorded Future", "description": "ブランド保護・ダークウェブ監視", "configured": false},
	}

	// Check if any are configured in integration_configs table.
	ctx := c.Request.Context()
	if h.tableExists(c, "integration_configs") {
		for i, integ := range integrations {
			var enabled bool
			if !ReadOK(c, h.pool.QueryRow(ctx,
				`SELECT enabled FROM integration_configs WHERE integ_type=$1`, integ["id"]).Scan(&enabled)) {
				return
			}
			integrations[i]["configured"] = enabled
		}
	}

	c.JSON(http.StatusOK, integrations)
}

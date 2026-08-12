package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EndpointHardeningHandler struct{ pool *pgxpool.Pool }

func NewEndpointHardeningHandler(pool *pgxpool.Pool) *EndpointHardeningHandler {
	return &EndpointHardeningHandler{pool: pool}
}

func (h *EndpointHardeningHandler) ListBaselines(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, COALESCE(description,''), os_type, framework, COALESCE(version,''), enabled, created_at
		FROM hardening_baselines ORDER BY os_type, framework, name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"baselines": []any{}})
		return
	}
	defer rows.Close()

	type Baseline struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		OSType      string `json:"os_type"`
		Framework   string `json:"framework"`
		Version     string `json:"version"`
		Enabled     bool   `json:"enabled"`
		CreatedAt   string `json:"created_at"`
	}
	var list []Baseline
	for rows.Next() {
		var b Baseline
		var createdAt time.Time
		if err := rows.Scan(&b.ID, &b.Name, &b.Description, &b.OSType, &b.Framework, &b.Version, &b.Enabled, &createdAt); err != nil {
			continue
		}
		b.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, b)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Baseline{}
	}
	c.JSON(http.StatusOK, gin.H{"baselines": list})
}

func (h *EndpointHardeningHandler) ListAssessments(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT a.id, a.agent_id, COALESCE(ag.hostname, a.agent_id::text),
		       COALESCE(b.name,'Unknown'), a.passed_checks, a.failed_checks, a.score, a.status, a.assessed_at, a.created_at
		FROM hardening_assessments a
		LEFT JOIN agents ag ON ag.id = a.agent_id
		LEFT JOIN hardening_baselines b ON b.id = a.baseline_id
		ORDER BY a.created_at DESC LIMIT 100
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"assessments": []any{}})
		return
	}
	defer rows.Close()

	type Assessment struct {
		ID           string  `json:"id"`
		AgentID      string  `json:"agent_id"`
		Hostname     string  `json:"hostname"`
		BaselineName string  `json:"baseline_name"`
		PassedChecks int     `json:"passed_checks"`
		FailedChecks int     `json:"failed_checks"`
		Score        float64 `json:"score"`
		Status       string  `json:"status"`
		AssessedAt   *string `json:"assessed_at"`
		CreatedAt    string  `json:"created_at"`
	}
	var list []Assessment
	for rows.Next() {
		var a Assessment
		var assessedAt *time.Time
		var createdAt time.Time
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Hostname, &a.BaselineName,
			&a.PassedChecks, &a.FailedChecks, &a.Score, &a.Status, &assessedAt, &createdAt); err != nil {
			continue
		}
		a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if assessedAt != nil {
			s := assessedAt.UTC().Format(time.RFC3339)
			a.AssessedAt = &s
		}
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Assessment{}
	}
	c.JSON(http.StatusOK, gin.H{"assessments": list})
}

func (h *EndpointHardeningHandler) Stats(c *gin.Context) {
	var total, compliant int
	var avgScore float64
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE score >= 80),
		       COALESCE(AVG(score), 0)
		FROM hardening_assessments WHERE status='completed'
	`).Scan(&total, &compliant, &avgScore)
	var baselines int
	h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM hardening_baselines WHERE enabled=true`).Scan(&baselines)
	c.JSON(http.StatusOK, gin.H{
		"total_assessments": total,
		"compliant":         compliant,
		"avg_score":         avgScore,
		"active_baselines":  baselines,
	})
}

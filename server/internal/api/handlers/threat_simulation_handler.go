package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ThreatSimulationHandler struct{ pool *pgxpool.Pool }

func NewThreatSimulationHandler(pool *pgxpool.Pool) *ThreatSimulationHandler {
	return &ThreatSimulationHandler{pool: pool}
}

func (h *ThreatSimulationHandler) ListTemplates(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, description, category, mitre_tactics, mitre_techniques, enabled, created_at
		FROM simulation_templates ORDER BY category, name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"templates": []any{}})
		return
	}
	defer rows.Close()

	type Tmpl struct {
		ID              string   `json:"id"`
		Name            string   `json:"name"`
		Description     string   `json:"description"`
		Category        string   `json:"category"`
		MitreTactics    []string `json:"mitre_tactics"`
		MitreTechniques []string `json:"mitre_techniques"`
		Enabled         bool     `json:"enabled"`
		CreatedAt       string   `json:"created_at"`
	}
	var list []Tmpl
	for rows.Next() {
		var t Tmpl
		var createdAt time.Time
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Category, &t.MitreTactics, &t.MitreTechniques, &t.Enabled, &createdAt); err != nil {
			continue
		}
		t.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, t)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Tmpl{}
	}
	c.JSON(http.StatusOK, gin.H{"templates": list})
}

func (h *ThreatSimulationHandler) ListRuns(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT r.id, r.name, r.status, r.detections_count, r.missed_count, r.started_at, r.completed_at, r.created_at
		FROM simulation_runs r
		ORDER BY r.created_at DESC LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"runs": []any{}})
		return
	}
	defer rows.Close()

	type Run struct {
		ID              string  `json:"id"`
		Name            string  `json:"name"`
		Status          string  `json:"status"`
		DetectionsCount int     `json:"detections_count"`
		MissedCount     int     `json:"missed_count"`
		StartedAt       *string `json:"started_at"`
		CompletedAt     *string `json:"completed_at"`
		CreatedAt       string  `json:"created_at"`
	}
	var list []Run
	for rows.Next() {
		var r Run
		var startedAt, completedAt *time.Time
		var createdAt time.Time
		if err := rows.Scan(&r.ID, &r.Name, &r.Status, &r.DetectionsCount, &r.MissedCount, &startedAt, &completedAt, &createdAt); err != nil {
			continue
		}
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if startedAt != nil {
			s := startedAt.UTC().Format(time.RFC3339)
			r.StartedAt = &s
		}
		if completedAt != nil {
			s := completedAt.UTC().Format(time.RFC3339)
			r.CompletedAt = &s
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Run{}
	}
	c.JSON(http.StatusOK, gin.H{"runs": list})
}

func (h *ThreatSimulationHandler) StartRun(c *gin.Context) {
	var req struct {
		TemplateID   string   `json:"template_id" binding:"required"`
		Name         string   `json:"name" binding:"required"`
		TargetAgents []string `json:"target_agents"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO simulation_runs (template_id, name, target_agents, status, started_at)
		VALUES ($1, $2, $3, 'running', NOW()) RETURNING id
	`, req.TemplateID, req.Name, req.TargetAgents).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "running"})
}

func (h *ThreatSimulationHandler) SimStats(c *gin.Context) {
	var total, completed, running int
	var avgDetection float64
	if err := h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE status='completed'),
		       COUNT(*) FILTER (WHERE status='running'),
		       COALESCE(AVG(detections_count::float / NULLIF(detections_count+missed_count,0)*100) FILTER (WHERE status='completed'), 0)
		FROM simulation_runs
	`).Scan(&total, &completed, &running, &avgDetection); err != nil {
		slog.Warn("threat simulation: 集計クエリに失敗しました", "error", err)
	}
	c.JSON(http.StatusOK, gin.H{
		"total":              total,
		"completed":          completed,
		"running":            running,
		"avg_detection_rate": avgDetection,
	})
}

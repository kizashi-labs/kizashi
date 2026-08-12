package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecuritySLAHandler struct{ pool *pgxpool.Pool }

func NewSecuritySLAHandler(pool *pgxpool.Pool) *SecuritySLAHandler {
	return &SecuritySLAHandler{pool: pool}
}

func (h *SecuritySLAHandler) ListPolicies(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, severity, response_minutes, resolution_hours, escalation_hours, enabled, created_at
		FROM sla_policies ORDER BY severity, name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"policies": []any{}})
		return
	}
	defer rows.Close()

	type Policy struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Severity        string `json:"severity"`
		ResponseMinutes int    `json:"response_minutes"`
		ResolutionHours int    `json:"resolution_hours"`
		EscalationHours int    `json:"escalation_hours"`
		Enabled         bool   `json:"enabled"`
		CreatedAt       string `json:"created_at"`
	}
	var list []Policy
	for rows.Next() {
		var p Policy
		var createdAt time.Time
		if err := rows.Scan(&p.ID, &p.Name, &p.Severity, &p.ResponseMinutes, &p.ResolutionHours, &p.EscalationHours, &p.Enabled, &createdAt); err != nil {
			continue
		}
		p.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Policy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": list})
}

func (h *SecuritySLAHandler) CreatePolicy(c *gin.Context) {
	var req struct {
		Name            string `json:"name" binding:"required"`
		Severity        string `json:"severity" binding:"required"`
		ResponseMinutes int    `json:"response_minutes"`
		ResolutionHours int    `json:"resolution_hours"`
		EscalationHours int    `json:"escalation_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ResponseMinutes == 0 {
		req.ResponseMinutes = 60
	}
	if req.ResolutionHours == 0 {
		req.ResolutionHours = 24
	}
	if req.EscalationHours == 0 {
		req.EscalationHours = 8
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO sla_policies (name, severity, response_minutes, resolution_hours, escalation_hours)
		VALUES ($1,$2,$3,$4,$5) RETURNING id
	`, req.Name, req.Severity, req.ResponseMinutes, req.ResolutionHours, req.EscalationHours).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *SecuritySLAHandler) SLAStats(c *gin.Context) {
	var total, responsBreached, resolBreached int
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE response_breached),
		       COUNT(*) FILTER (WHERE resolution_breached)
		FROM sla_tracking
	`).Scan(&total, &responsBreached, &resolBreached)
	c.JSON(http.StatusOK, gin.H{
		"total":               total,
		"response_breached":   responsBreached,
		"resolution_breached": resolBreached,
		"compliance_rate": func() float64 {
			if total == 0 {
				return 100.0
			}
			return float64(total-responsBreached-resolBreached) / float64(total) * 100
		}(),
	})
}

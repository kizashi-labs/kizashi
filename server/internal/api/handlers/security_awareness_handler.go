package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecurityAwarenessHandler struct{ pool *pgxpool.Pool }

func NewSecurityAwarenessHandler(pool *pgxpool.Pool) *SecurityAwarenessHandler {
	return &SecurityAwarenessHandler{pool: pool}
}

func (h *SecurityAwarenessHandler) ListCourses(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, title, COALESCE(description,''), category, duration_minutes, difficulty, passing_score, mandatory, enabled, created_at
		FROM awareness_courses ORDER BY mandatory DESC, category, title
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"courses": []any{}})
		return
	}
	defer rows.Close()

	type Course struct {
		ID              string `json:"id"`
		Title           string `json:"title"`
		Description     string `json:"description"`
		Category        string `json:"category"`
		DurationMinutes int    `json:"duration_minutes"`
		Difficulty      string `json:"difficulty"`
		PassingScore    int    `json:"passing_score"`
		Mandatory       bool   `json:"mandatory"`
		Enabled         bool   `json:"enabled"`
		CreatedAt       string `json:"created_at"`
	}
	var list []Course
	for rows.Next() {
		var course Course
		var createdAt time.Time
		if err := rows.Scan(&course.ID, &course.Title, &course.Description, &course.Category,
			&course.DurationMinutes, &course.Difficulty, &course.PassingScore,
			&course.Mandatory, &course.Enabled, &createdAt); err != nil {
			continue
		}
		course.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, course)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Course{}
	}
	c.JSON(http.StatusOK, gin.H{"courses": list})
}

func (h *SecurityAwarenessHandler) ListSimulations(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, template, target_count, sent_count, opened_count, clicked_count,
		       reported_count, credentials_entered, status, created_at
		FROM phishing_simulations ORDER BY created_at DESC LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"simulations": []any{}})
		return
	}
	defer rows.Close()

	type Sim struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		Template           string `json:"template"`
		TargetCount        int    `json:"target_count"`
		SentCount          int    `json:"sent_count"`
		OpenedCount        int    `json:"opened_count"`
		ClickedCount       int    `json:"clicked_count"`
		ReportedCount      int    `json:"reported_count"`
		CredentialsEntered int    `json:"credentials_entered"`
		Status             string `json:"status"`
		CreatedAt          string `json:"created_at"`
	}
	var list []Sim
	for rows.Next() {
		var s Sim
		var createdAt time.Time
		if err := rows.Scan(&s.ID, &s.Name, &s.Template, &s.TargetCount, &s.SentCount,
			&s.OpenedCount, &s.ClickedCount, &s.ReportedCount, &s.CredentialsEntered,
			&s.Status, &createdAt); err != nil {
			continue
		}
		s.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Sim{}
	}
	c.JSON(http.StatusOK, gin.H{"simulations": list})
}

func (h *SecurityAwarenessHandler) Stats(c *gin.Context) {
	var courses, mandatory int
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE mandatory=true)
		FROM awareness_courses WHERE enabled=true
	`).Scan(&courses, &mandatory)
	var totalEnroll, completed int
	var avgScore float64
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE status='completed'),
		       COALESCE(AVG(score) FILTER (WHERE status='completed'), 0)
		FROM awareness_enrollments
	`).Scan(&totalEnroll, &completed, &avgScore)
	completionRate := 0.0
	if totalEnroll > 0 {
		completionRate = float64(completed) / float64(totalEnroll) * 100
	}
	c.JSON(http.StatusOK, gin.H{
		"total_courses":     courses,
		"mandatory_courses": mandatory,
		"enrollments":       totalEnroll,
		"completed":         completed,
		"avg_score":         avgScore,
		"completion_rate":   completionRate,
	})
}

package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ShiftHandler manages SOC shift handover.
type ShiftHandler struct {
	pool *pgxpool.Pool
}

// NewShiftHandler creates a new ShiftHandler.
func NewShiftHandler(pool *pgxpool.Pool) *ShiftHandler {
	return &ShiftHandler{pool: pool}
}

type shiftRow struct {
	ID            string          `json:"id"`
	ShiftName     string          `json:"shift_name"`
	ShiftDate     time.Time       `json:"shift_date"`
	StartTime     time.Time       `json:"start_time"`
	EndTime       *time.Time      `json:"end_time"`
	LeadAnalystID *string         `json:"lead_analyst_id"`
	TeamMembers   json.RawMessage `json:"team_members"`
	Status        string          `json:"status"`
	HandoverNotes string          `json:"handover_notes"`
	OpenIncidents json.RawMessage `json:"open_incidents"`
	PendingTasks  json.RawMessage `json:"pending_tasks"`
	Metrics       json.RawMessage `json:"metrics"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

const shiftSelectCols = `id, shift_name, shift_date, start_time, end_time, lead_analyst_id,
	team_members, status, handover_notes, open_incidents, pending_tasks, metrics, created_at, updated_at`

// List GET /soc/shifts
func (h *ShiftHandler) List(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT `+shiftSelectCols+`
		 FROM soc_shifts
		 WHERE shift_date >= NOW() - INTERVAL '30 days'
		 ORDER BY shift_date DESC, start_time DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list shifts"})
		return
	}
	defer rows.Close()

	shifts := []shiftRow{}
	for rows.Next() {
		var s shiftRow
		if err := rows.Scan(&s.ID, &s.ShiftName, &s.ShiftDate, &s.StartTime, &s.EndTime,
			&s.LeadAnalystID, &s.TeamMembers, &s.Status, &s.HandoverNotes,
			&s.OpenIncidents, &s.PendingTasks, &s.Metrics, &s.CreatedAt, &s.UpdatedAt); err == nil {
			shifts = append(shifts, s)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	c.JSON(http.StatusOK, gin.H{"data": shifts})
}

// Get GET /soc/shifts/:id
func (h *ShiftHandler) Get(c *gin.Context) {
	id := c.Param("id")
	var s shiftRow
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+shiftSelectCols+` FROM soc_shifts WHERE id = $1`, id).
		Scan(&s.ID, &s.ShiftName, &s.ShiftDate, &s.StartTime, &s.EndTime,
			&s.LeadAnalystID, &s.TeamMembers, &s.Status, &s.HandoverNotes,
			&s.OpenIncidents, &s.PendingTasks, &s.Metrics, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "shift not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": s})
}

// StartShift POST /soc/shifts/start
func (h *ShiftHandler) StartShift(c *gin.Context) {
	var req struct {
		ShiftName     string        `json:"shift_name" binding:"required"`
		LeadAnalystID string        `json:"lead_analyst_id"`
		TeamMembers   []interface{} `json:"team_members"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "shift_name is required"})
		return
	}

	ctx := c.Request.Context()

	// Compute metrics from DB
	var openAlertsCount, openIncidentsCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'closed')`).
		Scan(&openAlertsCount)
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved', 'closed')`).
		Scan(&openIncidentsCount)

	metrics := map[string]interface{}{
		"open_alerts":    openAlertsCount,
		"open_incidents": openIncidentsCount,
	}
	metricsJSON, _ := json.Marshal(metrics)

	teamMembersJSON, _ := json.Marshal(req.TeamMembers)
	if string(teamMembersJSON) == "null" {
		teamMembersJSON = []byte("[]")
	}

	var leadID *string
	if req.LeadAnalystID != "" {
		leadID = &req.LeadAnalystID
	}

	now := time.Now()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO soc_shifts (shift_name, start_time, lead_analyst_id, team_members, status, metrics)
		 VALUES ($1, $2, $3, $4, 'active', $5) RETURNING id`,
		req.ShiftName, now, leadID, string(teamMembersJSON), string(metricsJSON)).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start shift"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"message": "shift started",
		"id":      id,
		"metrics": metrics,
	})
}

// EndShift POST /soc/shifts/:id/end
func (h *ShiftHandler) EndShift(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		HandoverNotes string        `json:"handover_notes"`
		PendingTasks  []interface{} `json:"pending_tasks"`
	}
	_ = c.ShouldBindJSON(&req)

	ctx := c.Request.Context()

	// Compute metrics from DB
	var alertsResolved, incidentsClosed, ticketsCreated int
	today := time.Now().UTC().Truncate(24 * time.Hour)
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE status IN ('resolved', 'closed') AND updated_at >= $1`,
		today).Scan(&alertsResolved)
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM incidents WHERE status IN ('resolved', 'closed') AND updated_at >= $1`,
		today).Scan(&incidentsClosed)
	// Try soc_tickets if it exists, fall through silently
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM soc_tickets WHERE created_at >= $1`,
		today).Scan(&ticketsCreated)

	metrics := map[string]interface{}{
		"alerts_resolved":  alertsResolved,
		"incidents_closed": incidentsClosed,
		"tickets_created":  ticketsCreated,
	}
	metricsJSON, _ := json.Marshal(metrics)

	pendingTasksJSON, _ := json.Marshal(req.PendingTasks)
	if string(pendingTasksJSON) == "null" {
		pendingTasksJSON = []byte("[]")
	}

	now := time.Now()
	ct, err := h.pool.Exec(ctx,
		`UPDATE soc_shifts
		 SET status = 'completed', end_time = $2, handover_notes = $3,
		     pending_tasks = $4, metrics = $5, updated_at = NOW()
		 WHERE id = $1 AND status = 'active'`,
		id, now, req.HandoverNotes, string(pendingTasksJSON), string(metricsJSON))
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "active shift not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "shift ended",
		"metrics": metrics,
	})
}

// UpdateNotes PUT /soc/shifts/:id/notes
func (h *ShiftHandler) UpdateNotes(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		HandoverNotes string        `json:"handover_notes"`
		PendingTasks  []interface{} `json:"pending_tasks"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	pendingTasksJSON, _ := json.Marshal(req.PendingTasks)
	if string(pendingTasksJSON) == "null" {
		pendingTasksJSON = []byte("[]")
	}

	ct, err := h.pool.Exec(c.Request.Context(),
		`UPDATE soc_shifts
		 SET handover_notes = $2, pending_tasks = $3, updated_at = NOW()
		 WHERE id = $1`,
		id, req.HandoverNotes, string(pendingTasksJSON))
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "shift not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "notes updated"})
}

// GetCurrentShift GET /soc/shifts/current
func (h *ShiftHandler) GetCurrentShift(c *gin.Context) {
	var s shiftRow
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+shiftSelectCols+`
		 FROM soc_shifts WHERE status = 'active' ORDER BY start_time DESC LIMIT 1`).
		Scan(&s.ID, &s.ShiftName, &s.ShiftDate, &s.StartTime, &s.EndTime,
			&s.LeadAnalystID, &s.TeamMembers, &s.Status, &s.HandoverNotes,
			&s.OpenIncidents, &s.PendingTasks, &s.Metrics, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active shift"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": s})
}

// GetStats GET /soc/shifts/stats
func (h *ShiftHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	var avgDurationMinutes float64
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (end_time - start_time)) / 60), 0)
		 FROM soc_shifts WHERE status = 'completed' AND end_time IS NOT NULL`).
		Scan(&avgDurationMinutes)

	var totalShiftsThisMonth int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM soc_shifts
		 WHERE shift_date >= DATE_TRUNC('month', NOW())`).Scan(&totalShiftsThisMonth)

	type AnalystStat struct {
		LeadAnalystID string `json:"lead_analyst_id"`
		ShiftCount    int    `json:"shift_count"`
	}
	var mostActive AnalystStat
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(lead_analyst_id::text, ''), COUNT(*) as cnt
		 FROM soc_shifts WHERE lead_analyst_id IS NOT NULL
		 GROUP BY lead_analyst_id ORDER BY cnt DESC LIMIT 1`).
		Scan(&mostActive.LeadAnalystID, &mostActive.ShiftCount)

	c.JSON(http.StatusOK, gin.H{
		"avg_shift_duration_minutes": avgDurationMinutes,
		"total_shifts_this_month":    totalShiftsThisMonth,
		"most_active_analyst":        mostActive,
	})
}

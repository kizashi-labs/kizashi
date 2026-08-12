package handlers

// CorrelationEngineHandler manages correlation_rules (trigger/follow engine rules) via the API.
// This is distinct from CorrelationHandler which manages correlation_groups (detection state).

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CorrelationEngineHandler provides CRUD endpoints for correlation_rules, which
// define trigger/follow event pairs used by the correlation detection engine.
type CorrelationEngineHandler struct {
	pool *pgxpool.Pool
}

// NewCorrelationEngineHandler creates a new CorrelationEngineHandler.
func NewCorrelationEngineHandler(pool *pgxpool.Pool) *CorrelationEngineHandler {
	return &CorrelationEngineHandler{pool: pool}
}

// correlationEngineRule is the API representation of a correlation_rules row.
type correlationEngineRule struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	Enabled           bool        `json:"enabled"`
	TriggerEventType  string      `json:"trigger_event_type"`
	FollowEventType   string      `json:"follow_event_type"`
	TimeWindowSeconds int         `json:"time_window_seconds"`
	SameAgent         bool        `json:"same_agent"`
	TriggerConditions interface{} `json:"trigger_conditions"`
	FollowConditions  interface{} `json:"follow_conditions"`
	AlertTitle        string      `json:"alert_title"`
	AlertSeverity     int         `json:"alert_severity"`
	CooldownSeconds   *int        `json:"cooldown_seconds"`
	MatchCount        int         `json:"match_count"`
	CreatedAt         string      `json:"created_at"`
}

const ceSelectCols = `id, name, description, enabled, trigger_event_type, follow_event_type,
	time_window_seconds, same_agent, trigger_conditions, follow_conditions,
	alert_title, alert_severity, cooldown_seconds, match_count, created_at`

func scanCorrelationEngineRule(row pgx.Row) (*correlationEngineRule, error) {
	var r correlationEngineRule
	var createdAt time.Time
	err := row.Scan(
		&r.ID, &r.Name, &r.Description, &r.Enabled,
		&r.TriggerEventType, &r.FollowEventType,
		&r.TimeWindowSeconds, &r.SameAgent,
		&r.TriggerConditions, &r.FollowConditions,
		&r.AlertTitle, &r.AlertSeverity,
		&r.CooldownSeconds, &r.MatchCount,
		&createdAt,
	)
	if err != nil {
		return nil, err
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	return &r, nil
}

// List returns a paginated list of correlation engine rules.
// GET /api/v1/correlation-engine
func (h *CorrelationEngineHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page > 1 && offset == 0 {
		offset = (page - 1) * limit
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	ctx := c.Request.Context()

	var total int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM correlation_rules`).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count correlation engine rules"})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT `+ceSelectCols+` FROM correlation_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list correlation engine rules"})
		return
	}
	defer rows.Close()

	var rules []*correlationEngineRule
	for rows.Next() {
		r, err := scanCorrelationEngineRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if rules == nil {
		rules = []*correlationEngineRule{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     rules,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// Get returns a single correlation engine rule by ID.
// GET /api/v1/correlation-engine/:id
func (h *CorrelationEngineHandler) Get(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+ceSelectCols+` FROM correlation_rules WHERE id = $1`, id,
	)
	r, err := scanCorrelationEngineRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Correlation engine rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get correlation engine rule"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// correlationEngineRuleRequest is the request body for Create and Update.
type correlationEngineRuleRequest struct {
	Name              string      `json:"name"               binding:"required"`
	Description       string      `json:"description"`
	Enabled           *bool       `json:"enabled"`
	TriggerEventType  string      `json:"trigger_event_type" binding:"required"`
	FollowEventType   string      `json:"follow_event_type"  binding:"required"`
	TimeWindowSeconds int         `json:"time_window_seconds"`
	SameAgent         *bool       `json:"same_agent"`
	TriggerConditions interface{} `json:"trigger_conditions"`
	FollowConditions  interface{} `json:"follow_conditions"`
	AlertTitle        string      `json:"alert_title"        binding:"required"`
	AlertSeverity     int         `json:"alert_severity"`
	CooldownSeconds   *int        `json:"cooldown_seconds"`
}

func validateCERequest(req *correlationEngineRuleRequest) string {
	if strings.TrimSpace(req.Name) == "" {
		return "name is required"
	}
	if strings.TrimSpace(req.TriggerEventType) == "" {
		return "trigger_event_type is required"
	}
	if strings.TrimSpace(req.FollowEventType) == "" {
		return "follow_event_type is required"
	}
	if strings.TrimSpace(req.AlertTitle) == "" {
		return "alert_title is required"
	}
	if req.TimeWindowSeconds <= 0 {
		req.TimeWindowSeconds = 300
	}
	if req.AlertSeverity <= 0 {
		req.AlertSeverity = 7
	}
	return ""
}

// Create inserts a new correlation engine rule (admin only).
// POST /api/v1/correlation-engine
func (h *CorrelationEngineHandler) Create(c *gin.Context) {
	var req correlationEngineRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateCERequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	sameAgent := true
	if req.SameAgent != nil {
		sameAgent = *req.SameAgent
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO correlation_rules
		    (name, description, enabled, trigger_event_type, follow_event_type,
		     time_window_seconds, same_agent, trigger_conditions, follow_conditions,
		     alert_title, alert_severity, cooldown_seconds)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING `+ceSelectCols,
		req.Name, req.Description, enabled,
		req.TriggerEventType, req.FollowEventType,
		req.TimeWindowSeconds, sameAgent,
		req.TriggerConditions, req.FollowConditions,
		req.AlertTitle, req.AlertSeverity, req.CooldownSeconds,
	)
	r, err := scanCorrelationEngineRule(row)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create correlation engine rule"})
		return
	}
	c.JSON(http.StatusCreated, r)
}

// Update modifies an existing correlation engine rule (admin only).
// PUT /api/v1/correlation-engine/:id
func (h *CorrelationEngineHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req correlationEngineRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg := validateCERequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	sameAgent := true
	if req.SameAgent != nil {
		sameAgent = *req.SameAgent
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE correlation_rules SET
		    name                = $2,
		    description         = $3,
		    enabled             = $4,
		    trigger_event_type  = $5,
		    follow_event_type   = $6,
		    time_window_seconds = $7,
		    same_agent          = $8,
		    trigger_conditions  = $9,
		    follow_conditions   = $10,
		    alert_title         = $11,
		    alert_severity      = $12,
		    cooldown_seconds    = $13
		 WHERE id = $1
		 RETURNING `+ceSelectCols,
		id,
		req.Name, req.Description, enabled,
		req.TriggerEventType, req.FollowEventType,
		req.TimeWindowSeconds, sameAgent,
		req.TriggerConditions, req.FollowConditions,
		req.AlertTitle, req.AlertSeverity, req.CooldownSeconds,
	)
	r, err := scanCorrelationEngineRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Correlation engine rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update correlation engine rule"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// Delete removes a correlation engine rule by ID (admin only).
// DELETE /api/v1/correlation-engine/:id
func (h *CorrelationEngineHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM correlation_rules WHERE id = $1`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete correlation engine rule"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Correlation engine rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Correlation engine rule deleted"})
}

// Toggle enables or disables a correlation engine rule (admin only).
// POST /api/v1/correlation-engine/:id/toggle
func (h *CorrelationEngineHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE correlation_rules
		 SET enabled = NOT enabled
		 WHERE id = $1
		 RETURNING `+ceSelectCols,
		id,
	)
	r, err := scanCorrelationEngineRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Correlation engine rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle correlation engine rule"})
		return
	}
	c.JSON(http.StatusOK, r)
}

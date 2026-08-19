package handlers

// CorrelationHandler manages correlation rules via the API.
// The correlation engine (internal/detection) reads these rules from DB.

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

// CorrelationHandler provides CRUD endpoints for correlation_groups, which
// represent active correlation rules / grouping state used by the detection engine.
type CorrelationHandler struct {
	pool *pgxpool.Pool
}

// NewCorrelationHandler creates a new CorrelationHandler.
func NewCorrelationHandler(pool *pgxpool.Pool) *CorrelationHandler {
	return &CorrelationHandler{pool: pool}
}

// correlationRule is the API representation of a correlation_groups row.
type correlationRule struct {
	ID             string  `json:"id"`
	AgentID        string  `json:"agent_id"`
	MITRETechnique string  `json:"mitre_technique"`
	FirstSeenAt    string  `json:"first_seen_at"`
	LastSeenAt     string  `json:"last_seen_at"`
	AlertCount     int     `json:"alert_count"`
	IncidentID     *string `json:"incident_id"`
	CreatedAt      string  `json:"created_at"`
}

const correlationSelectCols = `id, agent_id, mitre_technique, first_seen_at, last_seen_at, alert_count, incident_id, created_at`

func scanCorrelationRule(row pgx.Row) (*correlationRule, error) {
	var r correlationRule
	var firstSeen, lastSeen, createdAt time.Time
	err := row.Scan(
		&r.ID, &r.AgentID, &r.MITRETechnique,
		&firstSeen, &lastSeen,
		&r.AlertCount, &r.IncidentID, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	r.FirstSeenAt = firstSeen.Format(time.RFC3339)
	r.LastSeenAt = lastSeen.Format(time.RFC3339)
	r.CreatedAt = createdAt.Format(time.RFC3339)
	return &r, nil
}

// List returns a paginated list of correlation groups.
// GET /api/v1/correlation-rules
func (h *CorrelationHandler) List(c *gin.Context) {
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
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM correlation_groups`).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルール件数の取得に失敗しました"})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT `+correlationSelectCols+` FROM correlation_groups ORDER BY last_seen_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルール一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var rules []*correlationRule
	for rows.Next() {
		r, err := scanCorrelationRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルール一覧の取得に失敗しました"})
		return
	}
	if rules == nil {
		rules = []*correlationRule{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     rules,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// Get returns a single correlation group by ID.
// GET /api/v1/correlation-rules/:id
func (h *CorrelationHandler) Get(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+correlationSelectCols+` FROM correlation_groups WHERE id = $1`, id,
	)
	r, err := scanCorrelationRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "相関ルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルールの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// correlationRuleRequest is the request body for Create and Update.
type correlationRuleRequest struct {
	AgentID        string  `json:"agent_id" binding:"required"`
	MITRETechnique string  `json:"mitre_technique" binding:"required"`
	AlertCount     int     `json:"alert_count"`
	IncidentID     *string `json:"incident_id"`
}

func validateCorrelationRuleRequest(req *correlationRuleRequest) string {
	if strings.TrimSpace(req.AgentID) == "" {
		return "agent_id は必須です"
	}
	if strings.TrimSpace(req.MITRETechnique) == "" {
		return "mitre_technique は必須です"
	}
	if req.AlertCount < 1 {
		return "alert_count は 1 以上を指定してください"
	}
	return ""
}

// Create inserts a new correlation group entry (admin only).
// POST /api/v1/correlation-rules
func (h *CorrelationHandler) Create(c *gin.Context) {
	var req correlationRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.AlertCount == 0 {
		req.AlertCount = 1
	}
	if msg := validateCorrelationRuleRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO correlation_groups (agent_id, mitre_technique, first_seen_at, last_seen_at, alert_count, incident_id)
		 VALUES ($1, $2, NOW(), NOW(), $3, $4)
		 RETURNING `+correlationSelectCols,
		req.AgentID, req.MITRETechnique, req.AlertCount, req.IncidentID,
	)
	r, err := scanCorrelationRule(row)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルールの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, r)
}

// Update modifies an existing correlation group entry (admin only).
// PUT /api/v1/correlation-rules/:id
func (h *CorrelationHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req correlationRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.AlertCount == 0 {
		req.AlertCount = 1
	}
	if msg := validateCorrelationRuleRequest(&req); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE correlation_groups SET
		    agent_id        = $2,
		    mitre_technique = $3,
		    alert_count     = $4,
		    incident_id     = $5,
		    last_seen_at    = NOW()
		 WHERE id = $1
		 RETURNING `+correlationSelectCols,
		id, req.AgentID, req.MITRETechnique, req.AlertCount, req.IncidentID,
	)
	r, err := scanCorrelationRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "相関ルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルールの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// Delete removes a correlation group entry by ID (admin only).
// DELETE /api/v1/correlation-rules/:id
func (h *CorrelationHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM correlation_groups WHERE id = $1`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルールの削除に失敗しました"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "相関ルールが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "相関ルールを削除しました"})
}

// Toggle links or unlinks the incident_id on a correlation group (admin only).
// When incident_id is currently set it is cleared; when absent the group is
// marked as needing a new incident (incident_id set to NULL and alert_count
// reset to 0 so the engine will re-evaluate on the next cycle).
// PUT /api/v1/correlation-rules/:id/toggle
func (h *CorrelationHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`UPDATE correlation_groups
		 SET incident_id  = CASE WHEN incident_id IS NULL THEN incident_id ELSE NULL END,
		     last_seen_at = NOW()
		 WHERE id = $1
		 RETURNING `+correlationSelectCols,
		id,
	)
	r, err := scanCorrelationRule(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "相関ルールが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "相関ルールの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, r)
}

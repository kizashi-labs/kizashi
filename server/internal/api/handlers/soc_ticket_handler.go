package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SOCTicketHandler manages SOC workflow tickets.
type SOCTicketHandler struct {
	pool *pgxpool.Pool
}

// NewSOCTicketHandler creates a new SOCTicketHandler.
func NewSOCTicketHandler(pool *pgxpool.Pool) *SOCTicketHandler {
	return &SOCTicketHandler{pool: pool}
}

func (h *SOCTicketHandler) ticketTableExists(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='soc_tickets')`).Scan(&exists)
	return exists
}

func generateTicketNumber() string {
	now := time.Now()
	date := now.Format("20060102")
	n, err := rand.Int(rand.Reader, big.NewInt(9000))
	var suffix int64
	if err != nil {
		suffix = int64(now.UnixNano()%9000) + 1000
	} else {
		suffix = n.Int64() + 1000
	}
	return fmt.Sprintf("TKT-%s-%04d", date, suffix)
}

func slaDueAt(priority string) time.Time {
	now := time.Now()
	switch priority {
	case "critical":
		return now.Add(4 * time.Hour)
	case "high":
		return now.Add(8 * time.Hour)
	case "medium":
		return now.Add(24 * time.Hour)
	default: // low
		return now.Add(72 * time.Hour)
	}
}

type socTicket struct {
	ID             string      `json:"id"`
	TicketNumber   string      `json:"ticket_number"`
	AlertID        *string     `json:"alert_id"`
	IncidentID     *string     `json:"incident_id"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Status         string      `json:"status"`
	Priority       string      `json:"priority"`
	AssigneeID     *string     `json:"assignee_id"`
	Tags           interface{} `json:"tags"`
	ExternalID     *string     `json:"external_id"`
	ExternalSystem *string     `json:"external_system"`
	SLADueAt       *string     `json:"sla_due_at"`
	ResolvedAt     *string     `json:"resolved_at"`
	CreatedBy      *string     `json:"created_by"`
	CreatedAt      string      `json:"created_at"`
	UpdatedAt      string      `json:"updated_at"`
}

func scanSOCTicket(row interface{ Scan(...any) error }) (*socTicket, error) {
	var t socTicket
	var tagsRaw []byte
	var slaAt, resolvedAt *time.Time
	var createdAt, updatedAt time.Time
	err := row.Scan(
		&t.ID, &t.TicketNumber, &t.AlertID, &t.IncidentID, &t.Title, &t.Description,
		&t.Status, &t.Priority, &t.AssigneeID, &tagsRaw, &t.ExternalID, &t.ExternalSystem,
		&slaAt, &resolvedAt, &t.CreatedBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	if tagsRaw != nil {
		_ = json.Unmarshal(tagsRaw, &t.Tags)
	}
	if t.Tags == nil {
		t.Tags = []interface{}{}
	}
	if slaAt != nil {
		s := slaAt.Format(time.RFC3339)
		t.SLADueAt = &s
	}
	if resolvedAt != nil {
		s := resolvedAt.Format(time.RFC3339)
		t.ResolvedAt = &s
	}
	t.CreatedAt = createdAt.Format(time.RFC3339)
	t.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &t, nil
}

const socTicketCols = `id, ticket_number, alert_id, incident_id, title, description,
	status, priority, assignee_id, tags, external_id, external_system,
	sla_due_at, resolved_at, created_by, created_at, updated_at`

// List returns tickets with optional filters.
// GET /api/v1/soc/tickets
func (h *SOCTicketHandler) List(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"tickets": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	status := c.Query("status")
	priority := c.Query("priority")
	assigneeID := c.Query("assignee_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	query := `SELECT ` + socTicketCols + ` FROM soc_tickets WHERE 1=1`
	args := []interface{}{}
	i := 1
	if status != "" {
		query += ` AND status=$` + strconv.Itoa(i)
		args = append(args, status)
		i++
	}
	if priority != "" {
		query += ` AND priority=$` + strconv.Itoa(i)
		args = append(args, priority)
		i++
	}
	if assigneeID != "" {
		query += ` AND assignee_id=$` + strconv.Itoa(i)
		args = append(args, assigneeID)
		i++
	}
	query += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(i) + ` OFFSET $` + strconv.Itoa(i+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チケット一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var result []socTicket
	for rows.Next() {
		t, err := scanSOCTicket(rows)
		if err == nil {
			result = append(result, *t)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if result == nil {
		result = []socTicket{}
	}
	c.JSON(http.StatusOK, gin.H{"tickets": result, "total": len(result)})
}

// Get returns a single ticket with comments.
// GET /api/v1/soc/tickets/:id
func (h *SOCTicketHandler) Get(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	t, err := scanSOCTicket(h.pool.QueryRow(ctx,
		`SELECT `+socTicketCols+` FROM soc_tickets WHERE id=$1`, id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "チケットが見つかりません"})
		return
	}

	// Fetch comments
	type comment struct {
		ID        string  `json:"id"`
		TicketID  string  `json:"ticket_id"`
		Content   string  `json:"content"`
		AuthorID  *string `json:"author_id"`
		CreatedAt string  `json:"created_at"`
	}
	var comments []comment
	var commentTableExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='soc_ticket_comments')`).Scan(&commentTableExists)
	if commentTableExists {
		crows, _ := h.pool.Query(ctx,
			`SELECT id, ticket_id, content, author_id, created_at FROM soc_ticket_comments WHERE ticket_id=$1 ORDER BY created_at`, id)
		if crows != nil {
			defer crows.Close()
			for crows.Next() {
				var cm comment
				var createdAt time.Time
				if err := crows.Scan(&cm.ID, &cm.TicketID, &cm.Content, &cm.AuthorID, &createdAt); err == nil {
					cm.CreatedAt = createdAt.Format(time.RFC3339)
					comments = append(comments, cm)
				}
			}
			if err := crows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}
	}
	if comments == nil {
		comments = []comment{}
	}

	c.JSON(http.StatusOK, gin.H{"ticket": t, "comments": comments})
}

// Create creates a new SOC ticket.
// POST /api/v1/soc/tickets
func (h *SOCTicketHandler) Create(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var body struct {
		AlertID        *string     `json:"alert_id"`
		IncidentID     *string     `json:"incident_id"`
		Title          string      `json:"title" binding:"required"`
		Description    string      `json:"description"`
		Priority       string      `json:"priority"`
		AssigneeID     *string     `json:"assignee_id"`
		Tags           interface{} `json:"tags"`
		ExternalID     *string     `json:"external_id"`
		ExternalSystem *string     `json:"external_system"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	if body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "titleは必須です"})
		return
	}
	if body.Priority == "" {
		body.Priority = "medium"
	}

	ticketNumber := generateTicketNumber()
	sla := slaDueAt(body.Priority)

	tagsJSON, _ := json.Marshal(body.Tags)
	if tagsJSON == nil || string(tagsJSON) == "null" {
		tagsJSON = []byte("[]")
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO soc_tickets
		   (ticket_number, alert_id, incident_id, title, description, priority, assignee_id,
		    tags, external_id, external_system, sla_due_at, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		ticketNumber, body.AlertID, body.IncidentID, body.Title, body.Description, body.Priority,
		body.AssigneeID, tagsJSON, body.ExternalID, body.ExternalSystem, sla, userIDStr,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チケットの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "ticket_number": ticketNumber, "sla_due_at": sla.Format(time.RFC3339)})
}

// Update updates a ticket.
// PUT /api/v1/soc/tickets/:id
func (h *SOCTicketHandler) Update(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	var body struct {
		Title          string      `json:"title"`
		Description    string      `json:"description"`
		Status         string      `json:"status"`
		Priority       string      `json:"priority"`
		AssigneeID     *string     `json:"assignee_id"`
		Tags           interface{} `json:"tags"`
		ExternalID     *string     `json:"external_id"`
		ExternalSystem *string     `json:"external_system"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	tagsJSON, _ := json.Marshal(body.Tags)
	if tagsJSON == nil || string(tagsJSON) == "null" {
		tagsJSON = []byte("[]")
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE soc_tickets SET title=$1, description=$2, status=$3, priority=$4, assignee_id=$5,
		                        tags=$6, external_id=$7, external_system=$8, updated_at=NOW()
		 WHERE id=$9`,
		body.Title, body.Description, body.Status, body.Priority, body.AssigneeID,
		tagsJSON, body.ExternalID, body.ExternalSystem, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チケットの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "チケットを更新しました"})
}

// Close closes a ticket.
// POST /api/v1/soc/tickets/:id/close
func (h *SOCTicketHandler) Close(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE soc_tickets SET status='closed', resolved_at=NOW(), updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チケットのクローズに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "チケットをクローズしました"})
}

// AddComment adds a comment to a ticket.
// POST /api/v1/soc/tickets/:id/comments
func (h *SOCTicketHandler) AddComment(c *gin.Context) {
	ctx := c.Request.Context()
	var commentTableExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='soc_ticket_comments')`).Scan(&commentTableExists)
	if !commentTableExists {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	id := c.Param("id")
	var body struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contentは必須です"})
		return
	}
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var commentID string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO soc_ticket_comments (ticket_id, content, author_id) VALUES ($1,$2,$3) RETURNING id`,
		id, body.Content, userIDStr,
	).Scan(&commentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": commentID, "message": "コメントを追加しました"})
}

// CreateFromAlert creates a ticket from an existing alert.
// POST /api/v1/soc/tickets/from-alert
func (h *SOCTicketHandler) CreateFromAlert(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var body struct {
		AlertID string `json:"alert_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.AlertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "alert_idは必須です"})
		return
	}
	ctx := c.Request.Context()

	// Fetch alert
	var alertTitle, alertDesc, alertSeverity string
	var alertTableExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='alerts')`).Scan(&alertTableExists)

	priority := "medium"
	title := "アラートからのチケット"
	description := ""

	if alertTableExists {
		_ = h.pool.QueryRow(ctx,
			`SELECT COALESCE(title,''), COALESCE(description,''), CAST(severity AS TEXT) FROM alerts WHERE id=$1`,
			body.AlertID,
		).Scan(&alertTitle, &alertDesc, &alertSeverity)
		if alertTitle != "" {
			title = alertTitle
		}
		if alertDesc != "" {
			description = alertDesc
		}
		switch alertSeverity {
		case "4", "5":
			priority = "critical"
		case "3":
			priority = "high"
		case "2":
			priority = "medium"
		default:
			priority = "low"
		}
	}

	ticketNumber := generateTicketNumber()
	sla := slaDueAt(priority)

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO soc_tickets
		   (ticket_number, alert_id, title, description, priority, sla_due_at, created_by, tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'[]') RETURNING id`,
		ticketNumber, body.AlertID, title, description, priority, sla, userIDStr,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チケットの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id":            id,
		"ticket_number": ticketNumber,
		"sla_due_at":    sla.Format(time.RFC3339),
	})
}

// GetStats returns SOC ticket statistics.
// GET /api/v1/soc/tickets/stats
func (h *SOCTicketHandler) GetStats(c *gin.Context) {
	if !h.ticketTableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"open":               0,
			"closed":             0,
			"in_progress":        0,
			"avg_resolution_min": 0,
			"sla_breached":       0,
		})
		return
	}
	ctx := c.Request.Context()

	var open, closed, inProgress, slaBreached int
	var avgResolutionMin float64
	_ = h.pool.QueryRow(ctx,
		`SELECT
		  COUNT(*) FILTER (WHERE status='open'),
		  COUNT(*) FILTER (WHERE status='closed'),
		  COUNT(*) FILTER (WHERE status='in_progress'),
		  COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/60) FILTER (WHERE resolved_at IS NOT NULL), 0),
		  COUNT(*) FILTER (WHERE sla_due_at < NOW() AND status != 'closed')
		 FROM soc_tickets`).Scan(&open, &closed, &inProgress, &avgResolutionMin, &slaBreached)

	c.JSON(http.StatusOK, gin.H{
		"open":               open,
		"closed":             closed,
		"in_progress":        inProgress,
		"avg_resolution_min": avgResolutionMin,
		"sla_breached":       slaBreached,
	})
}

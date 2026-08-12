package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// TrainingHandler manages security awareness training campaign endpoints.
type TrainingHandler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewTrainingHandler creates a new TrainingHandler.
func NewTrainingHandler(pool *pgxpool.Pool) *TrainingHandler {
	return &TrainingHandler{pool: pool}
}

// NewTrainingHandlerWithNATS creates a TrainingHandler with NATS support.
func NewTrainingHandlerWithNATS(pool *pgxpool.Pool, nc *nats.Conn) *TrainingHandler {
	return &TrainingHandler{pool: pool, nc: nc}
}

func (h *TrainingHandler) campaignsTableExists(ctx context.Context) bool {
	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='training_campaigns')`).Scan(&exists)
	return exists
}

func (h *TrainingHandler) resultsTableExists(ctx context.Context) bool {
	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='training_results')`).Scan(&exists)
	return exists
}

// ListCampaigns — GET /training/campaigns
func (h *TrainingHandler) ListCampaigns(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.campaignsTableExists(ctx) {
		c.JSON(http.StatusOK, gin.H{"campaigns": []interface{}{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, name, campaign_type, status, target_count, sent_count,
		        opened_count, clicked_count, reported_count, scheduled_at, completed_at,
		        created_by, created_at, updated_at
		 FROM training_campaigns ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "キャンペーン一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type campaign struct {
		ID            string  `json:"id"`
		Name          string  `json:"name"`
		CampaignType  string  `json:"campaign_type"`
		Status        string  `json:"status"`
		TargetCount   int     `json:"target_count"`
		SentCount     int     `json:"sent_count"`
		OpenedCount   int     `json:"opened_count"`
		ClickedCount  int     `json:"clicked_count"`
		ReportedCount int     `json:"reported_count"`
		ScheduledAt   *string `json:"scheduled_at"`
		CompletedAt   *string `json:"completed_at"`
		CreatedBy     *string `json:"created_by"`
		CreatedAt     string  `json:"created_at"`
		UpdatedAt     string  `json:"updated_at"`
	}

	var result []campaign
	for rows.Next() {
		var camp campaign
		var createdAt, updatedAt time.Time
		var scheduledAt, completedAt *time.Time
		if err := rows.Scan(&camp.ID, &camp.Name, &camp.CampaignType, &camp.Status,
			&camp.TargetCount, &camp.SentCount, &camp.OpenedCount, &camp.ClickedCount,
			&camp.ReportedCount, &scheduledAt, &completedAt, &camp.CreatedBy,
			&createdAt, &updatedAt); err != nil {
			continue
		}
		camp.CreatedAt = createdAt.Format(time.RFC3339)
		camp.UpdatedAt = updatedAt.Format(time.RFC3339)
		if scheduledAt != nil {
			t := scheduledAt.Format(time.RFC3339)
			camp.ScheduledAt = &t
		}
		if completedAt != nil {
			t := completedAt.Format(time.RFC3339)
			camp.CompletedAt = &t
		}
		result = append(result, camp)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if result == nil {
		result = []campaign{}
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": result, "total": len(result)})
}

// GetCampaign — GET /training/campaigns/:id
func (h *TrainingHandler) GetCampaign(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.campaignsTableExists(ctx) {
		c.JSON(http.StatusNotFound, gin.H{"error": "キャンペーンが見つかりません"})
		return
	}

	id := c.Param("id")
	row := h.pool.QueryRow(ctx,
		`SELECT id, name, campaign_type, status, target_count, sent_count,
		        opened_count, clicked_count, reported_count, scheduled_at, completed_at,
		        created_by, created_at, updated_at
		 FROM training_campaigns WHERE id=$1`, id)

	var (
		campID, name, campType, status                                   string
		targetCount, sentCount, openedCount, clickedCount, reportedCount int
		createdBy                                                        *string
		createdAt, updatedAt                                             time.Time
		scheduledAt, completedAt                                         *time.Time
	)
	if err := row.Scan(&campID, &name, &campType, &status,
		&targetCount, &sentCount, &openedCount, &clickedCount, &reportedCount,
		&scheduledAt, &completedAt, &createdBy, &createdAt, &updatedAt); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "キャンペーンが見つかりません"})
		return
	}

	// Results summary
	resultsSummary := gin.H{"total": 0, "clicked": 0, "completed": 0}
	if h.resultsTableExists(ctx) {
		var total, clicked, completed int
		_ = h.pool.QueryRow(ctx,
			`SELECT COUNT(*),
			        COUNT(*) FILTER (WHERE action='clicked'),
			        COUNT(*) FILTER (WHERE completed_training=true)
			 FROM training_results WHERE campaign_id=$1`, campID).
			Scan(&total, &clicked, &completed)
		resultsSummary = gin.H{"total": total, "clicked": clicked, "completed": completed}
	}

	resp := gin.H{
		"id":              campID,
		"name":            name,
		"campaign_type":   campType,
		"status":          status,
		"target_count":    targetCount,
		"sent_count":      sentCount,
		"opened_count":    openedCount,
		"clicked_count":   clickedCount,
		"reported_count":  reportedCount,
		"created_by":      createdBy,
		"created_at":      createdAt.Format(time.RFC3339),
		"updated_at":      updatedAt.Format(time.RFC3339),
		"results_summary": resultsSummary,
		"scheduled_at":    nil,
		"completed_at":    nil,
	}
	if scheduledAt != nil {
		resp["scheduled_at"] = scheduledAt.Format(time.RFC3339)
	}
	if completedAt != nil {
		resp["completed_at"] = completedAt.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, resp)
}

// CreateCampaign — POST /training/campaigns
func (h *TrainingHandler) CreateCampaign(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.campaignsTableExists(ctx) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "キャンペーンテーブルが存在しません"})
		return
	}

	var body struct {
		Name         string  `json:"name" binding:"required"`
		CampaignType string  `json:"campaign_type"`
		TargetCount  int     `json:"target_count"`
		ScheduledAt  *string `json:"scheduled_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameは必須です"})
		return
	}
	if body.CampaignType == "" {
		body.CampaignType = "phishing_simulation"
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO training_campaigns (name, campaign_type, status, target_count, created_by)
		 VALUES ($1, $2, 'draft', $3, $4) RETURNING id`,
		body.Name, body.CampaignType, body.TargetCount, userIDStr).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "キャンペーンの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "キャンペーンを作成しました"})
}

// LaunchCampaign — POST /training/campaigns/:id/launch
func (h *TrainingHandler) LaunchCampaign(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.campaignsTableExists(ctx) {
		c.JSON(http.StatusNotFound, gin.H{"error": "キャンペーンが見つかりません"})
		return
	}

	id := c.Param("id")

	var targetCount int
	err := h.pool.QueryRow(ctx,
		`UPDATE training_campaigns SET status='running', updated_at=NOW()
		 WHERE id=$1 RETURNING target_count`, id).Scan(&targetCount)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "キャンペーンが見つかりません"})
		return
	}

	_, _ = h.pool.Exec(ctx,
		`UPDATE training_campaigns SET sent_count=$1 WHERE id=$2`, targetCount, id)

	if h.nc != nil {
		if err := h.nc.Publish("training.campaign.launched", []byte(`{"campaign_id":"`+id+`"}`)); err != nil {
			slog.Warn("NATS publish failed", "subject", "training.campaign.launched", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "キャンペーンを開始しました", "id": id})
}

// GetResults — GET /training/campaigns/:id/results
func (h *TrainingHandler) GetResults(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.resultsTableExists(ctx) {
		c.JSON(http.StatusOK, gin.H{"results": []interface{}{}, "total": 0})
		return
	}

	id := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit

	var total int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM training_results WHERE campaign_id=$1`, id).Scan(&total)

	rows, err := h.pool.Query(ctx,
		`SELECT id, campaign_id, user_id, email, action, action_at,
		        completed_training, training_score, created_at
		 FROM training_results WHERE campaign_id=$1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		id, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "結果の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type result struct {
		ID                string  `json:"id"`
		CampaignID        string  `json:"campaign_id"`
		UserID            *string `json:"user_id"`
		Email             string  `json:"email"`
		Action            string  `json:"action"`
		ActionAt          *string `json:"action_at"`
		CompletedTraining bool    `json:"completed_training"`
		TrainingScore     *int    `json:"training_score"`
		CreatedAt         string  `json:"created_at"`
	}

	var results []result
	for rows.Next() {
		var r result
		var createdAt time.Time
		var actionAt *time.Time
		if err := rows.Scan(&r.ID, &r.CampaignID, &r.UserID, &r.Email, &r.Action,
			&actionAt, &r.CompletedTraining, &r.TrainingScore, &createdAt); err != nil {
			continue
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		if actionAt != nil {
			t := actionAt.Format(time.RFC3339)
			r.ActionAt = &t
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if results == nil {
		results = []result{}
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "total": total, "page": page})
}

// GetStats — GET /training/stats
func (h *TrainingHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.campaignsTableExists(ctx) {
		c.JSON(http.StatusOK, gin.H{
			"campaigns_this_month": 0,
			"avg_click_rate":       0,
			"avg_completion_rate":  0,
		})
		return
	}

	var campaignsThisMonth int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM training_campaigns
		 WHERE created_at >= date_trunc('month', NOW())`).Scan(&campaignsThisMonth)

	var avgClickRate, avgCompletionRate float64
	if h.resultsTableExists(ctx) {
		_ = h.pool.QueryRow(ctx,
			`SELECT
			   COALESCE(AVG(CASE WHEN target_count > 0 THEN clicked_count::float / target_count ELSE 0 END) * 100, 0),
			   COALESCE(AVG(CASE WHEN sent_count > 0 THEN
			       (SELECT COUNT(*) FROM training_results tr WHERE tr.campaign_id=tc.id AND tr.completed_training=true)::float / sent_count
			   ELSE 0 END) * 100, 0)
			 FROM training_campaigns tc WHERE status IN ('running','completed')`).
			Scan(&avgClickRate, &avgCompletionRate)
	}

	c.JSON(http.StatusOK, gin.H{
		"campaigns_this_month": campaignsThisMonth,
		"avg_click_rate":       avgClickRate,
		"avg_completion_rate":  avgCompletionRate,
	})
}

// SimulateClick — POST /training/campaigns/:id/simulate-click
func (h *TrainingHandler) SimulateClick(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.resultsTableExists(ctx) {
		c.JSON(http.StatusNotFound, gin.H{"error": "結果レコードが見つかりません"})
		return
	}

	id := c.Param("id")
	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "emailは必須です"})
		return
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE training_results SET action='clicked', action_at=NOW()
		 WHERE campaign_id=$1 AND email=$2`,
		id, body.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "クリックシミュレートに失敗しました"})
		return
	}
	// Update campaign clicked_count
	_, _ = h.pool.Exec(ctx,
		`UPDATE training_campaigns SET clicked_count = (
		   SELECT COUNT(*) FROM training_results WHERE campaign_id=$1 AND action='clicked'
		 ) WHERE id=$1`, id)

	c.JSON(http.StatusOK, gin.H{"message": "クリックをシミュレートしました"})
}

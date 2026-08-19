package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccessReviewHandler manages access review campaigns and items.
// GET/POST /api/v1/admin/access-review/campaigns
// GET      /api/v1/admin/access-review/items
type AccessReviewHandler struct {
	pool *pgxpool.Pool
}

func NewAccessReviewHandler(pool *pgxpool.Pool) *AccessReviewHandler {
	return &AccessReviewHandler{pool: pool}
}

func (h *AccessReviewHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "access_review_campaigns")
}

type arCampaign struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	Reviewer    string `json:"reviewer"`
	DueDate     string `json:"due_date"`
	CreatedAt   string `json:"created_at"`
}

type arItem struct {
	ID         string `json:"id"`
	CampaignID string `json:"campaign_id"`
	User       string `json:"user"`
	Resource   string `json:"resource"`
	Permission string `json:"permission"`
	Decision   string `json:"decision"`
}

// ListCampaigns returns all access review campaigns.
// GET /api/v1/admin/access-review/campaigns
func (h *AccessReviewHandler) ListCampaigns(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"campaigns": []interface{}{}})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, name, COALESCE(description,''), status, reviewer, due_date, created_at
		 FROM access_review_campaigns ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list campaigns"})
		return
	}
	defer rows.Close()

	var campaigns []arCampaign
	for rows.Next() {
		var ac arCampaign
		var createdAt time.Time
		var dueDate time.Time
		if err := rows.Scan(&ac.ID, &ac.Name, &ac.Description, &ac.Status, &ac.Reviewer, &dueDate, &createdAt); err != nil {
			continue
		}
		ac.DueDate = dueDate.Format("2006-01-02")
		ac.CreatedAt = createdAt.Format(time.RFC3339)
		campaigns = append(campaigns, ac)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list campaigns"})
		return
	}
	if campaigns == nil {
		campaigns = []arCampaign{}
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": campaigns})
}

// CreateCampaign creates a new access review campaign.
// POST /api/v1/admin/access-review/campaigns
func (h *AccessReviewHandler) CreateCampaign(c *gin.Context) {
	var body struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Reviewer    string `json:"reviewer" binding:"required"`
		DueDate     string `json:"due_date" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, reviewer, due_date are required"})
		return
	}

	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Access review tables not available"})
		return
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO access_review_campaigns (name, description, status, reviewer, due_date)
		 VALUES ($1,$2,'draft',$3,$4) RETURNING id`,
		body.Name, body.Description, body.Reviewer, body.DueDate,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create campaign"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Campaign created"})
}

// ListItems returns review items, optionally filtered by campaign.
// GET /api/v1/admin/access-review/items?campaign_id=...
func (h *AccessReviewHandler) ListItems(c *gin.Context) {
	ctx := c.Request.Context()
	campaignID := c.Query("campaign_id")

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, []arItem{})
		return
	}

	query := `SELECT id, campaign_id, user_name, resource, permission, decision
	          FROM access_review_items ORDER BY user_name`
	args := []any{}
	if campaignID != "" {
		if !isValidUUID(campaignID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid campaign_id"})
			return
		}
		query = `SELECT id, campaign_id, user_name, resource, permission, decision
		         FROM access_review_items WHERE campaign_id=$1 ORDER BY user_name`
		args = append(args, campaignID)
	}

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list items"})
		return
	}
	defer rows.Close()

	var items []arItem
	for rows.Next() {
		var it arItem
		if err := rows.Scan(&it.ID, &it.CampaignID, &it.User, &it.Resource, &it.Permission, &it.Decision); err != nil {
			continue
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list items"})
		return
	}
	if items == nil {
		items = []arItem{}
	}
	c.JSON(http.StatusOK, items)
}

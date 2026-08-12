package handlers

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NotificationTemplateHandler manages custom notification templates.
type NotificationTemplateHandler struct {
	pool *pgxpool.Pool
}

// NewNotificationTemplateHandler creates a new NotificationTemplateHandler.
func NewNotificationTemplateHandler(pool *pgxpool.Pool) *NotificationTemplateHandler {
	return &NotificationTemplateHandler{pool: pool}
}

// NotifTemplate represents a notification template row.
type NotifTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ChannelType string    `json:"channel_type"`
	Subject     *string   `json:"subject,omitempty"`
	Body        string    `json:"body"`
	Variables   []string  `json:"variables"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// List handles GET /api/v1/admin/notification-templates
func (h *NotificationTemplateHandler) List(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, channel_type, subject, body, variables, is_default, created_at, updated_at
		 FROM notification_templates ORDER BY is_default DESC, created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テンプレート一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var templates []NotifTemplate
	for rows.Next() {
		var t NotifTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.ChannelType, &t.Subject, &t.Body, &t.Variables, &t.IsDefault, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		templates = append(templates, t)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if templates == nil {
		templates = []NotifTemplate{}
	}
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

// Create handles POST /api/v1/admin/notification-templates
func (h *NotificationTemplateHandler) Create(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		ChannelType string   `json:"channel_type"`
		Subject     *string  `json:"subject,omitempty"`
		Body        string   `json:"body"`
		Variables   []string `json:"variables"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Body) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameとbodyは必須です"})
		return
	}
	if req.Variables == nil {
		req.Variables = []string{}
	}

	var t NotifTemplate
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO notification_templates (name, channel_type, subject, body, variables)
		 VALUES ($1,$2,$3,$4,$5)
		 RETURNING id, name, channel_type, subject, body, variables, is_default, created_at, updated_at`,
		req.Name, req.ChannelType, req.Subject, req.Body, req.Variables,
	).Scan(&t.ID, &t.Name, &t.ChannelType, &t.Subject, &t.Body, &t.Variables, &t.IsDefault, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テンプレートの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, t)
}

// Update handles PUT /api/v1/admin/notification-templates/:id
func (h *NotificationTemplateHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name      string   `json:"name"`
		Subject   *string  `json:"subject,omitempty"`
		Body      string   `json:"body"`
		Variables []string `json:"variables"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Variables == nil {
		req.Variables = []string{}
	}

	var t NotifTemplate
	err := h.pool.QueryRow(c.Request.Context(),
		`UPDATE notification_templates SET name=$1, subject=$2, body=$3, variables=$4, updated_at=NOW()
		 WHERE id=$5
		 RETURNING id, name, channel_type, subject, body, variables, is_default, created_at, updated_at`,
		req.Name, req.Subject, req.Body, req.Variables, id,
	).Scan(&t.ID, &t.Name, &t.ChannelType, &t.Subject, &t.Body, &t.Variables, &t.IsDefault, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "テンプレートが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, t)
}

// Delete handles DELETE /api/v1/admin/notification-templates/:id
func (h *NotificationTemplateHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	result, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM notification_templates WHERE id=$1 AND is_default=false`, id)
	if err != nil || result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "テンプレートが見つかりません（デフォルトテンプレートは削除できません）"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "テンプレートを削除しました"})
}

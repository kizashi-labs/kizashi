package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CloudMonitorHandler struct {
	pool *pgxpool.Pool
}

func NewCloudMonitorHandler(pool *pgxpool.Pool) *CloudMonitorHandler {
	return &CloudMonitorHandler{pool: pool}
}

type CloudIntegration struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Provider     string                 `json:"provider"`
	Region       string                 `json:"region"`
	Config       map[string]interface{} `json:"config"`
	Enabled      bool                   `json:"enabled"`
	LastSyncedAt *time.Time             `json:"last_synced_at"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

type CloudEvent struct {
	ID            string                 `json:"id"`
	IntegrationID string                 `json:"integration_id"`
	Provider      string                 `json:"provider"`
	EventType     string                 `json:"event_type"`
	EventTime     time.Time              `json:"event_time"`
	SourceIP      string                 `json:"source_ip"`
	UserIdentity  map[string]interface{} `json:"user_identity"`
	Resource      string                 `json:"resource"`
	Region        string                 `json:"region"`
}

// GET /api/v1/cloud/integrations
func (h *CloudMonitorHandler) ListIntegrations(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, provider, region, config, enabled, last_synced_at, error_message, created_at
		 FROM cloud_integrations ORDER BY created_at`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	var integrations []CloudIntegration
	for rows.Next() {
		var i CloudIntegration
		if err := rows.Scan(&i.ID, &i.Name, &i.Provider, &i.Region, &i.Config,
			&i.Enabled, &i.LastSyncedAt, &i.ErrorMessage, &i.CreatedAt); err != nil {
			slog.Warn("cloud_monitor: integrations scan error", "error", err)
			continue
		}
		// Redact secrets from config response
		for key := range i.Config {
			if key == "secret_access_key" || key == "client_secret" || key == "api_key" {
				i.Config[key] = "***"
			}
		}
		integrations = append(integrations, i)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	if integrations == nil {
		integrations = []CloudIntegration{}
	}
	c.JSON(http.StatusOK, integrations)
}

// POST /api/v1/cloud/integrations
func (h *CloudMonitorHandler) CreateIntegration(c *gin.Context) {
	var req struct {
		Name     string                 `json:"name" binding:"required"`
		Provider string                 `json:"provider" binding:"required"`
		Region   string                 `json:"region"`
		Config   map[string]interface{} `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Config == nil {
		req.Config = map[string]interface{}{}
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO cloud_integrations (name, provider, region, config) VALUES ($1,$2,$3,$4) RETURNING id`,
		req.Name, req.Provider, req.Region, req.Config,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// PATCH /api/v1/cloud/integrations/:id
func (h *CloudMonitorHandler) UpdateIntegration(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled *bool                  `json:"enabled"`
		Config  map[string]interface{} `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 以前は Exec の戻り値を捨てて無条件に 200 "updated" を返していた。
	// UPDATE が失敗しても (不正な id、制約違反、DB 断) 画面には「更新しました」
	// と出て、実際には何も変わっていない状態になる。
	var updated int64
	if req.Enabled != nil {
		tag, err := h.pool.Exec(c.Request.Context(),
			`UPDATE cloud_integrations SET enabled=$1 WHERE id=$2`, req.Enabled, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		updated += tag.RowsAffected()
	}
	if req.Config != nil {
		tag, err := h.pool.Exec(c.Request.Context(),
			`UPDATE cloud_integrations SET config=$1 WHERE id=$2`, req.Config, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		updated += tag.RowsAffected()
	}
	// 更新対象が 1 行も無いのは「その id が存在しない」ということ。
	// 200 を返すと、消えた連携を編集し続けられてしまう。
	if updated == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "クラウド連携が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DELETE /api/v1/cloud/integrations/:id
func (h *CloudMonitorHandler) DeleteIntegration(c *gin.Context) {
	id := c.Param("id")
	// UpdateIntegration と同じ理由。存在しない id への DELETE も
	// 「削除しました」と返していた。
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM cloud_integrations WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "クラウド連携が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// GET /api/v1/cloud/events
func (h *CloudMonitorHandler) ListEvents(c *gin.Context) {
	integrationID := c.Query("integration_id")
	provider := c.Query("provider")
	limit := 100

	query := `SELECT id, integration_id, provider, event_type, event_time,
	           COALESCE(source_ip,''), COALESCE(user_identity,'{}'), COALESCE(resource,''), COALESCE(region,'')
	          FROM cloud_events WHERE event_time > NOW() - INTERVAL '24 hours'`
	args := []interface{}{}

	if integrationID != "" {
		args = append(args, integrationID)
		query += ` AND integration_id=$` + string(rune('0'+len(args)))
	}
	if provider != "" {
		args = append(args, provider)
		query += ` AND provider=$` + string(rune('0'+len(args)))
	}
	query += ` ORDER BY event_time DESC LIMIT $` + string(rune('0'+len(args)+1))
	args = append(args, limit)

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	var events []CloudEvent
	for rows.Next() {
		var e CloudEvent
		if err := rows.Scan(&e.ID, &e.IntegrationID, &e.Provider, &e.EventType, &e.EventTime,
			&e.SourceIP, &e.UserIdentity, &e.Resource, &e.Region); err != nil {
			slog.Warn("cloud_monitor: events scan error", "error", err)
			continue
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	if events == nil {
		events = []CloudEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// POST /api/v1/cloud/integrations/:id/test
func (h *CloudMonitorHandler) TestConnection(c *gin.Context) {
	// Placeholder — actual cloud SDK calls would go here
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "接続テストは実際のSDK設定後に利用可能です"})
}

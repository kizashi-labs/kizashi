package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/soar"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SOARHandler はSOAR連携設定とチケット作成を管理します
type SOARHandler struct {
	pool *pgxpool.Pool
}

// NewSOARHandler creates a new SOARHandler.
func NewSOARHandler(pool *pgxpool.Pool) *SOARHandler {
	return &SOARHandler{pool: pool}
}

// soarConfig はDB上のSOAR設定レコードです
type soarConfig struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Enabled     bool            `json:"enabled"`
	Config      json.RawMessage `json:"config"`
	MinSeverity int             `json:"min_severity"`
	AutoCreate  bool            `json:"auto_create"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// maskConfig は認証情報フィールドを *** でマスクした map を返します
func maskConfig(raw json.RawMessage) map[string]interface{} {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]interface{}{}
	}
	sensitiveKeys := map[string]bool{
		"api_token": true,
		"password":  true,
		"token":     true,
		"secret":    true,
	}
	for k := range m {
		if sensitiveKeys[k] {
			m[k] = "***"
		}
	}
	return m
}

// ListConfigs returns all SOAR configurations.
// GET /api/v1/soar/configs
func (h *SOARHandler) ListConfigs(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, type, enabled, config, min_severity, auto_create, created_at, updated_at
		FROM soar_configs
		ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SOAR設定の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type outItem struct {
		ID          string                 `json:"id"`
		Name        string                 `json:"name"`
		Type        string                 `json:"type"`
		Enabled     bool                   `json:"enabled"`
		Config      map[string]interface{} `json:"config"`
		MinSeverity int                    `json:"min_severity"`
		AutoCreate  bool                   `json:"auto_create"`
		CreatedAt   time.Time              `json:"created_at"`
		UpdatedAt   time.Time              `json:"updated_at"`
	}

	var results []outItem
	for rows.Next() {
		var sc soarConfig
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Type, &sc.Enabled, &sc.Config,
			&sc.MinSeverity, &sc.AutoCreate, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
			continue
		}
		results = append(results, outItem{
			ID:          sc.ID,
			Name:        sc.Name,
			Type:        sc.Type,
			Enabled:     sc.Enabled,
			Config:      maskConfig(sc.Config),
			MinSeverity: sc.MinSeverity,
			AutoCreate:  sc.AutoCreate,
			CreatedAt:   sc.CreatedAt,
			UpdatedAt:   sc.UpdatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if results == nil {
		results = []outItem{}
	}
	c.JSON(http.StatusOK, gin.H{"data": results})
}

// CreateConfig adds a new SOAR configuration.
// POST /api/v1/soar/configs (admin)
func (h *SOARHandler) CreateConfig(c *gin.Context) {
	var req struct {
		Name        string                 `json:"name"         binding:"required"`
		Type        string                 `json:"type"         binding:"required"`
		Enabled     bool                   `json:"enabled"`
		Config      map[string]interface{} `json:"config"`
		MinSeverity *int                   `json:"min_severity"`
		AutoCreate  bool                   `json:"auto_create"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name と type は必須です"})
		return
	}
	if req.Type != "jira" && req.Type != "servicenow" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type は 'jira' または 'servicenow' である必要があります"})
		return
	}

	minSeverity := 7
	if req.MinSeverity != nil {
		minSeverity = *req.MinSeverity
	}

	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config のシリアライズに失敗しました"})
		return
	}

	var id string
	err = h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO soar_configs (name, type, enabled, config, min_severity, auto_create)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		req.Name, req.Type, req.Enabled, string(configJSON), minSeverity, req.AutoCreate,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SOAR設定の作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "SOAR設定を作成しました", "id": id})
}

// UpdateConfig modifies an existing SOAR configuration.
// PATCH /api/v1/soar/configs/:id (admin)
func (h *SOARHandler) UpdateConfig(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name        *string                `json:"name"`
		Enabled     *bool                  `json:"enabled"`
		Config      map[string]interface{} `json:"config"`
		MinSeverity *int                   `json:"min_severity"`
		AutoCreate  *bool                  `json:"auto_create"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエスト"})
		return
	}

	// 現在の設定を取得
	var current soarConfig
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, name, type, enabled, config, min_severity, auto_create, created_at, updated_at
		FROM soar_configs WHERE id = $1`, id,
	).Scan(&current.ID, &current.Name, &current.Type, &current.Enabled, &current.Config,
		&current.MinSeverity, &current.AutoCreate, &current.CreatedAt, &current.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SOAR設定が見つかりません"})
		return
	}

	// PATCH: フィールドが指定されていた場合のみ更新
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	if req.MinSeverity != nil {
		current.MinSeverity = *req.MinSeverity
	}
	if req.AutoCreate != nil {
		current.AutoCreate = *req.AutoCreate
	}

	configJSON := current.Config
	if req.Config != nil {
		// 既存configとマージ (機密フィールドが *** の場合は既存値を維持)
		var existing map[string]interface{}
		if err := json.Unmarshal(current.Config, &existing); err != nil {
			slog.Warn("soar: 既存configのパースに失敗しました。空のconfigから開始します", "error", err)
		}
		if existing == nil {
			existing = map[string]interface{}{}
		}
		sensitiveKeys := map[string]bool{"api_token": true, "password": true, "token": true, "secret": true}
		for k, v := range req.Config {
			if sensitiveKeys[k] {
				if s, ok := v.(string); ok && s == "***" {
					// マスク済みの値は上書きしない
					continue
				}
			}
			existing[k] = v
		}
		b, err := json.Marshal(existing)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "config のシリアライズに失敗しました"})
			return
		}
		configJSON = b
	}

	_, err = h.pool.Exec(c.Request.Context(), `
		UPDATE soar_configs
		SET name=$2, enabled=$3, config=$4, min_severity=$5, auto_create=$6, updated_at=NOW()
		WHERE id=$1`,
		id, current.Name, current.Enabled, string(configJSON), current.MinSeverity, current.AutoCreate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SOAR設定の更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "SOAR設定を更新しました", "id": id})
}

// DeleteConfig removes a SOAR configuration.
// DELETE /api/v1/soar/configs/:id (admin)
func (h *SOARHandler) DeleteConfig(c *gin.Context) {
	id := c.Param("id")
	ct, err := h.pool.Exec(c.Request.Context(), `DELETE FROM soar_configs WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "SOAR設定が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "SOAR設定を削除しました"})
}

// TestConfig tests the connection for a SOAR configuration.
// POST /api/v1/soar/configs/:id/test
func (h *SOARHandler) TestConfig(c *gin.Context) {
	id := c.Param("id")

	var sc soarConfig
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, name, type, enabled, config, min_severity, auto_create, created_at, updated_at
		FROM soar_configs WHERE id = $1`, id,
	).Scan(&sc.ID, &sc.Name, &sc.Type, &sc.Enabled, &sc.Config,
		&sc.MinSeverity, &sc.AutoCreate, &sc.CreatedAt, &sc.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SOAR設定が見つかりません"})
		return
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(sc.Config, &configMap); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SOAR設定のパースに失敗しました"})
		return
	}

	client, err := soar.NewClient(sc.Type, configMap)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("クライアント初期化失敗: %s", err.Error())})
		return
	}

	if err := client.TestConnection(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "接続テスト成功"})
}

// CreateTicket creates an external ticket for the given incident.
// POST /api/v1/incidents/:id/ticket
func (h *SOARHandler) CreateTicket(c *gin.Context) {
	incidentID := c.Param("id")

	// リクエストボディ: 使用するSOAR設定IDを指定
	var req struct {
		ConfigID string `json:"config_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_id は必須です"})
		return
	}

	ctx := c.Request.Context()

	// 1. インシデントを取得
	type incidentRow struct {
		ID          string
		Title       string
		Description string
		Severity    int
		Status      string
	}
	var inc incidentRow
	err := h.pool.QueryRow(ctx, `
		SELECT id, title, COALESCE(description,''), severity, status
		FROM incidents WHERE id = $1`, incidentID,
	).Scan(&inc.ID, &inc.Title, &inc.Description, &inc.Severity, &inc.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "インシデントが見つかりません"})
		return
	}

	// 2. 紐付きアラートを取得してdescriptionに追加
	rows, err := h.pool.Query(ctx, `
		SELECT a.title, a.severity, a.hostname
		FROM alerts a
		JOIN incident_alerts ia ON ia.alert_id = a.id
		WHERE ia.incident_id = $1
		LIMIT 10`, incidentID)
	if err == nil {
		defer rows.Close()
		alertLines := ""
		for rows.Next() {
			var aTitle, aHostname string
			var aSeverity int
			if scanErr := rows.Scan(&aTitle, &aSeverity, &aHostname); scanErr == nil {
				alertLines += fmt.Sprintf("\n- [severity:%d] %s (%s)", aSeverity, aTitle, aHostname)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		if alertLines != "" {
			inc.Description += "\n\n## 関連アラート" + alertLines
		}
	}

	// 3. SOAR設定を取得
	var sc soarConfig
	err = h.pool.QueryRow(ctx, `
		SELECT id, name, type, enabled, config, min_severity, auto_create, created_at, updated_at
		FROM soar_configs WHERE id = $1`, req.ConfigID,
	).Scan(&sc.ID, &sc.Name, &sc.Type, &sc.Enabled, &sc.Config,
		&sc.MinSeverity, &sc.AutoCreate, &sc.CreatedAt, &sc.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SOAR設定が見つかりません"})
		return
	}
	if !sc.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "このSOAR設定は無効です"})
		return
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(sc.Config, &configMap); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SOAR設定のパースに失敗しました"})
		return
	}

	// 4. クライアントを生成してチケット作成
	client, err := soar.NewClient(sc.Type, configMap)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	priority := severityToPriority(inc.Severity)
	ticketReq := soar.TicketRequest{
		Title:       fmt.Sprintf("[EDR] %s", inc.Title),
		Description: inc.Description,
		Priority:    priority,
		Labels:      []string{"edr", "security"},
		IncidentID:  incidentID,
	}

	resp, err := client.CreateTicket(ctx, ticketReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// 5. incidents テーブルに外部チケット情報を更新
	_, err = h.pool.Exec(ctx, `
		UPDATE incidents
		SET external_ticket_id = $2,
		    external_ticket_url = $3,
		    external_system = $4,
		    updated_at = NOW()
		WHERE id = $1`,
		incidentID, resp.TicketID, resp.TicketURL, resp.System,
	)
	if err != nil {
		// チケット作成自体は成功しているので警告ログのみ
		c.JSON(http.StatusOK, gin.H{
			"ticket_id":  resp.TicketID,
			"ticket_url": resp.TicketURL,
			"system":     resp.System,
			"warning":    "チケットは作成されましたがDBの更新に失敗しました",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"ticket_id":  resp.TicketID,
		"ticket_url": resp.TicketURL,
		"system":     resp.System,
		"message":    "チケットを作成しました",
	})
}

// severityToPriority はインシデントの重大度 (1-10) を優先度文字列に変換します
func severityToPriority(severity int) string {
	switch {
	case severity >= 9:
		return "critical"
	case severity >= 7:
		return "high"
	case severity >= 4:
		return "medium"
	default:
		return "low"
	}
}

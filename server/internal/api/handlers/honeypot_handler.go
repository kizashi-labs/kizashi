package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HoneypotHandler manages honeypot/deception resources.
type HoneypotHandler struct {
	pool *pgxpool.Pool
}

// NewHoneypotHandler creates a new HoneypotHandler.
func NewHoneypotHandler(pool *pgxpool.Pool) *HoneypotHandler {
	return &HoneypotHandler{pool: pool}
}

func (h *HoneypotHandler) checkTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "honeypots")
}

func (h *HoneypotHandler) checkAccessTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "honeypot_accesses")
}

// List returns all honeypots.
// GET /api/v1/admin/honeypots
func (h *HoneypotHandler) List(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusOK, gin.H{"honeypots": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, description, honeypot_type, listen_address, listen_port,
		        agent_id, enabled, alert_on_access, access_count,
		        last_accessed_at, created_at, updated_at
		 FROM honeypots ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "honeypotの一覧取得に失敗しました"})
		return
	}
	defer rows.Close()

	type honeypot struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		Description    string  `json:"description"`
		HoneypotType   string  `json:"honeypot_type"`
		ListenAddress  string  `json:"listen_address"`
		ListenPort     int     `json:"listen_port"`
		AgentID        *string `json:"agent_id"`
		Enabled        bool    `json:"enabled"`
		AlertOnAccess  bool    `json:"alert_on_access"`
		AccessCount    int     `json:"access_count"`
		LastAccessedAt *string `json:"last_accessed_at"`
		CreatedAt      string  `json:"created_at"`
		UpdatedAt      string  `json:"updated_at"`
	}

	var result []honeypot
	for rows.Next() {
		var hp honeypot
		var lastAccessed *time.Time
		var createdAt, updatedAt time.Time
		if err := rows.Scan(
			&hp.ID, &hp.Name, &hp.Description, &hp.HoneypotType,
			&hp.ListenAddress, &hp.ListenPort, &hp.AgentID,
			&hp.Enabled, &hp.AlertOnAccess, &hp.AccessCount,
			&lastAccessed, &createdAt, &updatedAt,
		); err != nil {
			continue
		}
		if lastAccessed != nil {
			s := lastAccessed.Format(time.RFC3339)
			hp.LastAccessedAt = &s
		}
		hp.CreatedAt = createdAt.Format(time.RFC3339)
		hp.UpdatedAt = updatedAt.Format(time.RFC3339)
		result = append(result, hp)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "honeypotの一覧取得に失敗しました"})
		return
	}
	if result == nil {
		result = []honeypot{}
	}
	c.JSON(http.StatusOK, gin.H{"honeypots": result, "total": len(result)})
}

// Get returns a single honeypot.
// GET /api/v1/admin/honeypots/:id
func (h *HoneypotHandler) Get(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	var hp struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		Description    string  `json:"description"`
		HoneypotType   string  `json:"honeypot_type"`
		ListenAddress  string  `json:"listen_address"`
		ListenPort     int     `json:"listen_port"`
		AgentID        *string `json:"agent_id"`
		Enabled        bool    `json:"enabled"`
		AlertOnAccess  bool    `json:"alert_on_access"`
		AccessCount    int     `json:"access_count"`
		LastAccessedAt *string `json:"last_accessed_at"`
		CreatedAt      string  `json:"created_at"`
		UpdatedAt      string  `json:"updated_at"`
	}
	var lastAccessed *time.Time
	var createdAt, updatedAt time.Time
	err := h.pool.QueryRow(ctx,
		`SELECT id, name, description, honeypot_type, listen_address, listen_port,
		        agent_id, enabled, alert_on_access, access_count,
		        last_accessed_at, created_at, updated_at
		 FROM honeypots WHERE id=$1`, id).Scan(
		&hp.ID, &hp.Name, &hp.Description, &hp.HoneypotType,
		&hp.ListenAddress, &hp.ListenPort, &hp.AgentID,
		&hp.Enabled, &hp.AlertOnAccess, &hp.AccessCount,
		&lastAccessed, &createdAt, &updatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	if lastAccessed != nil {
		s := lastAccessed.Format(time.RFC3339)
		hp.LastAccessedAt = &s
	}
	hp.CreatedAt = createdAt.Format(time.RFC3339)
	hp.UpdatedAt = updatedAt.Format(time.RFC3339)
	c.JSON(http.StatusOK, hp)
}

// Create creates a new honeypot.
// POST /api/v1/admin/honeypots
func (h *HoneypotHandler) Create(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var body struct {
		Name          string  `json:"name" binding:"required"`
		Description   string  `json:"description"`
		HoneypotType  string  `json:"honeypot_type"`
		ListenAddress string  `json:"listen_address"`
		ListenPort    int     `json:"listen_port"`
		AgentID       *string `json:"agent_id"`
		Enabled       *bool   `json:"enabled"`
		AlertOnAccess *bool   `json:"alert_on_access"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameは必須です"})
		return
	}
	if body.ListenPort < 1 || body.ListenPort > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "listen_portは1から65535の範囲で指定してください"})
		return
	}
	if body.HoneypotType == "" {
		body.HoneypotType = "http"
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	alertOnAccess := true
	if body.AlertOnAccess != nil {
		alertOnAccess = *body.AlertOnAccess
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO honeypots (name, description, honeypot_type, listen_address, listen_port,
		                        agent_id, enabled, alert_on_access)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		body.Name, body.Description, body.HoneypotType, body.ListenAddress, body.ListenPort,
		body.AgentID, enabled, alertOnAccess,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "honeypotの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "honeypotを作成しました"})
}

// Update updates a honeypot.
// PUT /api/v1/admin/honeypots/:id
func (h *HoneypotHandler) Update(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name          string  `json:"name"`
		Description   string  `json:"description"`
		HoneypotType  string  `json:"honeypot_type"`
		ListenAddress string  `json:"listen_address"`
		ListenPort    int     `json:"listen_port"`
		AgentID       *string `json:"agent_id"`
		Enabled       *bool   `json:"enabled"`
		AlertOnAccess *bool   `json:"alert_on_access"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	if body.ListenPort != 0 && (body.ListenPort < 1 || body.ListenPort > 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "listen_portは1から65535の範囲で指定してください"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE honeypots SET name=$1, description=$2, honeypot_type=$3, listen_address=$4,
		                      listen_port=$5, agent_id=$6, enabled=$7, alert_on_access=$8,
		                      updated_at=NOW()
		 WHERE id=$9`,
		body.Name, body.Description, body.HoneypotType, body.ListenAddress, body.ListenPort,
		body.AgentID, body.Enabled, body.AlertOnAccess, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "honeypotの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "honeypotを更新しました"})
}

// Delete deletes a honeypot.
// DELETE /api/v1/admin/honeypots/:id
func (h *HoneypotHandler) Delete(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM honeypots WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "honeypotの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "honeypotを削除しました"})
}

// Toggle flips the enabled state of a honeypot.
// POST /api/v1/admin/honeypots/:id/toggle
func (h *HoneypotHandler) Toggle(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var enabled bool
	err := h.pool.QueryRow(ctx,
		`UPDATE honeypots SET enabled = NOT enabled, updated_at=NOW() WHERE id=$1 RETURNING enabled`, id,
	).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "honeypotの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}

// GetAccesses returns access records for a honeypot.
// GET /api/v1/admin/honeypots/:id/accesses
func (h *HoneypotHandler) GetAccesses(c *gin.Context) {
	if !h.checkAccessTable(c) {
		c.JSON(http.StatusOK, gin.H{"accesses": []interface{}{}, "total": 0})
		return
	}
	id := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, honeypot_id, source_ip, source_port, method, path, user_agent, payload, accessed_at
		 FROM honeypot_accesses WHERE honeypot_id=$1
		 ORDER BY accessed_at DESC LIMIT $2 OFFSET $3`,
		id, limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アクセス記録の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type access struct {
		ID         string  `json:"id"`
		HoneypotID string  `json:"honeypot_id"`
		SourceIP   string  `json:"source_ip"`
		SourcePort *int    `json:"source_port"`
		Method     *string `json:"method"`
		Path       *string `json:"path"`
		UserAgent  *string `json:"user_agent"`
		Payload    *string `json:"payload"`
		AccessedAt string  `json:"accessed_at"`
	}

	var result []access
	for rows.Next() {
		var a access
		var accessedAt time.Time
		if err := rows.Scan(
			&a.ID, &a.HoneypotID, &a.SourceIP, &a.SourcePort,
			&a.Method, &a.Path, &a.UserAgent, &a.Payload, &accessedAt,
		); err != nil {
			continue
		}
		a.AccessedAt = accessedAt.Format(time.RFC3339)
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アクセス記録の取得に失敗しました"})
		return
	}
	if result == nil {
		result = []access{}
	}
	c.JSON(http.StatusOK, gin.H{"accesses": result, "total": len(result)})
}

// SimulateAccess inserts a mock access record and optionally creates an alert.
// POST /api/v1/admin/honeypots/:id/simulate
func (h *HoneypotHandler) SimulateAccess(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	var body struct {
		SourceIP   string `json:"source_ip"`
		SourcePort *int   `json:"source_port"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		UserAgent  string `json:"user_agent"`
		Payload    string `json:"payload"`
	}
	// これはおとりへのアクセス記録を書く処理です。以前は本文が読めないと
	// 送信元 192.168.1.100 / GET / を作って記録していました。あとから見た
	// 人には、その IP から実際にアクセスがあったとしか読めません。
	if !OptionalBody(c, &body) {
		return
	}
	if body.SourceIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_ip は必須です。記録する送信元を作ることはできません"})
		return
	}

	ctx := c.Request.Context()

	// Check honeypot exists and get alert_on_access flag
	var alertOnAccess bool
	var hpName string
	err := h.pool.QueryRow(ctx,
		`SELECT name, alert_on_access FROM honeypots WHERE id=$1`, id,
	).Scan(&hpName, &alertOnAccess)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "honeypotが見つかりません"})
		return
	}

	// Insert access record
	if h.checkAccessTable(c) {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO honeypot_accesses (honeypot_id, source_ip, source_port, method, path, user_agent, payload)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, body.SourceIP, body.SourcePort, body.Method, body.Path, body.UserAgent, body.Payload,
		); err != nil {
			slog.Warn("honeypot: アクセスレコードの挿入に失敗しました", "honeypot_id", id, "error", err)
		}
	}

	// Increment access_count and update last_accessed_at
	if _, err := h.pool.Exec(ctx,
		`UPDATE honeypots SET access_count = access_count + 1, last_accessed_at=NOW(), updated_at=NOW()
		 WHERE id=$1`, id,
	); err != nil {
		slog.Warn("honeypot: アクセスカウント更新に失敗しました", "honeypot_id", id, "error", err)
	}

	// Create alert if configured
	if alertOnAccess {
		alertTitle := fmt.Sprintf("ハニーポットアクセス検出: %s", hpName)
		alertDesc := fmt.Sprintf("ハニーポット '%s' に %s からアクセスがありました", hpName, body.SourceIP)
		alertExists := tableIsThere(ctx, h.pool, "alerts")
		if alertExists {
			if _, err := h.pool.Exec(ctx,
				`INSERT INTO alerts (title, description, severity, status, source)
				 VALUES ($1,$2,$3,'open','honeypot')`,
				alertTitle, alertDesc, 3,
			); err != nil {
				slog.Warn("honeypot: アラートの挿入に失敗しました", "honeypot_id", id, "error", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "シミュレートアクセスを記録しました", "honeypot_id": id})
}

// GetStats returns honeypot statistics.
// GET /api/v1/admin/honeypots/stats
func (h *HoneypotHandler) GetStats(c *gin.Context) {
	if !h.checkTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"total":                0,
			"active":               0,
			"total_accesses_today": 0,
			"total_accesses_week":  0,
		})
		return
	}
	ctx := c.Request.Context()

	var total, active int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM honeypots`).Scan(&total, &active)) {
		return
	}

	var accessesToday, accessesWeek int
	if h.checkAccessTable(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT
				  COUNT(*) FILTER (WHERE accessed_at >= NOW() - INTERVAL '1 day'),
				  COUNT(*) FILTER (WHERE accessed_at >= NOW() - INTERVAL '7 days')
				 FROM honeypot_accesses`).Scan(&accessesToday, &accessesWeek)) {
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":                total,
		"active":               active,
		"total_accesses_today": accessesToday,
		"total_accesses_week":  accessesWeek,
	})
}

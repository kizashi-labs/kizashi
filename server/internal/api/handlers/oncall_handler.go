package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// OnCallHandler manages PagerDuty/OpsGenie alerting integrations.
type OnCallHandler struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewOnCallHandler creates a new OnCallHandler.
func NewOnCallHandler(pool *pgxpool.Pool, nc *nats.Conn) *OnCallHandler {
	return &OnCallHandler{pool: pool, nc: nc}
}

type oncallIntegration struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Provider             string     `json:"provider"`
	IntegrationKeyMasked string     `json:"integration_key"`
	APIURL               string     `json:"api_url"`
	SeverityThreshold    int        `json:"severity_threshold"`
	Enabled              bool       `json:"enabled"`
	EventsSent           int        `json:"events_sent"`
	LastEventAt          *time.Time `json:"last_event_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type oncallEvent struct {
	ID            string    `json:"id"`
	IntegrationID string    `json:"integration_id"`
	AlertID       *string   `json:"alert_id,omitempty"`
	EventType     string    `json:"event_type"`
	DedupKey      string    `json:"dedup_key"`
	Summary       string    `json:"summary"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	ResponseCode  *int      `json:"response_code,omitempty"`
	SentAt        time.Time `json:"sent_at"`
}

func maskIntegrationKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(key)-4) + key[len(key)-4:]
}

func (h *OnCallHandler) ensureTables(ctx context.Context) error {
	_, err := h.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS oncall_integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'pagerduty',
  integration_key TEXT NOT NULL,
  api_url TEXT NOT NULL DEFAULT '',
  severity_threshold INT NOT NULL DEFAULT 8,
  enabled BOOL NOT NULL DEFAULT TRUE,
  events_sent INT NOT NULL DEFAULT 0,
  last_event_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS oncall_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id UUID NOT NULL,
  alert_id UUID,
  event_type TEXT NOT NULL DEFAULT 'trigger',
  dedup_key TEXT NOT NULL,
  summary TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'critical',
  status TEXT NOT NULL DEFAULT 'sent',
  response_code INT,
  sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oncall_events_integration ON oncall_events(integration_id, sent_at DESC);
`)
	return err
}

// ListIntegrations — GET /admin/oncall
func (h *OnCallHandler) ListIntegrations(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, provider, integration_key, api_url, severity_threshold,
		        enabled, events_sent, last_event_at, created_at, updated_at
		 FROM oncall_integrations ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	var result []oncallIntegration
	for rows.Next() {
		var it oncallIntegration
		var rawKey string
		if err := rows.Scan(&it.ID, &it.Name, &it.Provider, &rawKey, &it.APIURL,
			&it.SeverityThreshold, &it.Enabled, &it.EventsSent, &it.LastEventAt,
			&it.CreatedAt, &it.UpdatedAt); err != nil {
			continue
		}
		it.IntegrationKeyMasked = maskIntegrationKey(rawKey)
		result = append(result, it)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if result == nil {
		result = []oncallIntegration{}
	}
	c.JSON(http.StatusOK, gin.H{"integrations": result})
}

// GetIntegration — GET /admin/oncall/:id
func (h *OnCallHandler) GetIntegration(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var it oncallIntegration
	var rawKey string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, name, provider, integration_key, api_url, severity_threshold,
		        enabled, events_sent, last_event_at, created_at, updated_at
		 FROM oncall_integrations WHERE id = $1`, id).
		Scan(&it.ID, &it.Name, &it.Provider, &rawKey, &it.APIURL,
			&it.SeverityThreshold, &it.Enabled, &it.EventsSent, &it.LastEventAt,
			&it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "統合が見つかりません"})
		return
	}
	it.IntegrationKeyMasked = maskIntegrationKey(rawKey)
	c.JSON(http.StatusOK, it)
}

// CreateIntegration — POST /admin/oncall
func (h *OnCallHandler) CreateIntegration(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		Name              string `json:"name" binding:"required"`
		Provider          string `json:"provider"`
		IntegrationKey    string `json:"integration_key" binding:"required"`
		APIURL            string `json:"api_url"`
		SeverityThreshold int    `json:"severity_threshold"`
		Enabled           *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	validProviders := map[string]bool{"pagerduty": true, "opsgenie": true, "victorops": true}
	if req.Provider == "" {
		req.Provider = "pagerduty"
	}
	if !validProviders[req.Provider] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "プロバイダーはpagerduty/opsgenie/victoropsのいずれかである必要があります"})
		return
	}
	if req.SeverityThreshold == 0 {
		req.SeverityThreshold = 8
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO oncall_integrations (name, provider, integration_key, api_url, severity_threshold, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.Name, req.Provider, req.IntegrationKey, req.APIURL, req.SeverityThreshold, enabled).
		Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "統合を作成しました"})
}

// UpdateIntegration — PUT /admin/oncall/:id
func (h *OnCallHandler) UpdateIntegration(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var req struct {
		Name              *string `json:"name"`
		Provider          *string `json:"provider"`
		IntegrationKey    *string `json:"integration_key"`
		APIURL            *string `json:"api_url"`
		SeverityThreshold *int    `json:"severity_threshold"`
		Enabled           *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Provider != nil {
		validProviders := map[string]bool{"pagerduty": true, "opsgenie": true, "victorops": true}
		if !validProviders[*req.Provider] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "プロバイダーはpagerduty/opsgenie/victoropsのいずれかである必要があります"})
			return
		}
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`UPDATE oncall_integrations SET
		   name = COALESCE($2, name),
		   provider = COALESCE($3, provider),
		   integration_key = COALESCE($4, integration_key),
		   api_url = COALESCE($5, api_url),
		   severity_threshold = COALESCE($6, severity_threshold),
		   enabled = COALESCE($7, enabled),
		   updated_at = NOW()
		 WHERE id = $1`,
		id, req.Name, req.Provider, req.IntegrationKey, req.APIURL, req.SeverityThreshold, req.Enabled)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "統合が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
}

// DeleteIntegration — DELETE /admin/oncall/:id
func (h *OnCallHandler) DeleteIntegration(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM oncall_integrations WHERE id = $1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "統合が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// ToggleIntegration — POST /admin/oncall/:id/toggle
func (h *OnCallHandler) ToggleIntegration(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(),
		`UPDATE oncall_integrations SET enabled = NOT enabled, updated_at = NOW()
		 WHERE id = $1 RETURNING enabled`, id).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "統合が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}

// oncallHTTPClient is shared across all provider calls.
var oncallHTTPClient = &http.Client{Timeout: 15 * time.Second}

// sendProviderAlert sends an alert event to the configured on-call provider.
// Supports: pagerduty, opsgenie, victorops
func sendProviderAlert(ctx context.Context, provider, integrationKey, summary, severity string) (int, error) {
	var (
		endpoint string
		payload  map[string]interface{}
		headers  map[string]string
	)

	switch provider {
	case "opsgenie":
		// OpsGenie Alert API v2
		endpoint = "https://api.opsgenie.com/v2/alerts"
		payload = map[string]interface{}{
			"message":  summary,
			"priority": opsGeniePriority(severity),
			"source":   "edr-platform",
			"tags":     []string{"edr", severity},
		}
		headers = map[string]string{
			"Authorization": "GenieKey " + integrationKey,
			"Content-Type":  "application/json",
		}

	case "victorops":
		// VictorOps REST Endpoint
		endpoint = "https://alert.victorops.com/integrations/generic/20131114/alert/" + integrationKey
		payload = map[string]interface{}{
			"message_type":  victorOpsMessageType(severity),
			"entity_id":     "edr-platform-alert",
			"state_message": summary,
		}
		headers = map[string]string{"Content-Type": "application/json"}

	default: // pagerduty
		// PagerDuty Events API v2
		endpoint = "https://events.pagerduty.com/v2/enqueue"
		payload = map[string]interface{}{
			"routing_key":  integrationKey,
			"event_action": "trigger",
			"payload": map[string]interface{}{
				"summary":  summary,
				"severity": pagerDutySeverity(severity),
				"source":   "edr-platform",
			},
		}
		headers = map[string]string{"Content-Type": "application/json"}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("ペイロードのシリアライズ失敗: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return 0, fmt.Errorf("リクエスト作成失敗: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := oncallHTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s へのHTTPリクエスト失敗: %w", provider, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func pagerDutySeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

func opsGeniePriority(s string) string {
	switch s {
	case "critical":
		return "P1"
	case "high":
		return "P2"
	case "medium":
		return "P3"
	default:
		return "P5"
	}
}

func victorOpsMessageType(s string) string {
	switch s {
	case "critical", "high":
		return "CRITICAL"
	case "medium":
		return "WARNING"
	default:
		return "INFO"
	}
}

// TestIntegration — POST /admin/oncall/:id/test
func (h *OnCallHandler) TestIntegration(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var provider, integrationKey string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT provider, integration_key FROM oncall_integrations WHERE id = $1`, id).
		Scan(&provider, &integrationKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "統合が見つかりません"})
		return
	}

	summary := "EDRプラットフォーム テストイベント"
	severity := "info"
	responseCode, _ := sendProviderAlert(c.Request.Context(), provider, integrationKey, summary, severity)

	dedupKey := fmt.Sprintf("test-%s-%d", id, time.Now().UnixNano())
	_, _ = h.pool.Exec(c.Request.Context(),
		`INSERT INTO oncall_events (integration_id, event_type, dedup_key, summary, severity, status, response_code)
		 VALUES ($1, 'test', $2, $3, $4, 'sent', $5)`,
		id, dedupKey, summary, severity, responseCode)

	_, _ = h.pool.Exec(c.Request.Context(),
		`UPDATE oncall_integrations SET events_sent = events_sent + 1, last_event_at = NOW(), updated_at = NOW()
		 WHERE id = $1`, id)

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"response_code": responseCode,
		"message":       "テストイベントを送信しました",
	})
}

// GetEvents — GET /admin/oncall/:id/events
func (h *OnCallHandler) GetEvents(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, integration_id, alert_id::TEXT, event_type, dedup_key, summary, severity, status, response_code, sent_at
		 FROM oncall_events WHERE integration_id = $1 ORDER BY sent_at DESC LIMIT 100`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	var events []oncallEvent
	for rows.Next() {
		var ev oncallEvent
		if err := rows.Scan(&ev.ID, &ev.IntegrationID, &ev.AlertID, &ev.EventType,
			&ev.DedupKey, &ev.Summary, &ev.Severity, &ev.Status, &ev.ResponseCode, &ev.SentAt); err != nil {
			continue
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if events == nil {
		events = []oncallEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

// TriggerAlert — POST /oncall/trigger
func (h *OnCallHandler) TriggerAlert(c *gin.Context) {
	if err := h.ensureTables(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		AlertID  *string `json:"alert_id"`
		Summary  string  `json:"summary" binding:"required"`
		Severity string  `json:"severity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Severity == "" {
		req.Severity = "critical"
	}

	// Map severity string to numeric score
	severityScore := map[string]int{
		"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1,
	}
	score := severityScore[req.Severity]
	if score == 0 {
		score = 5
	}

	// Find enabled integrations above threshold
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, provider, integration_key FROM oncall_integrations
		 WHERE enabled = TRUE AND severity_threshold <= $1`, score)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "統合の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var triggered int
	for rows.Next() {
		var intID, provider, key string
		if err := rows.Scan(&intID, &provider, &key); err != nil {
			continue
		}

		responseCode, _ := sendProviderAlert(c.Request.Context(), provider, key, req.Summary, req.Severity)
		dedupKey := fmt.Sprintf("alert-%s-%d", intID, time.Now().UnixNano())

		_, _ = h.pool.Exec(c.Request.Context(),
			`INSERT INTO oncall_events (integration_id, alert_id, event_type, dedup_key, summary, severity, status, response_code)
			 VALUES ($1, $2, 'trigger', $3, $4, $5, 'sent', $6)`,
			intID, req.AlertID, dedupKey, req.Summary, req.Severity, responseCode)

		_, _ = h.pool.Exec(c.Request.Context(),
			`UPDATE oncall_integrations SET events_sent = events_sent + 1, last_event_at = NOW(), updated_at = NOW()
			 WHERE id = $1`, intID)
		triggered++
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{"triggered": triggered, "message": "アラートをトリガーしました"})
}

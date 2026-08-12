// Package investigation provides AI-powered automatic alert investigation.
package investigation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	openAIAPIURL = "https://api.openai.com/v1/chat/completions"
	openAIModel  = "gpt-4o"

	// InvestigationModeStandard is the default mode with basic analysis.
	InvestigationModeStandard = "standard"
	// InvestigationModeAutonomous uses the agentic AI with richer prompts,
	// structured output, MITRE mapping, response recommendations, and Japanese reports.
	InvestigationModeAutonomous = "autonomous"
)

// InvestigatorConfig holds configuration for the Investigator.
type InvestigatorConfig struct {
	OpenAIKey    string
	AnthropicKey string
}

// InvestigationMode holds runtime settings that control the investigation behaviour.
// These values are read from system_settings in the DB before each investigation.
type InvestigationMode struct {
	Mode         string `json:"mode"`          // "standard" or "autonomous"
	Model        string `json:"model"`         // e.g. "claude-haiku-4-5-20251001"
	MaxTokens    int    `json:"max_tokens"`    // token limit for LLM response
	AutoResponse bool   `json:"auto_response"` // whether the agent should suggest auto-response actions
	Language     string `json:"language"`      // "ja" or "en"
}

// DefaultMode returns the default (standard) investigation settings.
func DefaultMode() InvestigationMode {
	return InvestigationMode{
		Mode:         InvestigationModeStandard,
		Model:        "claude-haiku-4-5-20251001",
		MaxTokens:    1024,
		AutoResponse: false,
		Language:     "ja",
	}
}

// InvestigationResult contains the outcome of an AI investigation.
type InvestigationResult struct {
	AlertID        string    `json:"alert_id"`
	Summary        string    `json:"summary"`
	Model          string    `json:"model"`
	Mode           string    `json:"mode"`
	InvestigatedAt time.Time `json:"investigated_at"`
}

// Alert holds the alert fields needed for investigation.
type Alert struct {
	ID          string
	AgentID     string
	Hostname    string
	OS          string
	Severity    int
	Title       string
	Description string
	MITRETech   string
	RuleName    string
	CreatedAt   time.Time
}

// Event represents a single agent event used as investigation context.
type Event struct {
	EventType string
	RawData   json.RawMessage
	Timestamp time.Time
}

// Investigator orchestrates AI-powered alert investigations.
type Investigator struct {
	db           *pgxpool.Pool
	httpClient   *http.Client
	openAIKey    string
	anthropicKey string
}

// NewInvestigator creates a new Investigator.
func NewInvestigator(db *pgxpool.Pool, cfg InvestigatorConfig) *Investigator {
	return &Investigator{
		db: db,
		httpClient: &http.Client{
			Timeout: 300 * time.Second,
		},
		openAIKey:    cfg.OpenAIKey,
		anthropicKey: cfg.AnthropicKey,
	}
}

// IsConfigured returns true if at least one AI API key is present.
func (inv *Investigator) IsConfigured() bool {
	return inv.openAIKey != "" || inv.anthropicKey != ""
}

// DB exposes the underlying pool for callers that need to run their own queries
// (e.g. the HTTP handler reading persisted investigation results).
func (inv *Investigator) DB() *pgxpool.Pool {
	return inv.db
}

// ReadModeFromDB reads the current AI investigation settings from system_settings.
func (inv *Investigator) ReadModeFromDB(ctx context.Context) InvestigationMode {
	m := DefaultMode()

	rows, err := inv.db.Query(ctx, `
		SELECT key, value FROM system_settings
		WHERE key IN (
			'ai_investigation_mode',
			'ai_autonomous_model',
			'ai_autonomous_max_tokens',
			'ai_autonomous_auto_response',
			'ai_autonomous_language'
		)`)
	if err != nil {
		slog.Warn("investigation: failed to read mode from DB, using defaults", "error", err)
		return m
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var rawValue []byte
		if err := rows.Scan(&key, &rawValue); err != nil {
			continue
		}
		// system_settings stores JSONB, so values are JSON-encoded strings/numbers/booleans.
		switch key {
		case "ai_investigation_mode":
			var v string
			if json.Unmarshal(rawValue, &v) == nil {
				m.Mode = v
			}
		case "ai_autonomous_model":
			var v string
			if json.Unmarshal(rawValue, &v) == nil && v != "" {
				m.Model = v
			}
		case "ai_autonomous_max_tokens":
			var v int
			if json.Unmarshal(rawValue, &v) == nil && v > 0 {
				m.MaxTokens = v
			}
		case "ai_autonomous_auto_response":
			var v bool
			if json.Unmarshal(rawValue, &v) == nil {
				m.AutoResponse = v
			}
		case "ai_autonomous_language":
			var v string
			if json.Unmarshal(rawValue, &v) == nil && v != "" {
				m.Language = v
			}
		}
	}
	return m
}

// InvestigateAlert performs an AI investigation for the given alert ID.
// It fetches the alert, gathers context events, calls the LLM, then persists
// the summary back on the alert record.
func (inv *Investigator) InvestigateAlert(ctx context.Context, alertID string) (*InvestigationResult, error) {
	return inv.InvestigateAlertWithMode(ctx, alertID, nil)
}

// InvestigateAlertWithMode performs an investigation using the given mode.
// If mode is nil, the current mode is read from system_settings.
func (inv *Investigator) InvestigateAlertWithMode(ctx context.Context, alertID string, mode *InvestigationMode) (*InvestigationResult, error) {
	if !inv.IsConfigured() {
		slog.Debug("investigation: no AI API key configured, skipping", "alert_id", alertID)
		return nil, nil
	}

	// Resolve mode from DB if not provided.
	if mode == nil {
		m := inv.ReadModeFromDB(ctx)
		mode = &m
	}

	slog.Info("investigation: starting", "alert_id", alertID, "mode", mode.Mode)

	// 1. Fetch alert.
	alert, err := inv.fetchAlert(ctx, alertID)
	if err != nil {
		return nil, fmt.Errorf("investigation: fetch alert %s: %w", alertID, err)
	}

	// 2. Gather related events from the last 10 minutes.
	events, err := inv.gatherEvents(ctx, alert.AgentID, alert.CreatedAt)
	if err != nil {
		slog.Warn("investigation: failed to gather events, proceeding without context",
			"alert_id", alertID, "error", err)
		events = []Event{}
	}

	// 3. Build prompt (differs by mode).
	var prompt string
	if mode.Mode == InvestigationModeAutonomous {
		prompt = buildAutonomousPrompt(alert, events, mode)
	} else {
		prompt = buildPrompt(alert, events)
	}

	// 4. Call LLM.
	var summary string
	var model string
	if mode.Mode == InvestigationModeAutonomous && inv.anthropicKey != "" {
		// Autonomous mode always uses Anthropic with the configured model & tokens.
		summary, model, err = inv.callAnthropicWithConfig(ctx, prompt, mode.Model, mode.MaxTokens)
	} else if inv.openAIKey != "" {
		summary, model, err = inv.callOpenAI(ctx, prompt)
	} else {
		summary, model, err = inv.callAnthropic(ctx, prompt)
	}
	if err != nil {
		return nil, fmt.Errorf("investigation: LLM call failed for alert %s: %w", alertID, err)
	}

	// 5. Persist summary.
	now := time.Now().UTC()
	_, dbErr := inv.db.Exec(ctx, `
		UPDATE alerts
		SET ai_summary          = $2,
		    ai_investigated_at  = $3,
		    ai_model            = $4,
		    updated_at          = NOW()
		WHERE id = $1`,
		alertID, summary, now, model,
	)
	if dbErr != nil {
		slog.Warn("investigation: failed to persist summary", "alert_id", alertID, "error", dbErr)
	}

	result := &InvestigationResult{
		AlertID:        alertID,
		Summary:        summary,
		Model:          model,
		Mode:           mode.Mode,
		InvestigatedAt: now,
	}
	slog.Info("investigation: completed", "alert_id", alertID, "model", model, "mode", mode.Mode)
	return result, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (inv *Investigator) fetchAlert(ctx context.Context, alertID string) (Alert, error) {
	row := inv.db.QueryRow(ctx, `
		SELECT
			al.id,
			al.agent_id,
			COALESCE(ag.hostname, al.agent_id::text),
			COALESCE(ag.os_type, ''),
			al.severity,
			al.title,
			COALESCE(al.description, ''),
			COALESCE(al.mitre_technique, ''),
			COALESCE(r.name, ''),
			al.created_at
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules  r  ON r.id  = al.rule_id
		WHERE al.id = $1`, alertID)

	var a Alert
	err := row.Scan(
		&a.ID, &a.AgentID, &a.Hostname, &a.OS,
		&a.Severity, &a.Title, &a.Description,
		&a.MITRETech, &a.RuleName, &a.CreatedAt,
	)
	return a, err
}

func (inv *Investigator) gatherEvents(ctx context.Context, agentID string, alertTime time.Time) ([]Event, error) {
	from := alertTime.Add(-10 * time.Minute)
	to := alertTime.Add(1 * time.Minute)

	// テレメトリの実表は `events` (migration 002 の hypertable)。
	// `agent_events` というテーブルはこのスキーマに存在しない。
	// 以前は agent_events を先に引いて、失敗したら events に落ちる形だったが、
	// 前段は毎回 `relation "agent_events" does not exist` で失敗するだけで、
	// 1 クエリ分のラウンドトリップを無駄にしていた。
	rows, err := inv.db.Query(ctx, `
		SELECT event_type, raw_data, "time"
		FROM events
		WHERE agent_id = $1::uuid
		  AND "time" BETWEEN $2 AND $3
		ORDER BY "time" ASC
		LIMIT 100`,
		agentID, from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var rawData []byte
		var ts time.Time
		if err := rows.Scan(&e.EventType, &rawData, &ts); err != nil {
			continue
		}
		e.RawData = json.RawMessage(rawData)
		e.Timestamp = ts
		events = append(events, e)
	}
	return events, rows.Err()
}

// ─── OpenAI call ──────────────────────────────────────────────────────────────

func (inv *Investigator) callOpenAI(ctx context.Context, prompt string) (string, string, error) {
	reqBody := map[string]interface{}{
		"model": openAIModel,
		"messages": []map[string]interface{}{
			{
				"role":    "system",
				"content": "You are a senior security analyst at a SOC. Provide concise, actionable investigation summaries.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  1024,
		"temperature": 0.2,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("marshal openai request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("build openai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+inv.openAIKey)

	resp, err := inv.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("openai http call: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read openai response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("openai API error %d: %s", resp.StatusCode, string(respBytes))
	}

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(respBytes, &openAIResp); err != nil {
		return "", "", fmt.Errorf("unmarshal openai response: %w", err)
	}
	if len(openAIResp.Choices) == 0 {
		return "", "", fmt.Errorf("openai returned no choices")
	}

	model := openAIResp.Model
	if model == "" {
		model = openAIModel
	}
	return openAIResp.Choices[0].Message.Content, model, nil
}

// ─── Anthropic call ───────────────────────────────────────────────────────────

const (
	anthropicAPIURL = "https://api.anthropic.com/v1/messages"
	anthropicModel  = "claude-haiku-4-5-20251001"
)

// callAnthropicWithConfig calls Anthropic API with a specific model and token limit.
func (inv *Investigator) callAnthropicWithConfig(ctx context.Context, prompt, model string, maxTokens int) (string, string, error) {
	reqBody := map[string]interface{}{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []map[string]interface{}{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("marshal anthropic request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("build anthropic request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", inv.anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := inv.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("anthropic http call: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read anthropic response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("anthropic API error %d: %s", resp.StatusCode, string(respBytes))
	}

	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBytes, &anthropicResp); err != nil {
		return "", "", fmt.Errorf("unmarshal anthropic response: %w", err)
	}
	for _, block := range anthropicResp.Content {
		if block.Type == "text" {
			return block.Text, model, nil
		}
	}
	return "", "", fmt.Errorf("anthropic returned no text content")
}

func (inv *Investigator) callAnthropic(ctx context.Context, prompt string) (string, string, error) {
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 1024,
		"messages": []map[string]interface{}{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("marshal anthropic request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("build anthropic request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", inv.anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := inv.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("anthropic http call: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read anthropic response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("anthropic API error %d: %s", resp.StatusCode, string(respBytes))
	}

	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBytes, &anthropicResp); err != nil {
		return "", "", fmt.Errorf("unmarshal anthropic response: %w", err)
	}
	for _, block := range anthropicResp.Content {
		if block.Type == "text" {
			return block.Text, anthropicModel, nil
		}
	}
	return "", "", fmt.Errorf("anthropic returned no text content")
}

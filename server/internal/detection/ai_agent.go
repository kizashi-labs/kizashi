// Package detection provides the Claude AI agent for deep threat analysis.
// This module is the intelligence layer of the EDR platform:
//   - Receives high-scoring events from the detection engine
//   - Uses Claude API with tool use to analyze threats
//   - Makes auto-response decisions with reasoning
//   - Generates human-readable investigation reports
package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ─── Claude API Types ─────────────────────────────────────────

type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []claudeMessage `json:"messages"`
	Tools     []claudeTool    `json:"tools"`
}

type claudeMessage struct {
	Role    string        `json:"role"`
	Content []claudeBlock `json:"content"`
}

type claudeBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

type claudeTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type claudeResponse struct {
	ID         string        `json:"id"`
	Type       string        `json:"type"`
	Role       string        `json:"role"`
	Content    []claudeBlock `json:"content"`
	StopReason string        `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ─── AI Analysis Result ───────────────────────────────────────

type ThreatAnalysis struct {
	AlertID            string                `json:"alert_id"`
	IsThreat           bool                  `json:"is_threat"`
	IsFalsePositive    bool                  `json:"is_false_positive"`
	Severity           int                   `json:"severity"`   // 1-10
	Confidence         float64               `json:"confidence"` // 0-1
	ThreatName         string                `json:"threat_name"`
	AttackTechniques   []MITRETechnique      `json:"attack_techniques"`
	AttackChain        []string              `json:"attack_chain"`
	RecommendedActions []ResponseAction      `json:"recommended_actions"`
	AutoResponse       *AutoResponseDecision `json:"auto_response,omitempty"`
	Summary            string                `json:"summary"`         // Japanese summary for analysts
	DetailedReport     string                `json:"detailed_report"` // Full Japanese report
	AnalyzedAt         time.Time             `json:"analyzed_at"`
}

type MITRETechnique struct {
	ID   string `json:"id"`   // e.g. "T1059.001"
	Name string `json:"name"` // e.g. "PowerShell"
}

type ResponseAction struct {
	Action   string `json:"action"`   // isolate|kill_process|quarantine_file|collect_artifact
	Target   string `json:"target"`   // PID, file path, etc.
	Priority string `json:"priority"` // immediate|high|normal
	Reason   string `json:"reason"`
}

type AutoResponseDecision struct {
	ShouldIsolate     bool   `json:"should_isolate"`
	ShouldKillProcess bool   `json:"should_kill_process"`
	KillPID           uint32 `json:"kill_pid,omitempty"`
	ShouldQuarantine  bool   `json:"should_quarantine"`
	QuarantinePath    string `json:"quarantine_path,omitempty"`
	Reasoning         string `json:"reasoning"`
}

// ─── Claude AI Agent ──────────────────────────────────────────

type AIAgent struct {
	apiKey     string
	model      string
	httpClient *http.Client
	store      AlertStore
	commander  AgentCommander
}

// AlertStore retrieves event history for context.
type AlertStore interface {
	GetRecentEvents(agentID string, limit int) ([]EventSummary, error)
	GetAlertHistory(agentID string, days int) ([]AlertSummary, error)
}

// AgentCommander sends response commands to endpoints.
type AgentCommander interface {
	IsolateEndpoint(ctx context.Context, agentID, reason, alertID, commandID string) error
	KillProcess(ctx context.Context, agentID string, pid uint32, reason, commandID string) error
	QuarantineFile(ctx context.Context, agentID, path, alertID, commandID string) error
}

type EventSummary struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Summary   string    `json:"summary"`
}

type AlertSummary struct {
	Title     string    `json:"title"`
	Severity  int       `json:"severity"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

func NewAIAgent(apiKey string, store AlertStore, commander AgentCommander) *AIAgent {
	return &AIAgent{
		apiKey: apiKey,
		model:  "claude-opus-4-6",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		store:     store,
		commander: commander,
	}
}

// SetModel overrides the default Claude model.
func (a *AIAgent) SetModel(model string) {
	a.model = model
}

// AnalyzeThreat sends a suspicious alert to Claude for deep analysis
// and executes auto-response actions based on the AI decision.
func (a *AIAgent) AnalyzeThreat(ctx context.Context, alert *Alert) (*ThreatAnalysis, error) {
	// Gather context: recent events from this endpoint
	recentEvents, _ := a.store.GetRecentEvents(alert.AgentID, 20)
	alertHistory, _ := a.store.GetAlertHistory(alert.AgentID, 7)

	// Build analysis prompt
	prompt := buildAnalysisPrompt(alert, recentEvents, alertHistory)

	// Define tools Claude can use
	tools := []claudeTool{
		{
			Name:        "submit_analysis",
			Description: "Submit the completed threat analysis with recommended response actions",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"is_threat": {"type": "boolean", "description": "Is this a real threat (true) or false positive (false)?"},
					"is_false_positive": {"type": "boolean"},
					"severity": {"type": "integer", "minimum": 1, "maximum": 10, "description": "Threat severity 1-10"},
					"confidence": {"type": "number", "minimum": 0, "maximum": 1},
					"threat_name": {"type": "string", "description": "Name/family of the threat if identified"},
					"attack_techniques": {
						"type": "array",
						"items": {
							"type": "object",
							"properties": {
								"id": {"type": "string"},
								"name": {"type": "string"}
							}
						}
					},
					"attack_chain": {"type": "array", "items": {"type": "string"}},
					"auto_response": {
						"type": "object",
						"properties": {
							"should_isolate": {"type": "boolean"},
							"should_kill_process": {"type": "boolean"},
							"kill_pid": {"type": "integer"},
							"should_quarantine": {"type": "boolean"},
							"quarantine_path": {"type": "string"},
							"reasoning": {"type": "string"}
						}
					},
					"summary": {"type": "string", "description": "Brief Japanese summary for analysts (2-3 sentences)"},
					"detailed_report": {"type": "string", "description": "Detailed Japanese investigation report"}
				},
				"required": ["is_threat", "severity", "confidence", "summary", "detailed_report"]
			}`),
		},
	}

	// Call Claude API with agentic loop
	analysis, err := a.runAgentLoop(ctx, prompt, tools)
	if err != nil {
		return nil, fmt.Errorf("claude analysis: %w", err)
	}

	analysis.AlertID = alert.ID
	analysis.AnalyzedAt = time.Now()

	// Execute auto-response if AI recommends it
	if analysis.AutoResponse != nil && alert.AutoResponseEnabled {
		if err := a.executeAutoResponse(ctx, alert, analysis); err != nil {
			// Log but don't fail - analysis is still valuable
			analysis.AutoResponse.Reasoning += fmt.Sprintf("\n[Auto-response execution error: %s]", err)
		}
	}

	return analysis, nil
}

// runAgentLoop implements the Claude tool-use agentic loop.
func (a *AIAgent) runAgentLoop(ctx context.Context, prompt string, tools []claudeTool) (*ThreatAnalysis, error) {
	messages := []claudeMessage{
		{
			Role:    "user",
			Content: []claudeBlock{{Type: "text", Text: prompt}},
		},
	}

	systemPrompt := `あなたはエンタープライズEDR（Endpoint Detection and Response）プラットフォームのセキュリティ分析AIエージェントです。

役割:
- 提供されたエンドポイントのセキュリティイベントを分析し、真の脅威か誤検知かを判断する
- MITRE ATT&CKフレームワークに基づいて攻撃手法を特定する
- エンドポイントの隔離、プロセス終了、ファイル隔離などの自動対応を推奨する
- 日本語でセキュリティアナリスト向けの分かりやすいレポートを生成する

判断基準:
- 重大度9-10: ランサムウェア、APT活動、クレデンシャルダンプ → 即座の隔離を推奨
- 重大度7-8: マルウェア感染の疑い、C2通信 → プロセス終了とファイル隔離を推奨
- 重大度5-6: 疑わしい行動だが確定的でない → 監視継続、調査推奨
- 重大度1-4: 誤検知の可能性が高い → 誤検知としてマーク

注意: 自動隔離は慎重に推奨すること。業務への影響を考慮し、確信がある場合のみ推奨する。`

	for iteration := 0; iteration < 5; iteration++ {
		resp, err := a.callClaude(ctx, messages, systemPrompt, tools)
		if err != nil {
			return nil, err
		}

		// Add assistant response to conversation
		messages = append(messages, claudeMessage{
			Role:    "assistant",
			Content: resp.Content,
		})

		// Check if Claude used the submit_analysis tool
		var toolResults []claudeBlock
		for _, block := range resp.Content {
			if block.Type == "tool_use" && block.Name == "submit_analysis" {
				var analysis ThreatAnalysis
				if err := json.Unmarshal(block.Input, &analysis); err != nil {
					return nil, fmt.Errorf("parse analysis: %w", err)
				}
				return &analysis, nil
			}
			if block.Type == "tool_use" {
				toolResults = append(toolResults, claudeBlock{
					Type:      "tool_result",
					ToolUseID: block.ID,
					Content:   "Tool executed successfully",
				})
			}
		}

		if resp.StopReason == "end_turn" && len(toolResults) == 0 {
			// Claude finished without using tool - extract from text
			return extractAnalysisFromText(resp.Content), nil
		}

		if len(toolResults) > 0 {
			messages = append(messages, claudeMessage{
				Role:    "user",
				Content: toolResults,
			})
		}
	}

	return nil, fmt.Errorf("agent loop did not produce analysis after 5 iterations")
}

func (a *AIAgent) callClaude(ctx context.Context, messages []claudeMessage, system string, tools []claudeTool) (*claudeResponse, error) {
	reqBody := claudeRequest{
		Model:     a.model,
		MaxTokens: 4096,
		System:    system,
		Messages:  messages,
		Tools:     tools,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claude API error %d: %s", resp.StatusCode, string(respBody))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &claudeResp, nil
}

// executeAutoResponse acts on Claude's recommendations.
func (a *AIAgent) executeAutoResponse(ctx context.Context, alert *Alert, analysis *ThreatAnalysis) error {
	ar := analysis.AutoResponse
	if ar == nil {
		return nil
	}

	// Isolate endpoint (most severe action - requires highest confidence)
	if ar.ShouldIsolate && analysis.Severity >= 8 && analysis.Confidence >= 0.80 {
		if err := a.commander.IsolateEndpoint(ctx, alert.AgentID,
			fmt.Sprintf("AI分析による自動隔離: %s", ar.Reasoning),
			alert.ID, ""); err != nil {
			return fmt.Errorf("isolate endpoint: %w", err)
		}
	}

	// Kill malicious process
	if ar.ShouldKillProcess && ar.KillPID > 0 && analysis.Severity >= 7 {
		if err := a.commander.KillProcess(ctx, alert.AgentID, ar.KillPID,
			fmt.Sprintf("AI分析によるプロセス終了: %s", ar.Reasoning), ""); err != nil {
			return fmt.Errorf("kill process: %w", err)
		}
	}

	// Quarantine suspicious file
	if ar.ShouldQuarantine && ar.QuarantinePath != "" && analysis.Severity >= 6 {
		if err := a.commander.QuarantineFile(ctx, alert.AgentID,
			ar.QuarantinePath, alert.ID, ""); err != nil {
			return fmt.Errorf("quarantine file: %w", err)
		}
	}

	return nil
}

// ─── Prompt Builder ───────────────────────────────────────────

func buildAnalysisPrompt(alert *Alert, events []EventSummary, history []AlertSummary) string {
	var sb strings.Builder

	sb.WriteString("## セキュリティアラート分析依頼\n\n")
	sb.WriteString("### アラート情報\n")
	sb.WriteString(fmt.Sprintf("- **アラートID**: %s\n", alert.ID))
	sb.WriteString(fmt.Sprintf("- **エンドポイント**: %s (%s)\n", alert.Hostname, alert.OS))
	sb.WriteString(fmt.Sprintf("- **検知ルール**: %s\n", alert.RuleName))
	sb.WriteString(fmt.Sprintf("- **初期重大度**: %d/10\n", alert.Severity))
	sb.WriteString(fmt.Sprintf("- **検知時刻**: %s\n", alert.DetectedAt.Format("2006-01-02 15:04:05 JST")))
	sb.WriteString(fmt.Sprintf("- **ローカルML異常スコア**: %.2f\n\n", alert.AnomalyScore))

	sb.WriteString("### トリガーイベント\n```json\n")
	eventJSON, _ := json.MarshalIndent(alert.TriggerEvent, "", "  ")
	sb.Write(eventJSON)
	sb.WriteString("\n```\n\n")

	if len(alert.RelatedEvents) > 0 {
		sb.WriteString("### 関連イベント（前後5分）\n```json\n")
		relatedJSON, _ := json.MarshalIndent(alert.RelatedEvents, "", "  ")
		sb.Write(relatedJSON)
		sb.WriteString("\n```\n\n")
	}

	if len(events) > 0 {
		sb.WriteString("### 最近のエンドポイント活動（直近20件）\n")
		for _, e := range events {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n",
				e.Timestamp.Format("15:04:05"), e.Type, e.Summary))
		}
		sb.WriteString("\n")
	}

	if len(history) > 0 {
		sb.WriteString("### 過去7日間のアラート履歴\n")
		for _, h := range history {
			sb.WriteString(fmt.Sprintf("- [%s] 重大度%d: %s (%s)\n",
				h.CreatedAt.Format("01/02"), h.Severity, h.Title, h.Status))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### 分析依頼\n")
	sb.WriteString("上記のセキュリティアラートを分析し、`submit_analysis`ツールを使用して結果を提出してください。\n")
	sb.WriteString("- 真の脅威か誤検知かを判断してください\n")
	sb.WriteString("- MITRE ATT&CKの攻撃手法を特定してください\n")
	sb.WriteString("- 自動対応（隔離・プロセス終了・ファイル隔離）の要否を判断してください\n")
	sb.WriteString("- セキュリティアナリスト向けの日本語レポートを生成してください\n")

	return sb.String()
}

func extractAnalysisFromText(content []claudeBlock) *ThreatAnalysis {
	var text strings.Builder
	for _, block := range content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	return &ThreatAnalysis{
		IsThreat:       true,
		Severity:       5,
		Confidence:     0.5,
		Summary:        "AI分析完了（テキスト形式）",
		DetailedReport: text.String(),
	}
}

// ─── Alert Type ───────────────────────────────────────────────

type Alert struct {
	ID                  string
	AgentID             string
	Hostname            string
	OS                  string
	RuleName            string
	Severity            int
	DetectedAt          time.Time
	AnomalyScore        float64
	TriggerEvent        interface{}
	RelatedEvents       []interface{}
	AutoResponseEnabled bool
}

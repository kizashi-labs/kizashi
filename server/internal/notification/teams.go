package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TeamsSender sends alert notifications to Microsoft Teams via Incoming Webhook.
// Uses the Adaptive Card format supported by Teams connectors.
type TeamsSender struct {
	webhookURL string
	client     *http.Client
}

func NewTeamsSender(webhookURL string) *TeamsSender {
	return &TeamsSender{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *TeamsSender) Type() string { return ChannelTeams }

func (s *TeamsSender) Send(ctx context.Context, n *AlertNotification) error {
	if s.webhookURL == "" {
		return fmt.Errorf("teams webhook URL が設定されていません")
	}

	color := teamsColor(n.Severity)
	icon := severityIcon(n.Severity)

	// Microsoft Teams MessageCard format
	facts := []teamsFact{
		{Name: "エンドポイント", Value: fmt.Sprintf("%s (%s)", n.Hostname, n.OS)},
		{Name: "重大度", Value: fmt.Sprintf("%s Lv.%d", icon, n.Severity)},
		{Name: "ステータス", Value: statusJP(n.Status)},
		{Name: "検知ルール", Value: n.RuleName},
		{Name: "検知日時", Value: n.CreatedAt.Format("2006/01/02 15:04:05")},
	}

	if n.AIIsThreat != nil {
		verdict := "✅ 誤検知の可能性"
		if *n.AIIsThreat {
			verdict = "🚨 脅威を確認"
		}
		facts = append(facts, teamsFact{Name: "AI判定", Value: verdict})
	}

	summary := n.Summary
	if summary == "" {
		summary = fmt.Sprintf("検知ルール「%s」がエンドポイント「%s」でトリガーされました。", n.RuleName, n.Hostname)
	}

	card := teamsMessageCard{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: color,
		Summary:    n.Title,
		Sections: []teamsSection{
			{
				ActivityTitle:    fmt.Sprintf("%s **%s**", icon, n.Title),
				ActivitySubtitle: summary,
				Facts:            facts,
				Markdown:         true,
			},
		},
		PotentialAction: []teamsAction{
			{
				Type: "OpenUri",
				Name: "ダッシュボードで確認",
				Targets: []teamsTarget{
					{OS: "default", URI: n.DashboardURL},
				},
			},
		},
	}

	body, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("teams メッセージのエンコードに失敗しました: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("teams webhook リクエスト失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams webhook がステータス %d を返しました", resp.StatusCode)
	}
	return nil
}

func teamsColor(severity int) string {
	switch {
	case severity >= 9:
		return "FF0000"
	case severity >= 7:
		return "FF6600"
	case severity >= 5:
		return "FFCC00"
	default:
		return "0099CC"
	}
}

// ─── Teams card types ─────────────────────────────────────────

type teamsMessageCard struct {
	Type            string         `json:"@type"`
	Context         string         `json:"@context"`
	ThemeColor      string         `json:"themeColor"`
	Summary         string         `json:"summary"`
	Sections        []teamsSection `json:"sections"`
	PotentialAction []teamsAction  `json:"potentialAction"`
}

type teamsSection struct {
	ActivityTitle    string      `json:"activityTitle"`
	ActivitySubtitle string      `json:"activitySubtitle"`
	Facts            []teamsFact `json:"facts"`
	Markdown         bool        `json:"markdown"`
}

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type teamsAction struct {
	Type    string        `json:"@type"`
	Name    string        `json:"name"`
	Targets []teamsTarget `json:"targets"`
}

type teamsTarget struct {
	OS  string `json:"os"`
	URI string `json:"uri"`
}

package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SlackSender sends alert notifications to a Slack channel via Incoming Webhook.
type SlackSender struct {
	webhookURL string
	client     *http.Client
}

func NewSlackSender(webhookURL string) *SlackSender {
	return &SlackSender{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackSender) Type() string { return ChannelSlack }

func (s *SlackSender) Send(ctx context.Context, n *AlertNotification) error {
	color := severityColor(n.Severity)
	icon := severityIcon(n.Severity)
	statusLabel := statusJP(n.Status)

	fields := []slackField{
		{Title: "エンドポイント", Value: fmt.Sprintf("%s (%s)", n.Hostname, n.OS), Short: true},
		{Title: "重大度", Value: fmt.Sprintf("%s Lv.%d", icon, n.Severity), Short: true},
		{Title: "ステータス", Value: statusLabel, Short: true},
		{Title: "検知ルール", Value: n.RuleName, Short: true},
	}

	if n.AIIsThreat != nil {
		verdict := "✅ 誤検知の可能性"
		if *n.AIIsThreat {
			verdict = "🚨 脅威を確認"
		}
		fields = append(fields, slackField{Title: "AI判定", Value: verdict, Short: true})
	}

	text := n.Summary
	if text == "" {
		text = fmt.Sprintf("検知ルール *%s* がエンドポイント *%s* でトリガーされました。", n.RuleName, n.Hostname)
	}

	payload := slackPayload{
		Attachments: []slackAttachment{
			{
				Color:      color,
				Title:      fmt.Sprintf("%s %s", icon, n.Title),
				TitleLink:  n.DashboardURL,
				Text:       text,
				Fields:     fields,
				Footer:     "EDR Platform",
				FooterIcon: "https://raw.githubusercontent.com/edr-platform/edr-platform/main/docs/logo.png",
				Timestamp:  n.CreatedAt.Unix(),
				Actions: []slackAction{
					{
						Type:  "button",
						Text:  "詳細を見る",
						URL:   n.DashboardURL,
						Style: "primary",
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack APIリクエスト失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API エラー: status %d", resp.StatusCode)
	}
	return nil
}

// ─── Slack types ──────────────────────────────────────────────

type slackPayload struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color      string        `json:"color"`
	Title      string        `json:"title"`
	TitleLink  string        `json:"title_link"`
	Text       string        `json:"text"`
	Fields     []slackField  `json:"fields"`
	Footer     string        `json:"footer"`
	FooterIcon string        `json:"footer_icon"`
	Timestamp  int64         `json:"ts"`
	Actions    []slackAction `json:"actions"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type slackAction struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	URL   string `json:"url"`
	Style string `json:"style"`
}

func severityColor(severity int) string {
	switch {
	case severity >= 9:
		return "#FF0000" // Red
	case severity >= 7:
		return "#FF6600" // Orange
	case severity >= 5:
		return "#FFCC00" // Yellow
	default:
		return "#0099CC" // Blue
	}
}

func severityIcon(severity int) string {
	switch {
	case severity >= 9:
		return "🔴"
	case severity >= 7:
		return "🟠"
	case severity >= 5:
		return "🟡"
	default:
		return "🔵"
	}
}

func statusJP(status string) string {
	switch status {
	case "open":
		return "未対応"
	case "investigating":
		return "調査中"
	case "resolved":
		return "解決済み"
	case "false_positive":
		return "誤検知"
	default:
		return status
	}
}

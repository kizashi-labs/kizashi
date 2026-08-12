package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
)

// AlertPayload is the data sent to notification channels.
type AlertPayload struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ServerURL string    `json:"server_url"`
}

// Notifier sends alert notifications to configured channels.
type Notifier struct {
	store     *store.AlertNotifStore
	serverURL string
	client    *http.Client
}

// NewNotifier creates a new Notifier backed by the given AlertNotifStore.
func NewNotifier(s *store.AlertNotifStore, serverURL string) *Notifier {
	return &Notifier{
		store:     s,
		serverURL: serverURL,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SendAlert dispatches an alert to all enabled notification channels.
func (n *Notifier) SendAlert(ctx context.Context, payload AlertPayload) {
	channels, err := n.store.ListEnabled(ctx)
	if err != nil {
		slog.Error("通知チャンネル一覧の取得に失敗しました", "error", err)
		return
	}
	payload.ServerURL = n.serverURL
	for _, ch := range channels {
		go n.dispatch(ctx, ch, payload)
	}
}

func (n *Notifier) dispatch(ctx context.Context, ch store.AlertNotifChannel, payload AlertPayload) {
	var cfg map[string]string
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		slog.Error("通知設定のパースに失敗しました", "channel_id", ch.ID, "error", err)
		return
	}
	switch ch.Type {
	case "webhook_slack":
		n.sendSlack(cfg["webhook_url"], payload)
	case "webhook_teams":
		n.sendTeams(cfg["webhook_url"], payload)
	case "webhook_generic":
		n.sendGenericWebhook(cfg["webhook_url"], payload)
	case "email":
		n.sendEmail(cfg, payload)
	default:
		slog.Warn("不明な通知タイプ", "type", ch.Type)
	}
}

func (n *Notifier) sendSlack(webhookURL string, p AlertPayload) {
	color := map[string]string{
		"critical": "#FF0000", "high": "#FF6600", "medium": "#FFCC00", "low": "#0099FF",
	}[p.Severity]
	if color == "" {
		color = "#808080"
	}
	body := map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"color":      color,
			"title":      fmt.Sprintf("[%s] %s", strings.ToUpper(p.Severity), p.Title),
			"text":       fmt.Sprintf("Source: %s | Status: %s", p.Source, p.Status),
			"footer":     "EDR Platform",
			"ts":         p.CreatedAt.Unix(),
			"title_link": fmt.Sprintf("%s/alerts/%s", p.ServerURL, p.ID),
		}},
	}
	n.postJSON(webhookURL, body)
}

func (n *Notifier) sendTeams(webhookURL string, p AlertPayload) {
	body := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    p.Title,
		"themeColor": "FF0000",
		"title":      fmt.Sprintf("EDR アラート: %s", p.Title),
		"sections": []map[string]interface{}{{
			"facts": []map[string]string{
				{"name": "重大度", "value": p.Severity},
				{"name": "ソース", "value": p.Source},
				{"name": "ステータス", "value": p.Status},
			},
		}},
		"potentialAction": []map[string]interface{}{{
			"@type":   "OpenUri",
			"name":    "アラートを確認",
			"targets": []map[string]string{{"os": "default", "uri": fmt.Sprintf("%s/alerts/%s", p.ServerURL, p.ID)}},
		}},
	}
	n.postJSON(webhookURL, body)
}

func (n *Notifier) sendGenericWebhook(webhookURL string, p AlertPayload) {
	n.postJSON(webhookURL, p)
}

func (n *Notifier) postJSON(url string, body interface{}) {
	data, err := json.Marshal(body)
	if err != nil {
		slog.Error("JSONマーシャルに失敗しました", "error", err)
		return
	}
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		slog.Error("Webhook送信に失敗しました", "url", url, "error", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("Webhook送信完了", "url", url, "status", resp.StatusCode)
}

func (n *Notifier) sendEmail(cfg map[string]string, p AlertPayload) {
	host := cfg["smtp_host"]
	port := cfg["smtp_port"]
	if port == "" {
		port = "587"
	}
	from := cfg["from"]
	to := cfg["to"]
	username := cfg["username"]
	password := cfg["password"]

	subject := fmt.Sprintf("[EDR %s] %s", strings.ToUpper(p.Severity), p.Title)
	body := fmt.Sprintf(
		"EDR Platformからのアラート通知\n\n"+
			"タイトル: %s\n重大度: %s\nソース: %s\nステータス: %s\n作成日時: %s\n\n"+
			"詳細: %s/alerts/%s",
		p.Title, p.Severity, p.Source, p.Status, p.CreatedAt.Format(time.RFC3339),
		p.ServerURL, p.ID,
	)
	msg := []byte("To: " + to + "\r\nFrom: " + from + "\r\nSubject: " + subject + "\r\n\r\n" + body)

	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	addr := host + ":" + port
	if err := smtp.SendMail(addr, auth, from, []string{to}, msg); err != nil {
		slog.Error("メール送信に失敗しました", "error", err)
		return
	}
	slog.Info("メール送信完了", "to", to)
}

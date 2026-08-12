package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/edr-platform/server/internal/notify"
	"github.com/edr-platform/server/internal/store"
)

// NotificationHandler handles CRUD and test operations for alert notification channels.
type NotificationHandler struct {
	store    *store.AlertNotifStore
	notifier *notify.Notifier
}

// NewNotificationHandler creates a new NotificationHandler.
func NewNotificationHandler(s *store.AlertNotifStore, notifier *notify.Notifier) *NotificationHandler {
	return &NotificationHandler{store: s, notifier: notifier}
}

var validNotificationTypes = map[string]struct{}{
	"webhook_slack": {}, "webhook_teams": {}, "webhook_generic": {}, "email": {},
}

// List handles GET /api/v1/admin/notifications
func (h *NotificationHandler) List(c *gin.Context) {
	channels, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "通知チャンネル一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"channels": channels})
}

// Create handles POST /api/v1/admin/notifications
func (h *NotificationHandler) Create(c *gin.Context) {
	var req store.CreateAlertNotifChannelInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameは必須です"})
		return
	}
	if _, ok := validNotificationTypes[req.Type]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "typeはwebhook_slack/webhook_teams/webhook_generic/emailのいずれかです"})
		return
	}
	if req.Config == nil {
		req.Config = json.RawMessage("{}")
	}
	ch, err := h.store.Create(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "通知チャンネルの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, ch)
}

// Update handles PUT /api/v1/admin/notifications/:id
func (h *NotificationHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req store.CreateAlertNotifChannelInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Config == nil {
		req.Config = json.RawMessage("{}")
	}
	ch, err := h.store.Update(c.Request.Context(), id, req)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "通知チャンネルが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, ch)
}

// Delete handles DELETE /api/v1/admin/notifications/:id
func (h *NotificationHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "通知チャンネルが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "通知チャンネルを削除しました"})
}

// Test handles POST /api/v1/admin/notifications/:id/test
func (h *NotificationHandler) Test(c *gin.Context) {
	id := c.Param("id")
	ch, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "通知チャンネルが見つかりません"})
		return
	}
	// Send a test alert asynchronously
	go h.notifier.SendAlert(c.Request.Context(), notify.AlertPayload{
		ID:       uuid.New().String(),
		Title:    "テスト通知 - EDR Platform",
		Severity: "low",
		Source:   "test",
		Status:   "open",
	})
	c.JSON(http.StatusOK, gin.H{"message": ch.Name + " にテスト通知を送信しました"})
}

// TestChannel handles POST /api/v1/admin/notifications/:id/test with channel-type-specific dispatch.
// It sends a test notification directly to the configured channel and returns synchronous feedback.
func (h *NotificationHandler) TestChannel(c *gin.Context) {
	id := c.Param("id")
	ch, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "通知チャンネルが見つかりません"})
		return
	}

	var cfg map[string]string
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チャンネル設定のパースに失敗しました"})
		return
	}

	var sendErr error
	switch ch.Type {
	case "email":
		sendErr = testChannelEmail(cfg)
	case "webhook_slack":
		sendErr = testChannelWebhook(cfg["webhook_url"], buildSlackTestPayload())
	case "webhook_teams":
		sendErr = testChannelWebhook(cfg["webhook_url"], buildTeamsTestPayload())
	case "webhook_generic":
		sendErr = testChannelWebhook(cfg["webhook_url"], buildGenericTestPayload())
	case "pagerduty":
		sendErr = testChannelPagerDuty(cfg)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("不明なチャンネルタイプ: %s", ch.Type)})
		return
	}

	if sendErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": sendErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "テスト通知を送信しました",
	})
}

// testChannelEmail sends a test email using the SMTP settings from the channel config.
func testChannelEmail(cfg map[string]string) error {
	host := cfg["smtp_host"]
	port := cfg["smtp_port"]
	if port == "" {
		port = "587"
	}
	// Support both field naming conventions (frontend: from_address/to_address, legacy: from/to)
	from := cfg["from_address"]
	if from == "" {
		from = cfg["from"]
	}
	to := cfg["to_address"]
	if to == "" {
		to = cfg["to"]
	}
	if host == "" || from == "" || to == "" {
		return fmt.Errorf("smtp_host / from_address / to_address の設定が不足しています")
	}

	senderName := cfg["sender_name"]
	if senderName == "" {
		senderName = "EDR Platform"
	}
	subjectPrefix := cfg["subject_prefix"]
	if subjectPrefix == "" {
		subjectPrefix = "[EDR Platform]"
	}

	subject := subjectPrefix + " テスト通知"
	now := time.Now().Format("2006年01月02日 15:04:05")
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:640px;margin:0 auto;padding:20px;color:#333">
  <div style="background:#2980B9;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">✉ テスト通知</h2>
    <p style="margin:4px 0 0;opacity:0.9;font-size:14px">%s</p>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <p style="font-size:14px;line-height:1.6">
      %sからのテスト通知です。<br>
      このメールが届いていれば、メール通知の設定は正常に動作しています。
    </p>
    <table style="width:100%%;border-collapse:collapse;font-size:14px;margin:16px 0">
      <tr><td style="padding:6px;color:#666;width:120px">送信日時</td>
          <td style="padding:6px"><strong>%s</strong></td></tr>
      <tr><td style="padding:6px;color:#666">送信元</td>
          <td style="padding:6px">%s</td></tr>
      <tr><td style="padding:6px;color:#666">送信先</td>
          <td style="padding:6px">%s</td></tr>
    </table>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールは%sから自動送信されています。
  </p>
</body>
</html>`, senderName, senderName, now, from, to, senderName)

	fromHeader := fmt.Sprintf("%s <%s>", senderName, from)
	msg := []byte("To: " + to + "\r\nFrom: " + fromHeader + "\r\nSubject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + body)

	var auth smtp.Auth
	username := cfg["smtp_username"]
	if username == "" {
		username = cfg["username"]
	}
	password := cfg["smtp_password"]
	if password == "" {
		password = cfg["password"]
	}
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	addr := host + ":" + port
	if err := smtp.SendMail(addr, auth, from, []string{to}, msg); err != nil {
		return fmt.Errorf("メール送信に失敗しました: %w", err)
	}
	return nil
}

// testChannelWebhook POSTs a JSON test payload to the given webhook URL.
func testChannelWebhook(webhookURL string, payload interface{}) error {
	if webhookURL == "" {
		return fmt.Errorf("webhook_url が設定されていません")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ペイロードのシリアライズに失敗しました: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("webhook送信に失敗しました: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Webhookが非2xxレスポンスを返しました: %d", resp.StatusCode)
	}
	return nil
}

// testChannelPagerDuty sends a test event to the PagerDuty Events API v2.
func testChannelPagerDuty(cfg map[string]string) error {
	routingKey := cfg["routing_key"]
	if routingKey == "" {
		return fmt.Errorf("routing_key が設定されていません")
	}
	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":   "EDR Platform テスト通知",
			"severity":  "info",
			"source":    "edr-platform",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"custom_details": map[string]string{
				"message": "これはEDR Platformからのテスト通知です。",
			},
		},
		"client":     "EDR Platform",
		"client_url": cfg["server_url"],
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("PagerDutyペイロードのシリアライズに失敗しました: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("https://events.pagerduty.com/v2/enqueue", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("PagerDutyへの送信に失敗しました: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PagerDutyが非2xxレスポンスを返しました: %d", resp.StatusCode)
	}
	return nil
}

// buildSlackTestPayload returns a Slack-compatible test message payload.
func buildSlackTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"color":  "#0099FF",
			"title":  "[LOW] EDR Platform テスト通知",
			"text":   "これはEDR Platformからのテスト通知です。",
			"footer": "EDR Platform",
			"ts":     time.Now().Unix(),
		}},
	}
}

// buildTeamsTestPayload returns a Microsoft Teams MessageCard test payload.
func buildTeamsTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    "EDR Platform テスト通知",
		"themeColor": "0099FF",
		"title":      "EDR Platform テスト通知",
		"sections": []map[string]interface{}{{
			"facts": []map[string]string{
				{"name": "種別", "value": "テスト"},
				{"name": "送信日時", "value": time.Now().Format(time.RFC3339)},
			},
		}},
	}
}

// buildGenericTestPayload returns a generic JSON test payload.
func buildGenericTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"event":     "test",
		"message":   "EDR Platform テスト通知",
		"source":    "edr-platform",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

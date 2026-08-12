package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"time"

	"github.com/edr-platform/server/internal/notification"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ChannelChangePublisher signals the detection engine to reload notification channels.
type ChannelChangePublisher interface {
	Publish(subject string, data []byte) error
}

// SettingsHandler provides system settings and notification channel endpoints.
type SettingsHandler struct {
	Pool       *pgxpool.Pool
	Dispatcher *notification.Dispatcher
	Publisher  ChannelChangePublisher // optional; signals detection engine on channel changes
}

// NewSettingsHandler creates a new SettingsHandler.
func NewSettingsHandler(pool *pgxpool.Pool, dispatcher *notification.Dispatcher) *SettingsHandler {
	return &SettingsHandler{Pool: pool, Dispatcher: dispatcher}
}

func (h *SettingsHandler) publishChannelsUpdated() {
	if h.Publisher != nil {
		if err := h.Publisher.Publish("settings.channels.updated", []byte("{}")); err != nil {
			slog.Warn("NATS publish failed", "subject", "settings.channels.updated", "error", err)
		}
	}
}

// Get returns current system settings.
// GET /api/v1/settings
func (h *SettingsHandler) Get(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.Pool.Query(ctx, "SELECT key, value FROM settings ORDER BY key")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "設定の取得に失敗しました"})
		return
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		settings[key] = value
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, settings)
}

// Update updates system settings.
// PUT /api/v1/settings
func (h *SettingsHandler) Update(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	ctx := c.Request.Context()
	for key, value := range req {
		_, err := h.Pool.Exec(ctx,
			`INSERT INTO settings (key, value) VALUES ($1, $2)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
			key, value,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("設定の更新に失敗しました: %s", key),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "設定を更新しました"})
}

// RegenerateToken generates a new agent enrollment token.
// POST /api/v1/settings/enrollment-token
func (h *SettingsHandler) RegenerateToken(c *gin.Context) {
	newToken := uuid.New().String()
	ctx := c.Request.Context()

	_, err := h.Pool.Exec(ctx,
		`INSERT INTO settings (key, value) VALUES ('enrollment_token', $1)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		newToken,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登録トークンの更新に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enrollment_token": newToken,
		"generated_at":     time.Now(),
	})
}

// notifChannelRow is the JSON representation of a notification channel.
type notifChannelRow struct {
	ID          string            `json:"id"`
	Name        string            `json:"name" binding:"required"`
	Type        string            `json:"type"`
	Config      map[string]string `json:"config"`
	Enabled     bool              `json:"enabled"`
	MinSeverity int               `json:"min_severity"`
}

// ListChannels returns all notification channels.
// GET /api/v1/notifications/channels
func (h *SettingsHandler) ListChannels(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.Pool.Query(ctx,
		`SELECT id, name, type, config, enabled, min_severity
		 FROM notification_channels ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "通知チャンネルの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var channels []*notifChannelRow
	for rows.Next() {
		var ch notifChannelRow
		var configJSON []byte
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &configJSON, &ch.Enabled, &ch.MinSeverity); err != nil {
			continue
		}
		ch.Config = make(map[string]string)
		_ = json.Unmarshal(configJSON, &ch.Config)
		channels = append(channels, &ch)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	if channels == nil {
		channels = []*notifChannelRow{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     channels,
		"total":    len(channels),
		"page":     1,
		"per_page": len(channels),
		"has_more": false,
	})
}

// CreateChannel creates a new notification channel.
// POST /api/v1/notifications/channels
func (h *SettingsHandler) CreateChannel(c *gin.Context) {
	var req notifChannelRow
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if req.Name == "" || req.Type == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名前とタイプが必要です"})
		return
	}

	req.ID = uuid.New().String()
	if req.Config == nil {
		req.Config = make(map[string]string)
	}

	configJSON, _ := json.Marshal(req.Config)
	ctx := c.Request.Context()

	_, err := h.Pool.Exec(ctx,
		`INSERT INTO notification_channels (id, name, type, config, enabled, min_severity)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		req.ID, req.Name, req.Type, configJSON, req.Enabled, req.MinSeverity,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チャンネルの作成に失敗しました"})
		return
	}

	h.publishChannelsUpdated()
	c.JSON(http.StatusCreated, req)
}

// UpdateChannel updates an existing notification channel.
// PUT /api/v1/notifications/channels/:id
func (h *SettingsHandler) UpdateChannel(c *gin.Context) {
	id := c.Param("id")
	var req notifChannelRow
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if req.Config == nil {
		req.Config = make(map[string]string)
	}
	configJSON, _ := json.Marshal(req.Config)
	ctx := c.Request.Context()

	result, err := h.Pool.Exec(ctx,
		`UPDATE notification_channels
		 SET name = $2, type = $3, config = $4, enabled = $5, min_severity = $6
		 WHERE id = $1`,
		id, req.Name, req.Type, configJSON, req.Enabled, req.MinSeverity,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チャンネルの更新に失敗しました"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "チャンネルが見つかりません"})
		return
	}

	req.ID = id
	h.publishChannelsUpdated()
	c.JSON(http.StatusOK, req)
}

// DeleteChannel deletes a notification channel.
// DELETE /api/v1/notifications/channels/:id
func (h *SettingsHandler) DeleteChannel(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	result, err := h.Pool.Exec(ctx, "DELETE FROM notification_channels WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チャンネルの削除に失敗しました"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "チャンネルが見つかりません"})
		return
	}

	h.publishChannelsUpdated()
	c.JSON(http.StatusOK, gin.H{"message": "チャンネルを削除しました", "id": id})
}

// TestChannel sends a test notification through the specified channel.
// It reads the latest config from DB directly (not from the Dispatcher cache)
// so that recent config changes (e.g. port updates) take effect immediately.
// POST /api/v1/notifications/channels/:id/test
func (h *SettingsHandler) TestChannel(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	// Read channel config fresh from DB
	var name, chType string
	var configJSON []byte
	err := h.Pool.QueryRow(ctx,
		`SELECT name, type, config FROM notification_channels WHERE id = $1`, id,
	).Scan(&name, &chType, &configJSON)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "チャンネルが見つかりません"})
		return
	}

	var cfg map[string]string
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "チャンネル設定のパースに失敗しました"})
		return
	}

	var sendErr error
	switch chType {
	case "email":
		sendErr = testEmailDirect(cfg)
	case "webhook_slack":
		sendErr = testWebhookDirect(cfg["webhook_url"], buildSlackTestPayload())
	case "webhook_teams":
		sendErr = testWebhookDirect(cfg["webhook_url"], buildTeamsTestPayload())
	case "webhook_generic":
		sendErr = testWebhookDirect(cfg["webhook_url"], buildGenericTestPayload())
	default:
		// Fallback: try Dispatcher for any other types (e.g. "slack", "teams")
		if err := h.Dispatcher.TestChannel(ctx, id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("テスト通知の送信に失敗しました: %s", err.Error())})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "テスト通知を送信しました", "channel_id": id})
		return
	}

	if sendErr != nil {
		slog.Warn("テスト通知の送信に失敗しました",
			"channel", name, "type", chType, "error", sendErr)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("テスト通知の送信に失敗しました: %s", sendErr.Error())})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "テスト通知を送信しました", "channel_id": id})
}

// testEmailDirect sends a test email using the latest SMTP settings from DB config.
// Supports three connection strategies:
//   - Port 465: implicit TLS (SMTPS) — wraps connection in TLS from the start
//   - Port 587/25: STARTTLS upgrade — if STARTTLS fails (e.g. server only supports
//     DHE cipher suites which Go doesn't implement), falls back to plain text
func testEmailDirect(cfg map[string]string) error {
	host := cfg["smtp_host"]
	port := cfg["smtp_port"]
	if port == "" {
		port = "587"
	}

	from := cfg["from_address"]
	if from == "" {
		from = cfg["from"]
	}
	to := cfg["to_address"]
	if to == "" {
		to = cfg["to"]
	}
	if to == "" {
		to = cfg["recipients"]
	}
	if host == "" || from == "" || to == "" {
		return fmt.Errorf("smtp_host / from_address / to_address の設定が不足しています (host=%q, from=%q, to=%q)", host, from, to)
	}

	senderName := cfg["sender_name"]
	if senderName == "" {
		senderName = "EDR Platform"
	}
	subjectPrefix := cfg["subject_prefix"]
	if subjectPrefix == "" {
		subjectPrefix = "[EDR Platform]"
	}

	subject := cfg["test_subject"]
	if subject == "" {
		subject = subjectPrefix + " テスト通知"
	}

	now := time.Now().Format("2006年01月02日 15:04:05")
	customBody := cfg["test_body"]

	var body string
	if customBody != "" {
		// カスタム本文が設定されている場合、HTMLテンプレートに埋め込む
		body = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:640px;margin:0 auto;padding:20px;color:#333">
  <div style="background:#2980B9;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">✉ %s</h2>
    <p style="margin:4px 0 0;opacity:0.9;font-size:14px">%s</p>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <div style="font-size:14px;line-height:1.6">%s</div>
    <p style="font-size:12px;color:#999;margin-top:16px">送信日時: %s</p>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールは%sから自動送信されています。
  </p>
</body>
</html>`, subject, senderName, customBody, now, senderName)
	} else {
		body = fmt.Sprintf(`<!DOCTYPE html>
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
	}

	fromHeader := fmt.Sprintf("%s <%s>", senderName, from)
	var msg []byte
	msg = append(msg, []byte("To: "+to+"\r\n")...)
	msg = append(msg, []byte("From: "+fromHeader+"\r\n")...)
	msg = append(msg, []byte("Subject: "+subject+"\r\n")...)
	msg = append(msg, []byte("MIME-Version: 1.0\r\n")...)
	msg = append(msg, []byte("Content-Type: text/html; charset=UTF-8\r\n")...)
	msg = append(msg, []byte("\r\n")...)
	msg = append(msg, []byte(body)...)

	username := cfg["smtp_username"]
	if username == "" {
		username = cfg["username"]
	}
	password := cfg["smtp_password"]
	if password == "" {
		password = cfg["password"]
	}

	addr := host + ":" + port

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		// G402: SMTP接続テスト。多様なSMTPサーバの証明書事情に対応するための意図的な設定。
		// 将来的に設定でゲート化する（P1-2b backlog）。
		InsecureSkipVerify: true, //nolint:gosec
	}

	var c *smtp.Client

	if port == "465" {
		// Port 465: implicit TLS (SMTPS) — connect with TLS from the start
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTPS接続に失敗しました: %w", err)
		}
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("SMTPクライアント作成に失敗しました: %w", err)
		}
	} else {
		// Port 587/25: try STARTTLS first, reconnect without if it fails.
		// A failed TLS handshake corrupts the TCP stream, so we must
		// open a brand-new connection when falling back to plain text.
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("SMTP接続に失敗しました: %w", err)
		}
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("SMTPクライアント作成に失敗しました: %w", err)
		}

		if err := c.StartTLS(tlsCfg); err != nil {
			slog.Warn("STARTTLS failed, reconnecting without TLS",
				"host", host, "error", err)
			c.Close()

			// Reconnect fresh — no STARTTLS attempt this time
			conn2, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				return fmt.Errorf("SMTP再接続に失敗しました: %w", err)
			}
			c, err = smtp.NewClient(conn2, host)
			if err != nil {
				conn2.Close()
				return fmt.Errorf("SMTPクライアント再作成に失敗しました: %w", err)
			}
		}
	}
	defer c.Close()

	// Authenticate if credentials are provided.
	// We use a custom Auth that doesn't refuse on non-TLS connections,
	// because some shared-hosting SMTP servers (e.g. sakura internet)
	// only support DHE cipher suites that Go's crypto/tls cannot negotiate.
	if username != "" && password != "" {
		auth := &plainAuthNoTLS{username: username, password: password}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP認証に失敗しました: %w", err)
		}
	}

	// Send the message
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROMに失敗しました: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TOに失敗しました: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATAに失敗しました: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("メール本文の書き込みに失敗しました: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("メール送信の完了に失敗しました: %w", err)
	}
	return c.Quit()
}

// testWebhookDirect POSTs a JSON test payload to the given webhook URL.
func testWebhookDirect(webhookURL string, payload interface{}) error {
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

// plainAuthNoTLS implements smtp.Auth with PLAIN mechanism but without
// the TLS requirement that Go's stdlib smtp.PlainAuth enforces.
// This is needed for SMTP servers that only support DHE cipher suites
// (which Go's crypto/tls does not implement), making STARTTLS impossible.
type plainAuthNoTLS struct {
	username string
	password string
}

func (a *plainAuthNoTLS) Start(server *smtp.ServerInfo) (string, []byte, error) {
	resp := []byte("\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuthNoTLS) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
}

// Note: buildSlackTestPayload, buildTeamsTestPayload, buildGenericTestPayload
// are defined in notification_handler.go and shared across this package.

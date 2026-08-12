package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/nats-io/nats.go"
)

// SMTPConfig holds SMTP connection settings.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// AlertPayload is the minimal shape of an alert published on NATS alerts.>
type AlertPayload struct {
	ID            string    `json:"id"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	AgentID       string    `json:"agent_id"`
	AgentHostname string    `json:"agent_hostname"`
	RuleName      string    `json:"rule_name"`
	CreatedAt     time.Time `json:"created_at"`
}

// EmailNotifier subscribes to NATS alert topics and sends email
// notifications to users whose preferences match the alert severity.
type EmailNotifier struct {
	store *store.NotificationPrefStore
	nc    *nats.Conn
	smtp  SMTPConfig

	// sendMail は実際の SMTP 送信。既定は sendMailSTARTTLS で、テストが
	// 送信内容を検査するためだけに差し替える。STARTTLS ハンドシェイクを
	// 伴う本物の送信は偽サーバを立てないと通せないため、ここを注入点にして
	// 「誰に何を送るか」の組み立てを検証できるようにしてある。
	sendMail func(addr, host, username, password, from, to string, msg []byte) error
}

// NewEmailNotifier reads SMTP config from environment variables and returns
// an EmailNotifier. Variables: SMTP_HOST, SMTP_PORT (default 587),
// SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM.
func NewEmailNotifier(prefStore *store.NotificationPrefStore, nc *nats.Conn) *EmailNotifier {
	port := 587
	if p := os.Getenv("SMTP_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	cfg := SMTPConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
	}
	if cfg.From == "" && cfg.Username != "" {
		cfg.From = cfg.Username
	}
	return &EmailNotifier{
		store:    prefStore,
		nc:       nc,
		smtp:     cfg,
		sendMail: sendMailSTARTTLS,
	}
}

// Start subscribes to NATS and begins processing alerts.
// If SMTP_HOST is not configured, it logs a warning and returns immediately.
// Start blocks until ctx is cancelled.
func (n *EmailNotifier) Start(ctx context.Context) {
	if n.smtp.Host == "" {
		slog.Warn("SMTP_HOSTが設定されていないためメール通知は無効です")
		return
	}
	if n.nc == nil {
		slog.Warn("NATS接続が無いためメール通知は無効です")
		return
	}

	// Subscribe to all alerts
	sub, err := n.nc.Subscribe("alerts.>", func(msg *nats.Msg) {
		var alert AlertPayload
		if err := json.Unmarshal(msg.Data, &alert); err != nil {
			slog.Debug("メール通知: アラートJSONのパースに失敗", "error", err)
			return
		}
		if !isCriticalOrHigh(alert.Severity) {
			return
		}
		go func() {
			sendCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := n.sendAlert(sendCtx, alert); err != nil {
				slog.Warn("アラートメール送信に失敗しました", "alert_id", alert.ID, "error", err)
			}
		}()
	})
	if err != nil {
		slog.Warn("メール通知用NATSサブスクリプション失敗", "error", err)
		return
	}
	defer sub.Unsubscribe()

	slog.Info("メールアラート通知を開始しました", "smtp_host", n.smtp.Host)
	<-ctx.Done()
	slog.Info("メールアラート通知を停止しました")
}

// sendAlert dispatches alert email to all users whose preferences match.
func (n *EmailNotifier) sendAlert(ctx context.Context, alert AlertPayload) error {
	prefs, err := n.store.ListEmailEnabled(ctx, alert.Severity)
	if err != nil {
		return fmt.Errorf("preferences取得失敗: %w", err)
	}
	if len(prefs) == 0 {
		return nil
	}

	subject := fmt.Sprintf("[EDR Platform] %s アラート: %s", severityLabel(alert.Severity), alert.Title)
	body := buildAlertEmailBody(alert)

	var lastErr error
	for _, p := range prefs {
		if err := n.sendEmail(ctx, p.EmailAddress, subject, body); err != nil {
			slog.Warn("メール送信失敗", "to", p.EmailAddress, "error", err)
			lastErr = err
		} else {
			slog.Info("アラートメールを送信しました", "to", p.EmailAddress, "alert_id", alert.ID)
		}
	}
	return lastErr
}

// sendEmail sends a single HTML email via SMTP with STARTTLS.
func (n *EmailNotifier) sendEmail(ctx context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", n.smtp.Host, n.smtp.Port)

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: EDR Platform <%s>\r\n", mailhdr.Sanitize(n.smtp.From)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", mailhdr.Sanitize(to)))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	done := make(chan error, 1)
	go func() {
		done <- n.sendMail(addr, n.smtp.Host, n.smtp.Username, n.smtp.Password,
			n.smtp.From, to, msg.Bytes())
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// sendMailSTARTTLS dials SMTP and upgrades to TLS with STARTTLS before auth.
func sendMailSTARTTLS(addr, host, username, password, from, to string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("SMTP接続失敗: %w", err)
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTPクライアント作成失敗: %w", err)
	}
	defer c.Close()

	// Attempt STARTTLS
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS失敗: %w", err)
		}
	}

	// Authenticate if credentials are set
	if username != "" {
		auth := smtp.PlainAuth("", username, password, host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP認証失敗: %w", err)
		}
	}

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM失敗: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO失敗: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA失敗: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("メッセージ書き込み失敗: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("DATA終了失敗: %w", err)
	}
	return c.Quit()
}

// isCriticalOrHigh returns true for severities that warrant email notification.
func isCriticalOrHigh(severity string) bool {
	return severity == "critical" || severity == "high"
}

// severityLabel returns a display label for the severity.
func severityLabel(severity string) string {
	switch severity {
	case "critical":
		return "緊急"
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	default:
		return severity
	}
}

// buildAlertEmailBody constructs the HTML email body for an alert.
func buildAlertEmailBody(alert AlertPayload) string {
	severityColor := "#dc2626" // red for critical
	if alert.Severity == "high" {
		severityColor = "#ea580c" // orange for high
	}

	hostname := alert.AgentHostname
	if hostname == "" {
		hostname = alert.AgentID
	}
	if hostname == "" {
		hostname = "不明"
	}

	ruleName := alert.RuleName
	if ruleName == "" {
		ruleName = "—"
	}

	createdAt := alert.CreatedAt.Format("2006-01-02 15:04:05 UTC")
	if alert.CreatedAt.IsZero() {
		createdAt = time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#333">
  <div style="background:#1D6FE8;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">EDR Platform — セキュリティアラート</h2>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px">
    <div style="display:inline-block;padding:4px 10px;border-radius:4px;background:%s;
                color:white;font-size:13px;font-weight:bold;margin-bottom:16px">
      %s
    </div>
    <h3 style="margin:0 0 16px">%s</h3>
    <table style="width:100%%;border-collapse:collapse;font-size:14px">
      <tr>
        <td style="padding:6px 0;color:#666;width:140px">エンドポイント</td>
        <td style="padding:6px 0">%s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:#666">検出ルール</td>
        <td style="padding:6px 0">%s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:#666">検出日時</td>
        <td style="padding:6px 0">%s</td>
      </tr>
    </table>
    <p style="margin-top:20px;font-size:13px;color:#666">
      EDR Platformにログインして詳細を確認し、適切な対応を行ってください。
    </p>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールはEDR Platformから自動送信されています。
    通知設定は「プロフィール &gt; 通知設定」から変更できます。
  </p>
</body>
</html>`,
		severityColor,
		severityLabel(alert.Severity),
		alert.Title,
		hostname,
		ruleName,
		createdAt,
	)
}

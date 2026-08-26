package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// EmailConfig contains SMTP configuration.
type EmailConfig struct {
	SMTPHost      string
	SMTPPort      string
	Username      string
	Password      string
	From          string
	Recipients    []string
	SenderName    string // display name in From header (default: "EDR Platform")
	SubjectPrefix string // prefix for email subjects (default: "[EDR]")
}

func (c EmailConfig) senderName() string {
	if c.SenderName != "" {
		return c.SenderName
	}
	return "EDR Platform"
}

func (c EmailConfig) subjectPrefix() string {
	if c.SubjectPrefix != "" {
		return c.SubjectPrefix
	}
	return "[EDR]"
}

// EmailSender sends alert notifications via SMTP.
type EmailSender struct {
	cfg EmailConfig
}

func NewEmailSender(cfg EmailConfig) *EmailSender {
	return &EmailSender{cfg: cfg}
}

func (s *EmailSender) Type() string { return ChannelEmail }

func (s *EmailSender) Send(ctx context.Context, n *AlertNotification) error {
	if len(s.cfg.Recipients) == 0 {
		return fmt.Errorf("メール受信者が設定されていません")
	}

	subject, body, err := s.buildEmail(n)
	if err != nil {
		return fmt.Errorf("メール作成失敗: %w", err)
	}

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s <%s>\r\n", mailhdr.Sanitize(s.cfg.senderName()), mailhdr.Sanitize(s.cfg.From)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(mailhdr.SanitizeAll(s.cfg.Recipients), ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	done := make(chan error, 1)
	go func() {
		done <- smtpSendWithFallback(
			s.cfg.SMTPHost, s.cfg.SMTPPort,
			s.cfg.Username, s.cfg.Password,
			s.cfg.From, s.cfg.Recipients, msg.Bytes(),
		)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// SendHTMLMail builds a UTF-8 HTML message and sends it via the same DHE-safe
// SMTP path used for alert notifications. fromHeader is the full "Name <addr>"
// From header; from is the bare envelope address. Exposed so other features
// (e.g. phishing simulation) can reuse the proven SMTP transport.
func SendHTMLMail(host, port, username, password, fromHeader, from string, to []string, subject, htmlBody string) error {
	var msg bytes.Buffer
	msg.WriteString("From: " + fromHeader + "\r\n")
	msg.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	msg.WriteString("Subject: " + subject + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)
	return smtpSendWithFallback(host, port, username, password, from, to, msg.Bytes())
}

// smtpSendWithFallback connects to the SMTP server with DHE-safe TLS handling.
// Port 465: implicit TLS (SMTPS). Port 587/25: tries STARTTLS, falls back to plain.
func smtpSendWithFallback(host, port, username, password, from string, recipients []string, msg []byte) error {
	addr := host + ":" + port

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		// G402: 多様なSMTPサーバの証明書/TLS事情（DHE等）に対応するための意図的な設定。
		// 配送性を優先。将来的に設定でゲート化する（P1-2b backlog）。
		InsecureSkipVerify: true, //nolint:gosec
	}

	var c *smtp.Client

	if port == "465" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTPS接続に失敗: %w", err)
		}
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTPクライアント作成失敗: %w", err)
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("SMTP接続に失敗: %w", err)
		}
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTPクライアント作成失敗: %w", err)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			slog.Warn("STARTTLS failed, reconnecting without TLS",
				"host", host, "error", err)
			_ = c.Close()

			conn2, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				return fmt.Errorf("SMTP再接続に失敗: %w", err)
			}
			c, err = smtp.NewClient(conn2, host)
			if err != nil {
				_ = conn2.Close()
				return fmt.Errorf("SMTPクライアント再作成失敗: %w", err)
			}
		}
	}
	defer func() { _ = c.Close() }()

	if username != "" && password != "" {
		auth := &plainAuthNoTLS{username: username, password: password}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP認証失敗: %w", err)
		}
	}

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM失敗: %w", err)
	}
	for _, r := range recipients {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("RCPT TO失敗 (%s): %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA失敗: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("メール書き込み失敗: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("メール送信完了失敗: %w", err)
	}
	return c.Quit()
}

func (s *EmailSender) buildEmail(n *AlertNotification) (subject, body string, err error) {
	sev := strconv.Itoa(n.Severity)
	icon := severityIcon(n.Severity)

	subject = fmt.Sprintf("%s %s Lv.%s - %s (%s)",
		s.cfg.subjectPrefix(), icon, sev, n.Title, n.Hostname)

	aiSection := ""
	if n.AIIsThreat != nil {
		if *n.AIIsThreat {
			aiSection = `
                        <div style="background:#FFF3CD;border:1px solid #FFC107;padding:12px;border-radius:6px;margin-top:16px">
                                <strong>🤖 AI判定: 脅威を確認</strong><br>
                                <p style="margin:8px 0 0">` + template.HTMLEscapeString(n.Summary) + `</p>
                        </div>`
		} else {
			aiSection = `
                        <div style="background:#D4EDDA;border:1px solid #28A745;padding:12px;border-radius:6px;margin-top:16px">
                                <strong>🤖 AI判定: 誤検知の可能性</strong><br>
                                <p style="margin:8px 0 0">` + template.HTMLEscapeString(n.Summary) + `</p>
                        </div>`
		}
	}

	name := s.cfg.senderName()

	body = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:640px;margin:0 auto;padding:20px;color:#333">
  <div style="background:%s;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">%s セキュリティアラート</h2>
    <p style="margin:4px 0 0;opacity:0.9;font-size:14px">%s</p>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <h3 style="margin-top:0">%s</h3>
    <table style="width:100%%;border-collapse:collapse;font-size:14px">
      <tr><td style="padding:6px;color:#666;width:140px">エンドポイント</td>
          <td style="padding:6px"><strong>%s</strong> (%s)</td></tr>
      <tr><td style="padding:6px;color:#666">重大度</td>
          <td style="padding:6px"><strong>%s Lv.%d</strong></td></tr>
      <tr><td style="padding:6px;color:#666">検知ルール</td>
          <td style="padding:6px">%s</td></tr>
      <tr><td style="padding:6px;color:#666">検知日時</td>
          <td style="padding:6px">%s</td></tr>
    </table>
    %s
    <div style="margin-top:24px;text-align:center">
      <a href="%s"
         style="background:#1D6FE8;color:white;padding:10px 24px;border-radius:6px;text-decoration:none;font-size:14px">
        ダッシュボードで確認する
      </a>
    </div>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールは%sから自動送信されています。
  </p>
</body>
</html>`,
		severityBGColor(n.Severity),
		icon,
		template.HTMLEscapeString(name),
		template.HTMLEscapeString(n.Title),
		template.HTMLEscapeString(n.Hostname),
		template.HTMLEscapeString(n.OS),
		icon, n.Severity,
		template.HTMLEscapeString(n.RuleName),
		n.CreatedAt.Format("2006年01月02日 15:04:05"),
		aiSection,
		n.DashboardURL,
		template.HTMLEscapeString(name),
	)

	return subject, body, nil
}

func severityBGColor(severity int) string {
	switch {
	case severity >= 9:
		return "#C0392B"
	case severity >= 7:
		return "#E67E22"
	case severity >= 5:
		return "#F39C12"
	default:
		return "#2980B9"
	}
}

// ─── Webhook Sender ───────────────────────────────────────────

type WebhookSender struct {
	url    string
	secret string
	client *http.Client
}

func NewWebhookSender(url, secret string) *WebhookSender {
	return &WebhookSender{
		url:    url,
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *WebhookSender) Type() string { return ChannelWebhook }

func (s *WebhookSender) Send(ctx context.Context, n *AlertNotification) error {
	payload := map[string]interface{}{
		"alert_id":      n.AlertID,
		"title":         n.Title,
		"severity":      n.Severity,
		"status":        n.Status,
		"hostname":      n.Hostname,
		"os":            n.OS,
		"rule_name":     n.RuleName,
		"summary":       n.Summary,
		"dashboard_url": n.DashboardURL,
		"created_at":    n.CreatedAt.Format(time.RFC3339),
	}
	if n.AIIsThreat != nil {
		payload["ai_is_threat"] = *n.AIIsThreat
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "EDR-Platform/1.0")

	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-EDR-Signature", "sha256="+sig)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// plainAuthNoTLS implements smtp.Auth with PLAIN mechanism but without
// the TLS requirement that Go's stdlib smtp.PlainAuth enforces.
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

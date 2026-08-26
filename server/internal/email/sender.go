// Package email provides a centralised SMTP client shared by all handlers
// that need to send transactional emails (invite, password reset, verification,
// alert digests, etc.).
//
// Configuration is read from environment variables:
//
//	SMTP_HOST        SMTP server hostname (e.g. smtp.sendgrid.net)
//	SMTP_PORT        Port (default: 587)
//	SMTP_USERNAME    SMTP login username
//	SMTP_PASSWORD    SMTP login password
//	SMTP_FROM        Sender address (fallback: SMTP_USERNAME)
//	EDR_BASE_URL     Used to build links inside email bodies
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"html/template"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// Sender is a thread-safe SMTP client with STARTTLS support.
type Sender struct {
	host    string
	port    int
	user    string
	pass    string
	from    string
	baseURL string
}

// NewSenderFromEnv reads SMTP configuration from environment variables and
// returns a Sender. Returns nil (not an error) when SMTP_HOST is unset so
// callers can treat email as optional.
func NewSenderFromEnv() *Sender {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return nil
	}
	port := 587
	if p, err := strconv.Atoi(os.Getenv("SMTP_PORT")); err == nil && p > 0 {
		port = p
	}
	from := os.Getenv("SMTP_FROM")
	user := os.Getenv("SMTP_USERNAME")
	if from == "" {
		from = user
	}
	return &Sender{
		host:    host,
		port:    port,
		user:    user,
		pass:    os.Getenv("SMTP_PASSWORD"),
		from:    from,
		baseURL: os.Getenv("EDR_BASE_URL"),
	}
}

// BaseURL returns the configured service base URL (used in email link hrefs).
func (s *Sender) BaseURL() string { return s.baseURL }

// Send sends a single HTML email. If the Sender is nil (SMTP not configured)
// it logs a debug message and returns nil so callers degrade gracefully.
func (s *Sender) Send(ctx context.Context, to, subject, htmlBody string) error {
	if s == nil {
		slog.Debug("email: SMTP未設定のため送信をスキップします", "to", to, "subject", subject)
		return nil
	}

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: Kizashi <%s>\r\n", mailhdr.Sanitize(s.from)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", mailhdr.Sanitize(to)))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	done := make(chan error, 1)
	go func() {
		done <- s.dialAndSend(s.from, to, msg.Bytes())
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// dialAndSend opens an SMTP connection, upgrades to STARTTLS, authenticates,
// and delivers the message.
func (s *Sender) dialAndSend(from, to string, msg []byte) error {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}

	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	// Attempt STARTTLS upgrade
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	// Auth (optional — some internal/dev servers skip it)
	if s.user != "" {
		auth := smtp.PlainAuth("", s.user, s.pass, s.host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return w.Close()
}

// ─── Template helpers ─────────────────────────────────────────────────────────

// SendInvitation sends a user-invitation email.
func (s *Sender) SendInvitation(ctx context.Context, toEmail, inviteURL string) error {
	body, err := renderTemplate(inviteTmpl, map[string]string{
		"Email":     toEmail,
		"InviteURL": inviteURL,
	})
	if err != nil {
		return err
	}
	return s.Send(ctx, toEmail, "[Kizashi] ユーザー招待", body)
}

// SendPasswordReset sends a password-reset email.
func (s *Sender) SendPasswordReset(ctx context.Context, toEmail, displayName, resetURL string) error {
	body, err := renderTemplate(passwordResetTmpl, map[string]string{
		"Name":     displayName,
		"ResetURL": resetURL,
	})
	if err != nil {
		return err
	}
	return s.Send(ctx, toEmail, "[Kizashi] パスワードリセット", body)
}

// SendEmailVerification sends an email-address verification email.
func (s *Sender) SendEmailVerification(ctx context.Context, toEmail, verifyURL string) error {
	body, err := renderTemplate(verifyTmpl, map[string]string{
		"Email":     toEmail,
		"VerifyURL": verifyURL,
	})
	if err != nil {
		return err
	}
	return s.Send(ctx, toEmail, "[Kizashi] メールアドレスの確認", body)
}

// ─── HTML templates ───────────────────────────────────────────────────────────

// renderTemplate renders one of the built-in HTML templates.
//
// 以前は解析に失敗すると "" を返し、Execute の失敗も捨てていました。
// 呼び出し側はそれをそのまま Send に渡すので、本文が空のメールが
// 送られます。パスワード再設定の案内が白紙で届く、という形です。
func renderTemplate(tmplStr string, data map[string]string) (string, error) {
	t, err := template.New("").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("メール本文のテンプレートを解析できませんでした: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("メール本文を組み立てられませんでした: %w", err)
	}
	if buf.Len() == 0 {
		return "", fmt.Errorf("メール本文が空です")
	}
	return buf.String(), nil
}

const emailBase = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#f5f7fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:#f5f7fa;padding:40px 20px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%%">
  <!-- Header -->
  <tr>
    <td style="background:#0a0f1e;padding:20px 28px;border-radius:10px 10px 0 0">
      <table cellpadding="0" cellspacing="0">
        <tr>
          <td style="background:#e8002d;width:28px;height:28px;border-radius:6px;text-align:center;vertical-align:middle">
            <span style="color:white;font-size:16px;font-weight:bold">V</span>
          </td>
          <td style="padding-left:10px;color:#e2e8f4;font-size:15px;font-weight:600">Kizashi</td>
        </tr>
      </table>
    </td>
  </tr>
  <!-- Body -->
  <tr>
    <td style="background:#ffffff;padding:32px 28px;border:1px solid #e2e8f0;border-top:none">
      {{CONTENT}}
    </td>
  </tr>
  <!-- Footer -->
  <tr>
    <td style="padding:16px 28px;text-align:center;font-size:12px;color:#94a3b8;border-radius:0 0 10px 10px">
      このメールはKizashiから自動送信されています。心当たりがない場合は無視してください。
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>`

func wrapBase(content string) string {
	return strings.ReplaceAll(emailBase, "{{CONTENT}}", content)
}

var inviteTmpl = wrapBase(`
<h2 style="margin:0 0 16px;font-size:22px;color:#0f172a">ご招待が届いています</h2>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 12px">
  <strong>{{.Email}}</strong> 様、Kizashi へご招待しました。
</p>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 28px">
  以下のボタンからアカウントを設定してください。リンクは <strong>7日間</strong> 有効です。
</p>
<div style="text-align:center;margin-bottom:28px">
  <a href="{{.InviteURL}}"
     style="display:inline-block;padding:13px 28px;background:#e8002d;color:white;
            text-decoration:none;border-radius:8px;font-weight:600;font-size:15px">
    アカウントを設定する
  </a>
</div>
<p style="color:#94a3b8;font-size:13px;margin:0">
  ボタンが機能しない場合は以下のURLをブラウザに貼り付けてください：<br>
  <a href="{{.InviteURL}}" style="color:#3b82f6;word-break:break-all">{{.InviteURL}}</a>
</p>`)

var passwordResetTmpl = wrapBase(`
<h2 style="margin:0 0 16px;font-size:22px;color:#0f172a">パスワードのリセット</h2>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 12px">
  {{.Name}} 様、パスワードリセットのリクエストを受け付けました。
</p>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 28px">
  以下のボタンから新しいパスワードを設定してください。リンクは <strong>1時間</strong> 有効です。
</p>
<div style="text-align:center;margin-bottom:28px">
  <a href="{{.ResetURL}}"
     style="display:inline-block;padding:13px 28px;background:#e8002d;color:white;
            text-decoration:none;border-radius:8px;font-weight:600;font-size:15px">
    パスワードを再設定する
  </a>
</div>
<div style="background:#fef3c7;border:1px solid #fbbf24;border-radius:6px;padding:12px 16px;margin-bottom:20px">
  <p style="margin:0;font-size:13px;color:#92400e">
    ⚠ このリクエストを行っていない場合は、このメールを無視してください。パスワードは変更されません。
  </p>
</div>
<p style="color:#94a3b8;font-size:13px;margin:0">
  ボタンが機能しない場合：<br>
  <a href="{{.ResetURL}}" style="color:#3b82f6;word-break:break-all">{{.ResetURL}}</a>
</p>`)

var verifyTmpl = wrapBase(`
<h2 style="margin:0 0 16px;font-size:22px;color:#0f172a">メールアドレスの確認</h2>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 12px">
  <strong>{{.Email}}</strong> のメールアドレスを確認してください。
</p>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 28px">
  以下のボタンをクリックしてメールアドレスを確認します。リンクは <strong>24時間</strong> 有効です。
</p>
<div style="text-align:center;margin-bottom:28px">
  <a href="{{.VerifyURL}}"
     style="display:inline-block;padding:13px 28px;background:#e8002d;color:white;
            text-decoration:none;border-radius:8px;font-weight:600;font-size:15px">
    メールアドレスを確認する
  </a>
</div>
<p style="color:#94a3b8;font-size:13px;margin:0">
  ボタンが機能しない場合：<br>
  <a href="{{.VerifyURL}}" style="color:#3b82f6;word-break:break-all">{{.VerifyURL}}</a>
</p>`)

// ─── Dynamic template helper ──────────────────────────────────────────────────

// renderTemplateDynamic is like renderTemplate but accepts any data value,
// allowing structs, map[string]interface{}, etc.
func renderTemplateDynamic(tmplStr string, data interface{}) (string, error) {
	t, err := template.New("").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("メール本文のテンプレートを解析できませんでした: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("メール本文を組み立てられませんでした: %w", err)
	}
	if buf.Len() == 0 {
		return "", fmt.Errorf("メール本文が空です")
	}
	return buf.String(), nil
}

// ─── SendAlertNotification ────────────────────────────────────────────────────

// SendAlertNotification sends a security-alert notification email.
func (s *Sender) SendAlertNotification(ctx context.Context, toEmail, alertTitle, hostname, ruleName, alertURL string, severity int) error {
	severityColor := "#2563eb"
	severityLabel := "LOW"
	switch {
	case severity >= 9:
		severityColor = "#dc2626"
		severityLabel = "CRITICAL"
	case severity >= 7:
		severityColor = "#ea580c"
		severityLabel = "HIGH"
	case severity >= 5:
		severityColor = "#d97706"
		severityLabel = "MEDIUM"
	}

	body, err := renderTemplateDynamic(alertNotifTmpl, map[string]interface{}{
		"Title":         alertTitle,
		"Hostname":      hostname,
		"RuleName":      ruleName,
		"AlertURL":      alertURL,
		"Severity":      severity,
		"SeverityColor": severityColor,
		"SeverityLabel": severityLabel,
	})
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[Kizashi] 🚨 セキュリティアラート — %s", alertTitle)
	return s.Send(ctx, toEmail, subject, body)
}

// ─── SendWeeklyDigest ─────────────────────────────────────────────────────────

// SendWeeklyDigest sends a weekly security digest email.
func (s *Sender) SendWeeklyDigest(ctx context.Context, toEmail string, totalAlerts, criticalCount, highCount, resolvedCount int, periodStart, periodEnd string) error {
	period := fmt.Sprintf("%s 〜 %s", periodStart, periodEnd)
	body, err := renderTemplateDynamic(weeklyDigestTmpl, map[string]interface{}{
		"TotalAlerts":   totalAlerts,
		"CriticalCount": criticalCount,
		"HighCount":     highCount,
		"ResolvedCount": resolvedCount,
		"PeriodStart":   periodStart,
		"PeriodEnd":     periodEnd,
	})
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[Kizashi] 週次セキュリティダイジェスト — %s", period)
	return s.Send(ctx, toEmail, subject, body)
}

// ─── SendOnboardingWelcome ────────────────────────────────────────────────────

// SendOnboardingWelcome sends a welcome / quick-start guide email to a new user.
func (s *Sender) SendOnboardingWelcome(ctx context.Context, toEmail, displayName, loginURL string) error {
	body, err := renderTemplateDynamic(onboardingTmpl, map[string]interface{}{
		"Name":     displayName,
		"LoginURL": loginURL,
	})
	if err != nil {
		return err
	}
	return s.Send(ctx, toEmail, "[Kizashi] ようこそ！セットアップガイド", body)
}

// ─── HTML templates (alert / digest / onboarding) ────────────────────────────

var alertNotifTmpl = wrapBase(`
<div style="background:#dc2626;border-radius:8px 8px 0 0;padding:16px 20px;margin:-0px 0 20px">
  <table cellpadding="0" cellspacing="0" width="100%%">
    <tr>
      <td style="color:white;font-size:22px;vertical-align:middle;width:36px">🚨</td>
      <td style="padding-left:10px">
        <p style="margin:0;color:white;font-size:17px;font-weight:700">セキュリティアラート</p>
        <p style="margin:2px 0 0;color:#fecaca;font-size:13px">Kizashi が脅威を検出しました</p>
      </td>
      <td align="right">
        <span style="display:inline-block;padding:4px 12px;background:{{.SeverityColor}};color:white;
                     border-radius:20px;font-size:12px;font-weight:700;letter-spacing:0.5px">
          {{.SeverityLabel}}
        </span>
      </td>
    </tr>
  </table>
</div>
<h2 style="margin:0 0 16px;font-size:20px;color:#0f172a">{{.Title}}</h2>
<table cellpadding="0" cellspacing="0" width="100%%" style="border:1px solid #e2e8f0;border-radius:6px;margin-bottom:24px">
  <tr style="background:#f8fafc">
    <td style="padding:10px 14px;font-size:13px;font-weight:600;color:#64748b;width:38%%">エンドポイント</td>
    <td style="padding:10px 14px;font-size:14px;color:#0f172a;font-weight:500">{{.Hostname}}</td>
  </tr>
  <tr>
    <td style="padding:10px 14px;font-size:13px;font-weight:600;color:#64748b;border-top:1px solid #e2e8f0">検出ルール</td>
    <td style="padding:10px 14px;font-size:14px;color:#0f172a;border-top:1px solid #e2e8f0">{{.RuleName}}</td>
  </tr>
  <tr style="background:#f8fafc">
    <td style="padding:10px 14px;font-size:13px;font-weight:600;color:#64748b;border-top:1px solid #e2e8f0">重大度スコア</td>
    <td style="padding:10px 14px;font-size:14px;font-weight:700;border-top:1px solid #e2e8f0">
      <span style="color:{{.SeverityColor}}">{{.Severity}} / 10</span>
    </td>
  </tr>
</table>
<div style="text-align:center;margin-bottom:28px">
  <a href="{{.AlertURL}}"
     style="display:inline-block;padding:13px 28px;background:#e8002d;color:white;
            text-decoration:none;border-radius:8px;font-weight:600;font-size:15px">
    アラートを確認する
  </a>
</div>
<p style="color:#94a3b8;font-size:13px;margin:0">
  ボタンが機能しない場合：<br>
  <a href="{{.AlertURL}}" style="color:#3b82f6;word-break:break-all">{{.AlertURL}}</a>
</p>`)

var weeklyDigestTmpl = wrapBase(`
<h2 style="margin:0 0 6px;font-size:22px;color:#0f172a">週次セキュリティダイジェスト</h2>
<p style="color:#64748b;font-size:14px;margin:0 0 24px">集計期間：{{.PeriodStart}} 〜 {{.PeriodEnd}}</p>
<table cellpadding="0" cellspacing="0" width="100%%" style="margin-bottom:28px">
  <tr>
    <td style="padding:0 6px 0 0;width:25%%">
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 10px;text-align:center">
        <p style="margin:0;font-size:26px;font-weight:700;color:#0f172a">{{.TotalAlerts}}</p>
        <p style="margin:4px 0 0;font-size:11px;color:#64748b;font-weight:500">総アラート数</p>
      </div>
    </td>
    <td style="padding:0 6px;width:25%%">
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px 10px;text-align:center">
        <p style="margin:0;font-size:26px;font-weight:700;color:#dc2626">{{.CriticalCount}}</p>
        <p style="margin:4px 0 0;font-size:11px;color:#ef4444;font-weight:500">CRITICAL</p>
      </div>
    </td>
    <td style="padding:0 6px;width:25%%">
      <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:14px 10px;text-align:center">
        <p style="margin:0;font-size:26px;font-weight:700;color:#ea580c">{{.HighCount}}</p>
        <p style="margin:4px 0 0;font-size:11px;color:#f97316;font-weight:500">HIGH</p>
      </div>
    </td>
    <td style="padding:0 0 0 6px;width:25%%">
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px 10px;text-align:center">
        <p style="margin:0;font-size:26px;font-weight:700;color:#16a34a">{{.ResolvedCount}}</p>
        <p style="margin:4px 0 0;font-size:11px;color:#22c55e;font-weight:500">解決済み</p>
      </div>
    </td>
  </tr>
</table>
<div style="text-align:center;margin-bottom:28px">
  <a href="#dashboard"
     style="display:inline-block;padding:13px 28px;background:#e8002d;color:white;
            text-decoration:none;border-radius:8px;font-weight:600;font-size:15px">
    ダッシュボードで確認する
  </a>
</div>
<p style="color:#94a3b8;font-size:13px;margin:0;text-align:center">
  このダイジェストは毎週月曜日に自動送信されます。
</p>`)

var onboardingTmpl = wrapBase(`
<h2 style="margin:0 0 8px;font-size:22px;color:#0f172a">ようこそ、{{.Name}} さん！</h2>
<p style="color:#475569;font-size:15px;line-height:1.6;margin:0 0 24px">
  Kizashi へのご参加ありがとうございます。以下の手順で簡単に始められます。
</p>
<!-- Step 1 -->
<table cellpadding="0" cellspacing="0" width="100%%" style="margin-bottom:14px">
  <tr>
    <td style="vertical-align:top;width:36px">
      <div style="background:#e8002d;width:28px;height:28px;border-radius:50%%;text-align:center;
                  line-height:28px;color:white;font-size:13px;font-weight:700">1</div>
    </td>
    <td style="padding-left:12px;vertical-align:top">
      <p style="margin:0 0 2px;font-size:15px;font-weight:600;color:#0f172a">エージェントのインストール</p>
      <p style="margin:0;font-size:14px;color:#64748b;line-height:1.5">
        監視対象ホストに Kizashi エージェントをインストールして、テレメトリの収集を開始します。
      </p>
    </td>
  </tr>
</table>
<!-- Step 2 -->
<table cellpadding="0" cellspacing="0" width="100%%" style="margin-bottom:14px">
  <tr>
    <td style="vertical-align:top;width:36px">
      <div style="background:#e8002d;width:28px;height:28px;border-radius:50%%;text-align:center;
                  line-height:28px;color:white;font-size:13px;font-weight:700">2</div>
    </td>
    <td style="padding-left:12px;vertical-align:top">
      <p style="margin:0 0 2px;font-size:15px;font-weight:600;color:#0f172a">最初のアラートの確認</p>
      <p style="margin:0;font-size:14px;color:#64748b;line-height:1.5">
        ダッシュボードでリアルタイムのアラートを確認し、脅威の詳細を調査します。
      </p>
    </td>
  </tr>
</table>
<!-- Step 3 -->
<table cellpadding="0" cellspacing="0" width="100%%" style="margin-bottom:28px">
  <tr>
    <td style="vertical-align:top;width:36px">
      <div style="background:#e8002d;width:28px;height:28px;border-radius:50%%;text-align:center;
                  line-height:28px;color:white;font-size:13px;font-weight:700">3</div>
    </td>
    <td style="padding-left:12px;vertical-align:top">
      <p style="margin:0 0 2px;font-size:15px;font-weight:600;color:#0f172a">ルールの設定</p>
      <p style="margin:0;font-size:14px;color:#64748b;line-height:1.5">
        検出ルールをカスタマイズして、組織の環境に合わせたアラートポリシーを構築します。
      </p>
    </td>
  </tr>
</table>
<div style="text-align:center;margin-bottom:28px">
  <a href="{{.LoginURL}}"
     style="display:inline-block;padding:13px 28px;background:#e8002d;color:white;
            text-decoration:none;border-radius:8px;font-weight:600;font-size:15px">
    ダッシュボードにログインする
  </a>
</div>
<p style="color:#94a3b8;font-size:13px;margin:0">
  ボタンが機能しない場合：<br>
  <a href="{{.LoginURL}}" style="color:#3b82f6;word-break:break-all">{{.LoginURL}}</a>
</p>`)

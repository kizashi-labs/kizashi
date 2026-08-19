package scheduler

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jackc/pgx/v5"
)

// notifyThresholds are the days-before-expiry milestones at which emails are sent.
var notifyThresholds = []int{30, 14, 7, 1}

// LicenseExpiryNotifier checks the license expiry daily and sends email
// notifications to admin users at 30, 14, 7, and 1 days before expiry.
type LicenseExpiryNotifier struct {
	pool *pgxpool.Pool
}

// NewLicenseExpiryNotifier creates a new notifier.
func NewLicenseExpiryNotifier(pool *pgxpool.Pool) *LicenseExpiryNotifier {
	return &LicenseExpiryNotifier{pool: pool}
}

// Run starts the notifier. First check after 2 minutes, then every 24 hours.
// Designed to be called as a goroutine.
func (n *LicenseExpiryNotifier) Run(ctx context.Context) {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	slog.Info("ライセンス期限切れ通知スケジューラーを起動しました")

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			trackRun(ctx, "license_expiry_notifier", n.check)
		case <-ticker.C:
			trackRun(ctx, "license_expiry_notifier", n.check)
		}
	}
}

func (n *LicenseExpiryNotifier) check(ctx context.Context) {
	var expiresAt time.Time
	var orgName, plan string
	err := n.pool.QueryRow(ctx,
		`SELECT organization_name, plan, expires_at FROM license_info WHERE id = 1`,
	).Scan(&orgName, &plan, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return // ライセンス行がまだ無いだけ。失敗ではありません。
		}
		fail(ctx, err, "ライセンス期限チェック: license_info 読み込み失敗")
		return
	}

	daysLeft := int(time.Until(expiresAt).Hours() / 24)

	for _, threshold := range notifyThresholds {
		if daysLeft == threshold || (threshold == 1 && daysLeft <= 0 && daysLeft > -1) {
			n.sendNotification(ctx, orgName, plan, expiresAt, daysLeft)
			return
		}
	}
}

func (n *LicenseExpiryNotifier) sendNotification(
	ctx context.Context,
	orgName, plan string,
	expiresAt time.Time,
	daysLeft int,
) {
	smtpHost := os.Getenv("SMTP_HOST")

	// Always create an in-app alert.
	n.createAlert(ctx, orgName, plan, expiresAt, daysLeft)

	if smtpHost == "" {
		slog.Info("ライセンス期限通知: SMTP_HOST 未設定のためメール送信をスキップ", "days_left", daysLeft)
		return
	}

	recipients, err := adminRecipients(ctx, n.pool)
	if err != nil {
		fail(ctx, err, "ライセンス期限通知: 管理者メール取得失敗")
		return
	}

	if len(recipients) == 0 {
		slog.Info("ライセンス期限通知: 管理者メールアドレスが見つかりません")
		return
	}

	subject, body := buildLicenseExpiryEmail(orgName, plan, expiresAt, daysLeft)
	for _, to := range recipients {
		if err := sendLicenseSMTP(smtpHost, to, subject, body); err != nil {
			fail(ctx, err, "ライセンス期限通知メール送信失敗", "to", to)
		} else {
			slog.Info("ライセンス期限通知メールを送信しました", "to", to, "days_left", daysLeft)
		}
	}
}

func (n *LicenseExpiryNotifier) createAlert(
	ctx context.Context,
	orgName, plan string,
	expiresAt time.Time,
	daysLeft int,
) {
	var existing int
	_ = n.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE title LIKE '%ライセンス%期限%'
		   AND created_at > NOW() - INTERVAL '23 hours'`,
	).Scan(&existing)
	if existing > 0 {
		return
	}

	var title, description string
	var severity int

	switch {
	case daysLeft <= 0:
		title = fmt.Sprintf("ライセンス期限切れ: %s", orgName)
		description = fmt.Sprintf(
			"組織 %s の %s プランライセンスが期限切れです（期限: %s）。管理者に連絡してライセンスを更新してください。",
			orgName, plan, expiresAt.Format("2006-01-02"),
		)
		severity = 9
	case daysLeft <= 7:
		title = fmt.Sprintf("ライセンス期限まで残り%d日: %s", daysLeft, orgName)
		description = fmt.Sprintf(
			"組織 %s の %s プランライセンスは %s に期限切れになります（残り %d 日）。早急にライセンスを更新してください。",
			orgName, plan, expiresAt.Format("2006-01-02"), daysLeft,
		)
		severity = 7
	case daysLeft <= 14:
		title = fmt.Sprintf("ライセンス期限まで残り%d日: %s", daysLeft, orgName)
		description = fmt.Sprintf(
			"組織 %s の %s プランライセンスは %s に期限切れになります（残り %d 日）。",
			orgName, plan, expiresAt.Format("2006-01-02"), daysLeft,
		)
		severity = 5
	default:
		title = fmt.Sprintf("ライセンス期限まで残り%d日: %s", daysLeft, orgName)
		description = fmt.Sprintf(
			"組織 %s の %s プランライセンスは %s に期限切れになります（残り %d 日）。",
			orgName, plan, expiresAt.Format("2006-01-02"), daysLeft,
		)
		severity = 3
	}

	var alertID string
	err := n.pool.QueryRow(ctx,
		`INSERT INTO alerts (title, description, severity, status)
		 VALUES ($1, $2, $3, 'open')
		 RETURNING id::text`,
		title, description, severity,
	).Scan(&alertID)
	if err != nil {
		fail(ctx, err, "ライセンス期限アラート作成失敗")
		return
	}
	slog.Info("ライセンス期限アラートを作成しました", "alert_id", alertID, "days_left", daysLeft)
}

func buildLicenseExpiryEmail(orgName, plan string, expiresAt time.Time, daysLeft int) (subject, body string) {
	var urgencyColor, urgencyLabel string
	switch {
	case daysLeft <= 0:
		urgencyColor = "#dc2626"
		urgencyLabel = "期限切れ"
		subject = "[EDR Platform] ライセンスが期限切れです — 今すぐ更新してください"
	case daysLeft <= 7:
		urgencyColor = "#ea580c"
		urgencyLabel = fmt.Sprintf("残り %d 日", daysLeft)
		subject = fmt.Sprintf("[EDR Platform] ライセンス期限まで残り %d 日 — 至急更新が必要です", daysLeft)
	default:
		urgencyColor = "#d97706"
		urgencyLabel = fmt.Sprintf("残り %d 日", daysLeft)
		subject = fmt.Sprintf("[EDR Platform] ライセンス期限まで残り %d 日のお知らせ", daysLeft)
	}

	var msgBody string
	if daysLeft <= 0 {
		msgBody = "ライセンスが期限切れのため、一部の機能が制限される場合があります。早急にライセンスを更新してください。"
	} else {
		msgBody = fmt.Sprintf(
			"ライセンスは <strong>%s</strong> に期限切れになります。"+
				"引き続きすべての機能を利用するために、期限前にライセンスを更新してください。",
			expiresAt.Format("2006年01月02日"),
		)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#333">
  <div style="background:#1D6FE8;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">EDR Platform — ライセンス通知</h2>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px">
    <div style="display:inline-block;padding:4px 12px;border-radius:4px;background:%s;
                color:white;font-size:13px;font-weight:bold;margin-bottom:16px">%s</div>
    <h3 style="margin:0 0 12px">ライセンス有効期限のお知らせ</h3>
    <table style="width:100%%;border-collapse:collapse;font-size:14px;margin-bottom:16px">
      <tr>
        <td style="padding:6px 0;color:#666;width:140px">組織名</td>
        <td style="padding:6px 0;font-weight:bold">%s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:#666">プラン</td>
        <td style="padding:6px 0">%s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:#666">有効期限</td>
        <td style="padding:6px 0;font-weight:bold;color:%s">%s</td>
      </tr>
    </table>
    <p style="font-size:14px;color:#444;line-height:1.6">%s</p>
    <p style="margin-top:20px;font-size:13px;color:#666">
      ライセンスの更新については、サポートチームまでお問い合わせください。
    </p>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールはEDR Platformから自動送信されています。
  </p>
</body>
</html>`,
		urgencyColor, urgencyLabel,
		orgName, plan,
		urgencyColor, expiresAt.Format("2006年01月02日"),
		msgBody,
	)

	return subject, buf.String()
}

// sendLicenseSMTP sends an HTML email using SMTP settings from environment variables.
func sendLicenseSMTP(smtpHost, to, subject, htmlBody string) error {
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = username
	}
	if from == "" {
		from = "noreply@edr-platform"
	}
	addr := smtpHost + ":" + port

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: EDR Platform <%s>\r\n", mailhdr.Sanitize(from)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", mailhdr.Sanitize(to)))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("SMTP接続失敗: %w", err)
	}
	c, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("SMTPクライアント作成失敗: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: smtpHost}); err != nil {
			return fmt.Errorf("STARTTLS失敗: %w", err)
		}
	}
	if username != "" {
		if err := c.Auth(smtp.PlainAuth("", username, password, smtpHost)); err != nil {
			return fmt.Errorf("SMTP認証失敗: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

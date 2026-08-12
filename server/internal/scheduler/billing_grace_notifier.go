package scheduler

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// graceNotifyThresholds are the days-before-grace-end milestones at which
// notification emails are sent. The zero value doubles as the "grace expired
// today" notification.
var graceNotifyThresholds = []int{7, 3, 1, 0}

// defaultBillingGracePeriodDays mirrors billing.defaultGracePeriodDays.
// Kept here to avoid creating an import cycle between scheduler and billing.
const defaultBillingGracePeriodDays = 30

// BillingGraceNotifier scans canceled subscriptions daily and emails the
// admin group when the grace window is approaching its end.
//
// Three signals are emitted per subscription:
//   - 7 days remaining  (info)
//   - 3 days remaining  (warning)
//   - 1 day remaining   (warning)
//   - 0 days remaining  (critical — Free downgrade imminent / already applied)
type BillingGraceNotifier struct {
	pool *pgxpool.Pool
	tick time.Duration
}

// NewBillingGraceNotifier returns a notifier with the default 24h tick.
func NewBillingGraceNotifier(pool *pgxpool.Pool) *BillingGraceNotifier {
	return &BillingGraceNotifier{pool: pool, tick: 24 * time.Hour}
}

// Run starts the notifier. First check after 3 minutes (offset from
// LicenseExpiryNotifier so the two don't hit the DB simultaneously on boot),
// then every tick.
func (n *BillingGraceNotifier) Run(ctx context.Context) {
	startupDelay := time.NewTimer(3 * time.Minute)
	defer startupDelay.Stop()
	ticker := time.NewTicker(n.tick)
	defer ticker.Stop()

	slog.Info("billing grace notifier started", "tick", n.tick)

	for {
		select {
		case <-ctx.Done():
			return
		case <-startupDelay.C:
			n.check(ctx)
		case <-ticker.C:
			n.check(ctx)
		}
	}
}

func (n *BillingGraceNotifier) check(ctx context.Context) {
	gracePeriodDays := billingGracePeriodDays()

	rows, err := n.pool.Query(ctx,
		`SELECT s.id, s.stripe_subscription_id, s.canceled_at, s.plan, c.email, c.name
		 FROM billing_subscriptions s
		 LEFT JOIN billing_customers c ON c.id = s.customer_id
		 WHERE s.status = 'canceled' AND s.canceled_at IS NOT NULL`,
	)
	if err != nil {
		slog.Debug("billing grace notifier: query failed", "error", err)
		return
	}
	defer rows.Close()

	now := time.Now()
	for rows.Next() {
		var (
			subID, stripeID, plan string
			canceledAt            time.Time
			email, name           *string
		)
		if err := rows.Scan(&subID, &stripeID, &canceledAt, &plan, &email, &name); err != nil {
			continue
		}

		graceEnd := canceledAt.Add(time.Duration(gracePeriodDays) * 24 * time.Hour)
		daysLeft := int(graceEnd.Sub(now).Hours() / 24)

		for _, threshold := range graceNotifyThresholds {
			if daysLeft == threshold {
				tenantLabel := safeStr(name, safeStr(email, stripeID))
				n.notify(ctx, subID, stripeID, tenantLabel, plan, graceEnd, daysLeft)
				break
			}
		}
	}
}

func safeStr(p *string, fallback string) string {
	if p != nil && *p != "" {
		return *p
	}
	return fallback
}

func (n *BillingGraceNotifier) notify(
	ctx context.Context,
	subID, stripeID, tenantLabel, plan string,
	graceEnd time.Time,
	daysLeft int,
) {
	// Dedupe: skip if an alert with the same subscription + threshold was
	// created within the last 23h. Without this, a restart loop would
	// re-send on every boot.
	title := fmt.Sprintf("課金猶予期間: %s (残り%d日)", tenantLabel, daysLeft)
	var existing int
	_ = n.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts
		 WHERE title = $1 AND created_at > NOW() - INTERVAL '23 hours'`,
		title,
	).Scan(&existing)
	if existing > 0 {
		return
	}

	severity := 3
	switch {
	case daysLeft <= 0:
		severity = 9
	case daysLeft == 1:
		severity = 7
	case daysLeft <= 3:
		severity = 5
	}

	var description string
	if daysLeft <= 0 {
		description = fmt.Sprintf(
			"テナント %s の課金猶予期間が本日終了しました。Free プラン (エージェント上限 5) へ自動ダウングレードされます。既存エージェントは接続継続しますが、6台目以降の登録はブロックされます。",
			tenantLabel,
		)
	} else {
		description = fmt.Sprintf(
			"テナント %s の課金猶予期間は %s に終了します (残り %d 日)。期限までに再契約されない場合、Free プラン (エージェント上限 5) へ自動ダウングレードされます。",
			tenantLabel, graceEnd.Format("2006-01-02"), daysLeft,
		)
	}

	var alertID string
	err := n.pool.QueryRow(ctx,
		`INSERT INTO alerts (title, description, severity, status)
		 VALUES ($1, $2, $3, 'open')
		 RETURNING id::text`,
		title, description, severity,
	).Scan(&alertID)
	if err != nil {
		slog.Warn("billing grace notifier: alert create failed", "error", err)
	} else {
		slog.Info("billing grace notifier: alert created",
			"alert_id", alertID,
			"subscription", stripeID,
			"days_left", daysLeft,
		)
	}

	// Email notification (optional — skipped when SMTP is not configured).
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		slog.Info("billing grace notifier: SMTP_HOST unset, skipping email", "days_left", daysLeft)
		return
	}

	recipients, err := n.adminEmails(ctx)
	if err != nil || len(recipients) == 0 {
		slog.Info("billing grace notifier: no admin recipients", "error", err)
		return
	}

	subject, body := buildGraceEmail(tenantLabel, plan, graceEnd, daysLeft)
	for _, to := range recipients {
		if err := sendLicenseSMTP(smtpHost, to, subject, body); err != nil {
			slog.Warn("billing grace notifier: email send failed", "to", to, "error", err)
		} else {
			slog.Info("billing grace notifier: email sent", "to", to, "days_left", daysLeft)
		}
	}
}

func (n *BillingGraceNotifier) adminEmails(ctx context.Context) ([]string, error) {
	rows, err := n.pool.Query(ctx,
		`SELECT email FROM users WHERE role = 'admin' AND email IS NOT NULL AND email <> '' AND active = true`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err == nil && e != "" {
			emails = append(emails, e)
		}
	}
	return emails, nil
}

// billingGracePeriodDays mirrors the env-var reader in the billing package.
// Duplicated here to avoid a billing→scheduler import cycle.
func billingGracePeriodDays() int {
	if v := os.Getenv("BILLING_GRACE_PERIOD_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return defaultBillingGracePeriodDays
}

func buildGraceEmail(tenantLabel, plan string, graceEnd time.Time, daysLeft int) (subject, body string) {
	var urgencyColor, urgencyLabel, headline string
	switch {
	case daysLeft <= 0:
		urgencyColor = "#dc2626"
		urgencyLabel = "本日終了"
		subject = fmt.Sprintf("[EDR Platform] 課金猶予期間が本日終了しました — %s", tenantLabel)
		headline = "課金猶予期間が終了しました"
	case daysLeft == 1:
		urgencyColor = "#ea580c"
		urgencyLabel = "残り 1 日"
		subject = fmt.Sprintf("[EDR Platform] 課金猶予期間まで残り 1 日 — %s", tenantLabel)
		headline = "課金猶予期間が明日終了します"
	case daysLeft <= 3:
		urgencyColor = "#f59e0b"
		urgencyLabel = fmt.Sprintf("残り %d 日", daysLeft)
		subject = fmt.Sprintf("[EDR Platform] 課金猶予期間まで残り %d 日 — %s", daysLeft, tenantLabel)
		headline = fmt.Sprintf("課金猶予期間が %d 日後に終了します", daysLeft)
	default:
		urgencyColor = "#d97706"
		urgencyLabel = fmt.Sprintf("残り %d 日", daysLeft)
		subject = fmt.Sprintf("[EDR Platform] 課金猶予期間まで残り %d 日 — %s", daysLeft, tenantLabel)
		headline = fmt.Sprintf("課金猶予期間が %d 日後に終了します", daysLeft)
	}

	var msgBody string
	if daysLeft <= 0 {
		msgBody = "Starter 相当の機能は利用できなくなり、Free プラン (エージェント上限 5 台、基本検知のみ) へ自動ダウングレードされます。" +
			"既存のエージェント接続は維持されますが、新規エージェントの登録は 6 台目以降ブロックされます。" +
			"引き続き Starter / Professional / Enterprise 機能をご利用になるには、Stripe Customer Portal から再契約してください。"
	} else {
		msgBody = fmt.Sprintf(
			"解約後の課金猶予期間は <strong>%s</strong> に終了します。"+
				"期限までに再契約されない場合、Free プラン (エージェント上限 5 台) へ自動ダウングレードされます。"+
				"継続してご利用いただくには、Stripe Customer Portal から再契約をお願いします。",
			graceEnd.Format("2006年01月02日"),
		)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#333">
  <div style="background:#1D6FE8;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">EDR Platform — 課金猶予期間のお知らせ</h2>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px">
    <div style="display:inline-block;padding:4px 12px;border-radius:4px;background:%s;
                color:white;font-size:13px;font-weight:bold;margin-bottom:16px">%s</div>
    <h3 style="margin:0 0 12px">%s</h3>
    <table style="width:100%%;border-collapse:collapse;font-size:14px;margin-bottom:16px">
      <tr>
        <td style="padding:6px 0;color:#666;width:140px">テナント</td>
        <td style="padding:6px 0;font-weight:bold">%s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:#666">最終プラン</td>
        <td style="padding:6px 0">%s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:#666">猶予期間終了日</td>
        <td style="padding:6px 0;font-weight:bold;color:%s">%s</td>
      </tr>
    </table>
    <p style="font-size:14px;color:#444;line-height:1.6">%s</p>
    <p style="margin-top:20px;font-size:13px;color:#666">
      再契約は Stripe Customer Portal から行えます。詳細はサポートチームまでお問い合わせください。
    </p>
  </div>
  <p style="font-size:12px;color:#999;text-align:center;margin-top:16px">
    このメールは EDR Platform から自動送信されています。
  </p>
</body>
</html>`,
		urgencyColor, urgencyLabel,
		headline,
		tenantLabel, plan,
		urgencyColor, graceEnd.Format("2006年01月02日"),
		msgBody,
	)

	return subject, buf.String()
}

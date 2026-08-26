package scheduler

import (
	"bytes"
	"context"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DigestScheduler sends a daily security summary email to configured recipients.
type DigestScheduler struct {
	pool       *pgxpool.Pool
	smtp       smtpCfg
	recipients []string
}

// NewDigestScheduler creates a DigestScheduler. SMTP settings are read from the
// environment (shared smtpFromEnv helper). recipients is a slice of email
// addresses to send the daily digest to.
func NewDigestScheduler(pool *pgxpool.Pool, recipients []string) *DigestScheduler {
	return &DigestScheduler{
		pool:       pool,
		smtp:       smtpFromEnv(),
		recipients: recipients,
	}
}

// Run starts the digest loop. It fires the daily digest at 08:00 local time.
// Designed to be called as a goroutine.
func (d *DigestScheduler) Run(ctx context.Context) {
	if d.smtp.host == "" || len(d.recipients) == 0 {
		slog.Info("ダイジェストスケジューラー無効 (SMTP未設定またはDIGEST_RECIPIENTS未設定)")
		return
	}
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 8, 0, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
			trackRun(ctx, "digest_scheduler", d.sendDailyDigest)
		}
	}
}

func (d *DigestScheduler) sendDailyDigest(ctx context.Context) {
	yesterday := time.Now().Add(-24 * time.Hour)

	// **数えられなかった 0 を、そのまま日次ダイジェストに書いていました。**
	// 「クリティカル 0件」は読んだ人にとって最も安心できる行で、
	// 読めなかったこととは区別がつきません。数えられないなら送りません。
	var newAlerts, criticalAlerts, openIncidents, onlineAgents int
	for _, c := range []struct {
		what string
		sql  string
		args []any
		into *int
	}{
		{"新規アラート", `SELECT COUNT(*) FROM alerts WHERE created_at >= $1`, []any{yesterday}, &newAlerts},
		{"クリティカル", `SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at >= $1`, []any{yesterday}, &criticalAlerts},
		{"未解決インシデント", `SELECT COUNT(*) FROM incidents WHERE status='open'`, nil, &openIncidents},
		{"オンラインエージェント", `SELECT COUNT(*) FROM agents WHERE status='online'`, nil, &onlineAgents},
	} {
		if err := d.pool.QueryRow(ctx, c.sql, c.args...).Scan(c.into); err != nil {
			fail(ctx, err, "日次ダイジェスト: 数えられないため送りません", "what", c.what)
			return
		}
	}

	subject := fmt.Sprintf("[EDR] 日次セキュリティダイジェスト - %s", time.Now().Format("2006-01-02"))

	var body bytes.Buffer
	fmt.Fprintf(&body, "EDR Platform 日次セキュリティレポート\n")
	fmt.Fprintf(&body, "報告日時: %s\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintf(&body, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	fmt.Fprintf(&body, "【過去24時間のサマリー】\n")
	fmt.Fprintf(&body, "  新規アラート:         %d件\n", newAlerts)
	fmt.Fprintf(&body, "  クリティカル:         %d件\n", criticalAlerts)
	fmt.Fprintf(&body, "  未解決インシデント:   %d件\n", openIncidents)
	fmt.Fprintf(&body, "  オンラインエージェント: %d台\n\n", onlineAgents)
	if criticalAlerts > 0 {
		fmt.Fprintf(&body, "警告: クリティカルアラートが %d件 検出されています。\n", criticalAlerts)
		fmt.Fprintf(&body, "      早急な対応をご検討ください。\n\n")
	}
	fmt.Fprintf(&body, "EDR Platform 自動通知システム\n")

	for _, to := range d.recipients {
		if err := d.sendEmail(ctx, to, subject, body.String()); err != nil {
			fail(ctx, err, "ダイジェストメール送信失敗", "to", to)
		} else {
			slog.Info("ダイジェストメール送信完了", "to", to)
		}
	}
}

func (d *DigestScheduler) sendEmail(ctx context.Context, to, subject, textBody string) error {
	addr := fmt.Sprintf("%s:%d", d.smtp.host, d.smtp.port)

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: EDR Platform <%s>\r\n", mailhdr.Sanitize(d.smtp.from)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", mailhdr.Sanitize(to)))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(textBody)

	done := make(chan error, 1)
	go func() {
		done <- sendSTARTTLS(addr, d.smtp.host, d.smtp.username, d.smtp.password,
			d.smtp.from, to, msg.Bytes())
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

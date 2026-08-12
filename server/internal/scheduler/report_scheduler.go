// Package scheduler provides background workers for the EDR platform.
package scheduler

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/edr-platform/server/internal/mailhdr"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

// smtpCfg holds SMTP connection settings read from environment variables.
type smtpCfg struct {
	host     string
	port     int
	username string
	password string
	from     string
}

func smtpFromEnv() smtpCfg {
	port := 587
	if p := os.Getenv("SMTP_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = os.Getenv("SMTP_USERNAME")
	}
	return smtpCfg{
		host:     os.Getenv("SMTP_HOST"),
		port:     port,
		username: os.Getenv("SMTP_USERNAME"),
		password: os.Getenv("SMTP_PASSWORD"),
		from:     from,
	}
}

// ReportScheduler polls for due report schedules and delivers them by email.
type ReportScheduler struct {
	scheduleStore *store.ReportScheduleStore
	pool          *pgxpool.Pool
	smtp          smtpCfg
}

// NewReportScheduler creates a ReportScheduler that reads SMTP config from
// environment variables (SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
// SMTP_FROM).
func NewReportScheduler(
	scheduleStore *store.ReportScheduleStore,
	pool *pgxpool.Pool,
) *ReportScheduler {
	return &ReportScheduler{
		scheduleStore: scheduleStore,
		pool:          pool,
		smtp:          smtpFromEnv(),
	}
}

// Run starts the scheduler loop. Designed to be called as a goroutine.
func (s *ReportScheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	slog.Info("レポートスケジューラー起動 (メール配信)")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processDue(ctx)
		}
	}
}

func (s *ReportScheduler) processDue(ctx context.Context) {
	due, err := s.scheduleStore.GetDue(ctx)
	if err != nil {
		slog.Error("期限切れレポートの取得に失敗しました", "error", err)
		return
	}
	for _, sched := range due {
		if err := s.deliver(ctx, sched); err != nil {
			slog.Error("レポートメール送信に失敗しました", "id", sched.ID, "name", sched.Name, "error", err)
		}
		// Always advance next_run_at so the record is not re-processed in a
		// tight loop even when delivery failed.
		next := store.ComputeNextRun(sched, time.Now().UTC())
		if err := s.scheduleStore.MarkRun(ctx, sched.ID, next); err != nil {
			slog.Warn("MarkRunに失敗しました", "id", sched.ID, "error", err)
		}
	}
}

// deliver generates a report body and sends it to all recipients.
func (s *ReportScheduler) deliver(ctx context.Context, sched *store.ReportSchedule) error {
	if s.smtp.host == "" {
		slog.Warn("SMTP_HOSTが未設定のためレポートメール送信をスキップしました", "id", sched.ID)
		return nil
	}
	if len(sched.Recipients) == 0 {
		slog.Debug("受信者なしのためレポートをスキップしました", "id", sched.ID)
		return nil
	}

	body, err := s.generateReport(ctx, sched)
	if err != nil {
		return fmt.Errorf("レポート生成失敗: %w", err)
	}

	subject := fmt.Sprintf("[EDR Report] %s - %s", sched.Name, time.Now().UTC().Format("2006-01-02"))
	html := buildReportEmail(sched, body)

	var lastErr error
	for _, recipient := range sched.Recipients {
		if err := s.sendEmail(ctx, recipient, subject, html); err != nil {
			slog.Warn("レポートメール送信失敗", "to", recipient, "error", err)
			lastErr = err
		} else {
			slog.Info("レポートメールを送信しました", "to", recipient, "schedule", sched.Name)
		}
	}
	return lastErr
}

// generateReport builds a plain-text report body for the given schedule.
func (s *ReportScheduler) generateReport(ctx context.Context, sched *store.ReportSchedule) (string, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("レポート名: %s\n", sched.Name))
	sb.WriteString(fmt.Sprintf("種別: %s\n", sched.ReportType))
	sb.WriteString(fmt.Sprintf("頻度: %s\n", sched.Frequency))
	sb.WriteString(fmt.Sprintf("生成日時: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("─────────────────────────────────\n\n")

	switch sched.ReportType {
	case "alert_summary":
		rows, err := s.pool.Query(ctx,
			`SELECT severity, COUNT(*) FROM alerts
			 WHERE created_at >= NOW() - INTERVAL '24 hours'
			 GROUP BY severity ORDER BY severity`)
		if err != nil {
			return "", fmt.Errorf("アラートクエリ失敗: %w", err)
		}
		defer rows.Close()
		sb.WriteString("過去24時間のアラートサマリー:\n")
		any := false
		for rows.Next() {
			any = true
			var sev string
			var cnt int
			if err := rows.Scan(&sev, &cnt); err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s: %d件\n", sev, cnt))
		}
		if !any {
			sb.WriteString("  (アラートなし)\n")
		}

	case "agent_status":
		rows, err := s.pool.Query(ctx,
			`SELECT status, COUNT(*) FROM agents GROUP BY status ORDER BY status`)
		if err != nil {
			return "", fmt.Errorf("エージェントクエリ失敗: %w", err)
		}
		defer rows.Close()
		sb.WriteString("エージェント状態:\n")
		any := false
		for rows.Next() {
			any = true
			var status string
			var cnt int
			if err := rows.Scan(&status, &cnt); err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s: %d台\n", status, cnt))
		}
		if !any {
			sb.WriteString("  (エージェントなし)\n")
		}

	case "threat_report":
		rows, err := s.pool.Query(ctx,
			`SELECT status, COUNT(*) FROM incidents GROUP BY status ORDER BY status`)
		if err != nil {
			return "", fmt.Errorf("インシデントクエリ失敗: %w", err)
		}
		defer rows.Close()
		sb.WriteString("インシデント状況:\n")
		any := false
		for rows.Next() {
			any = true
			var status string
			var cnt int
			if err := rows.Scan(&status, &cnt); err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s: %d件\n", status, cnt))
		}
		if !any {
			sb.WriteString("  (インシデントなし)\n")
		}

	case "daily_summary":
		// Open incident count
		var openCount int
		err := s.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM incidents WHERE status NOT IN ('closed', 'resolved')`).
			Scan(&openCount)
		if err != nil {
			return "", fmt.Errorf("オープンインシデントクエリ失敗: %w", err)
		}
		sb.WriteString(fmt.Sprintf("オープンインシデント数: %d件\n\n", openCount))

		// Agent health
		agentRows, err := s.pool.Query(ctx,
			`SELECT status, COUNT(*) FROM agents GROUP BY status ORDER BY status`)
		if err != nil {
			return "", fmt.Errorf("エージェント状態クエリ失敗: %w", err)
		}
		defer agentRows.Close()
		sb.WriteString("エージェント状態:\n")
		anyAgent := false
		for agentRows.Next() {
			anyAgent = true
			var status string
			var cnt int
			if err := agentRows.Scan(&status, &cnt); err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s: %d台\n", status, cnt))
		}
		if !anyAgent {
			sb.WriteString("  (エージェントなし)\n")
		}
		sb.WriteString("\n")

		// Top alerts last 24h
		// alerts に rule_name 列は無い。ルール名は rules から JOIN で引き、
		// 紐付かないもの (組み込み検知器は rule_id を埋めない) は title で
		// まとめる。title は NOT NULL なので表示名が空になることはない。
		alertRows, err := s.pool.Query(ctx,
			`SELECT COALESCE(NULLIF(r.name,''), al.title) AS rule_name, COUNT(*) cnt
			 FROM alerts al
			 LEFT JOIN rules r ON r.id = al.rule_id
			 WHERE al.created_at >= NOW() - INTERVAL '24 hours'
			 GROUP BY 1 ORDER BY cnt DESC LIMIT 5`)
		if err != nil {
			return "", fmt.Errorf("トップアラートクエリ失敗: %w", err)
		}
		defer alertRows.Close()
		sb.WriteString("過去24時間のトップアラート (最大5件):\n")
		anyAlert := false
		for alertRows.Next() {
			anyAlert = true
			var ruleName string
			var cnt int
			if err := alertRows.Scan(&ruleName, &cnt); err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s: %d件\n", ruleName, cnt))
		}
		if !anyAlert {
			sb.WriteString("  (アラートなし)\n")
		}

	case "compliance":
		var complianceStatus string
		err := s.pool.QueryRow(ctx,
			`SELECT setting_value FROM system_settings WHERE key = 'compliance_status'`).
			Scan(&complianceStatus)
		if err != nil {
			complianceStatus = "コンプライアンスデータなし"
		}
		sb.WriteString(fmt.Sprintf("コンプライアンス状況:\n  %s\n", complianceStatus))

	default:
		sb.WriteString("このレポート種別のデータは現在準備中です。\n")
	}

	sb.WriteString("\n\nEDR Platform 自動レポートシステム\n")
	return sb.String(), nil
}

// buildReportEmail wraps plain-text content in a dark-branded Kizashi HTML layout.
func buildReportEmail(sched *store.ReportSchedule, textBody string) string {
	baseURL := os.Getenv("EDR_BASE_URL")
	if baseURL == "" {
		baseURL = "#"
	}
	generatedAt := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Kizashi — 定期レポート</title>
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:32px 0">
    <tr>
      <td align="center">
        <table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%">

          <!-- Header -->
          <tr>
            <td style="background:#0a0f1e;padding:20px 28px;border-radius:8px 8px 0 0">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="width:44px;vertical-align:middle">
                    <div style="width:40px;height:40px;background:#e8002d;border-radius:6px;
                                text-align:center;line-height:40px;font-size:22px;
                                font-weight:900;color:#ffffff;letter-spacing:-1px">V</div>
                  </td>
                  <td style="padding-left:14px;vertical-align:middle">
                    <span style="color:#ffffff;font-size:18px;font-weight:700;
                                 letter-spacing:0.3px">Kizashi</span>
                    <span style="color:#8892a4;font-size:14px;font-weight:400"> — 定期レポート</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Subtitle bar -->
          <tr>
            <td style="background:#111827;padding:12px 28px;border-left:4px solid #e8002d">
              <span style="color:#e8002d;font-size:13px;font-weight:600;
                           text-transform:uppercase;letter-spacing:0.8px">`)
	buf.WriteString(sched.ReportType)
	buf.WriteString(`</span>
              <span style="color:#d1d5db;font-size:15px;font-weight:600;margin-left:10px">`)
	buf.WriteString(sched.Name)
	buf.WriteString(`</span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="background:#ffffff;padding:28px 28px 20px">
              <p style="margin:0 0 6px;font-size:12px;color:#9ca3af">
                生成日時: `)
	buf.WriteString(generatedAt)
	buf.WriteString(`
              </p>
              <hr style="border:none;border-top:1px solid #e5e7eb;margin:14px 0 18px">
              <pre style="margin:0;font-size:13px;line-height:1.75;color:#1f2937;
                          white-space:pre-wrap;word-break:break-word;
                          font-family:'Courier New',Courier,monospace;
                          background:#f9fafb;border:1px solid #e5e7eb;
                          border-radius:6px;padding:16px">`)
	buf.WriteString(textBody)
	buf.WriteString(`</pre>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td style="background:#ffffff;padding:0 28px 28px;text-align:center">
              <a href="`)
	buf.WriteString(baseURL)
	buf.WriteString(`"
                 style="display:inline-block;background:#e8002d;color:#ffffff;
                        font-size:14px;font-weight:700;text-decoration:none;
                        padding:12px 32px;border-radius:6px;letter-spacing:0.3px;
                        margin-top:8px">
                ダッシュボードを開く
              </a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#0a0f1e;padding:16px 28px;border-radius:0 0 8px 8px;
                       text-align:center">
              <p style="margin:0;font-size:11px;color:#4b5563;line-height:1.6">
                このメールは Kizashi から自動送信されています。<br>
                心当たりのない場合はシステム管理者にお問い合わせください。
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`)
	return buf.String()
}

// sendEmail delivers a single HTML email using STARTTLS (matching the pattern
// used by notification.EmailNotifier).
func (s *ReportScheduler) sendEmail(ctx context.Context, to, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", s.smtp.host, s.smtp.port)

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: EDR Platform <%s>\r\n", mailhdr.Sanitize(s.smtp.from)))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", mailhdr.Sanitize(to)))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mailhdr.Sanitize(subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	done := make(chan error, 1)
	go func() {
		done <- sendSTARTTLS(addr, s.smtp.host, s.smtp.username, s.smtp.password,
			s.smtp.from, to, msg.Bytes())
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// sendSTARTTLS dials SMTP and upgrades to TLS before authentication, mirroring
// the implementation in internal/notification/email_notifier.go.
func sendSTARTTLS(addr, host, username, password, from, to string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("SMTP接続失敗: %w", err)
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTPクライアント作成失敗: %w", err)
	}
	defer c.Close()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS失敗: %w", err)
		}
	}

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

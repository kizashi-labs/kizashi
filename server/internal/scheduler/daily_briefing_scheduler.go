package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DailyBriefingScheduler generates a SOC briefing at a configured hour each day
// and publishes it via NATS or writes to the notification system.
type DailyBriefingScheduler struct {
	pool       *pgxpool.Pool
	hour       int                                     // 送信する時刻（24h表記、デフォルト8）
	slackURL   string                                  // Slack Incoming Webhook URL (空なら送信しない)
	webhookURL string                                  // 汎用Webhook URL (空なら送信しない)
	publish    func(subject string, data []byte) error // NATS publish 関数
	emailCfg   *emailConfig
}

// EmailConfig holds SMTP settings for email delivery.
type EmailConfig struct {
	Host string // SMTPサーバーホスト (例: smtp.gmail.com)
	Port string // SMTPポート (例: 587)
	User string // 認証ユーザー
	Pass string // 認証パスワード
	From string // 送信元アドレス
	To   string // 送信先アドレス（カンマ区切りで複数可）
}

// emailConfig は内部互換用エイリアス
type emailConfig = EmailConfig

// BriefingSummary holds the daily SOC briefing data.
type BriefingSummary struct {
	GeneratedAt       time.Time `json:"generated_at"`
	UrgentAlerts      int       `json:"urgent_alerts"`
	OpenIncidents     int       `json:"open_incidents"`
	NewAlertsToday    int       `json:"new_alerts_today"`
	AutoClosedToday   int       `json:"auto_closed_today"`
	TopTechniques     []string  `json:"top_techniques"`
	OfflineEndpoints  int       `json:"offline_endpoints"`
	RecommendedAction string    `json:"recommended_action"`
}

// NewDailyBriefingScheduler creates the scheduler.
// hour: 0-23, publishFn: NATS publish (nil = log only).
// slackURL / webhookURL: optional Incoming Webhook URLs (empty = skip).
func NewDailyBriefingScheduler(
	pool *pgxpool.Pool,
	hour int,
	publishFn func(string, []byte) error,
	slackURL string,
	webhookURL string,
) *DailyBriefingScheduler {
	if hour < 0 || hour > 23 {
		hour = 8
	}
	return &DailyBriefingScheduler{
		pool:       pool,
		hour:       hour,
		slackURL:   slackURL,
		webhookURL: webhookURL,
		publish:    publishFn,
	}
}

// WithEmail sets SMTP email delivery for the daily briefing.
// host: SMTPサーバー, port: ポート番号(例:587), user/pass: 認証情報,
// from: 送信元アドレス, to: 送信先（カンマ区切り複数可）
func (s *DailyBriefingScheduler) WithEmail(host, port, user, pass, from, to string) *DailyBriefingScheduler {
	if host != "" && to != "" {
		s.emailCfg = &emailConfig{Host: host, Port: port, User: user, Pass: pass, From: from, To: to}
	}
	return s
}

// Run starts the daily briefing loop. Fires once at the configured hour each day.
// collectAndDeliver は1回分の送信。tick の中身を関数にしてあるのは、
// trackRun に渡すためと、「起きたが送れなかった」も1回の実行として
// 数えるためです。
func (s *DailyBriefingScheduler) collectAndDeliver(ctx context.Context) {
	summary, err := s.collect(ctx)
	if err != nil {
		fail(ctx, err, "DailyBriefingScheduler: データ収集に失敗しました")
		return
	}
	s.deliver(ctx, summary)
}

func (s *DailyBriefingScheduler) Run(ctx context.Context) {
	slog.Info("DailyBriefingScheduler: 開始", "hour", s.hour)
	for {
		// 次の送信時刻を計算
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), s.hour, 0, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		wait := next.Sub(now)
		slog.Info("DailyBriefingScheduler: 次回送信", "at", next.Format("2006-01-02 15:04"), "wait", wait.Round(time.Minute))

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			trackRun(ctx, "daily_briefing_scheduler", s.collectAndDeliver)
		}
	}
}

// collect gathers all metrics needed for the daily briefing.
func (s *DailyBriefingScheduler) collect(ctx context.Context) (*BriefingSummary, error) {
	summary := &BriefingSummary{GeneratedAt: time.Now()}

	// **数えられなかった 0 を、そのまま朝のメールに書いていました。**
	// 「緊急アラート 0件」は読んだ人にとって最も安心できる行で、
	// 読めなかったこととは区別がつきません。数えられないなら送りません。
	for _, c := range []struct {
		what string
		sql  string
		into *int
	}{
		{"緊急アラート", `SELECT COUNT(*) FROM alerts WHERE severity >= 7 AND status = 'open'`,
			&summary.UrgentAlerts},
		{"未処理インシデント", `SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating','contained')`,
			&summary.OpenIncidents},
		{"本日の新規アラート", `SELECT COUNT(*) FROM alerts WHERE created_at >= CURRENT_DATE`,
			&summary.NewAlertsToday},
		{"本日の自動クローズ", `SELECT COUNT(*) FROM alerts WHERE status = 'false_positive' AND updated_at >= CURRENT_DATE`,
			&summary.AutoClosedToday},
		{"オフラインエンドポイント", `SELECT COUNT(*) FROM agents WHERE status = 'offline' AND last_seen >= NOW() - INTERVAL '7 days'`,
			&summary.OfflineEndpoints},
	} {
		if err := s.pool.QueryRow(ctx, c.sql).Scan(c.into); err != nil {
			return nil, fmt.Errorf("%sを数えられません: %w", c.what, err)
		}
	}

	// 上位MITREテクニック（直近24時間）
	rows, err := s.pool.Query(ctx,
		`SELECT mitre_technique, COUNT(*) as cnt
		 FROM alerts WHERE mitre_technique IS NOT NULL AND mitre_technique <> ''
		   AND created_at >= NOW() - INTERVAL '24 hours'
		 GROUP BY mitre_technique ORDER BY cnt DESC LIMIT 3`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var tech string
			var cnt int
			if err := rows.Scan(&tech, &cnt); err == nil {
				summary.TopTechniques = append(summary.TopTechniques,
					fmt.Sprintf("%s (%d件)", tech, cnt))
			}
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("ブリーフィング集計の走査に失敗しました: %w", err)
		}
	}

	// 推奨アクション
	summary.RecommendedAction = s.recommendAction(summary)
	return summary, nil
}

func (s *DailyBriefingScheduler) recommendAction(b *BriefingSummary) string {
	if b.UrgentAlerts > 0 {
		return fmt.Sprintf("⚠️ 緊急アラート %d件を優先対応してください（/soc-queue を確認）", b.UrgentAlerts)
	}
	if b.OpenIncidents > 5 {
		return fmt.Sprintf("📋 未処理インシデントが %d件あります。インシデント管理で状況を確認してください", b.OpenIncidents)
	}
	if b.OfflineEndpoints > 0 {
		return fmt.Sprintf("🖥️ %d台のエンドポイントがオフラインです。エージェント接続を確認してください", b.OfflineEndpoints)
	}
	return "✅ 重大な問題は検出されていません。通常業務を継続してください"
}

// deliver logs the briefing, publishes to NATS, and sends to Slack/Webhook if configured.
func (s *DailyBriefingScheduler) deliver(ctx context.Context, b *BriefingSummary) {
	msg := fmt.Sprintf(
		"\n=== SOC デイリーブリーフィング %s ===\n"+
			"📊 本日の新規アラート: %d件\n"+
			"🚨 緊急対応が必要: %d件\n"+
			"📁 未処理インシデント: %d件\n"+
			"🤖 AI自動クローズ(本日): %d件\n"+
			"🖥️ オフライン端末: %d台\n"+
			"🎯 上位テクニック: %s\n"+
			"→ 推奨アクション: %s\n"+
			"=====================================",
		b.GeneratedAt.Format("2006年01月02日 15:04"),
		b.NewAlertsToday,
		b.UrgentAlerts,
		b.OpenIncidents,
		b.AutoClosedToday,
		b.OfflineEndpoints,
		joinOrNone(b.TopTechniques),
		b.RecommendedAction,
	)
	slog.Info("DailyBriefingScheduler: ブリーフィング生成", "summary", msg)

	if s.publish != nil {
		if err := s.publish("soc.daily_briefing", []byte(msg)); err != nil {
			fail(ctx, err, "DailyBriefingScheduler: NATS送信に失敗しました")
		}
	}

	if s.slackURL != "" {
		s.sendSlack(ctx, b)
	}

	if s.webhookURL != "" {
		s.sendWebhook(ctx, b)
	}

	if s.emailCfg != nil {
		s.sendEmail(ctx, b, msg)
	}
}

// sendSlack posts the briefing as a Slack Incoming Webhook message.
func (s *DailyBriefingScheduler) sendSlack(ctx context.Context, b *BriefingSummary) {
	urgentStr := ""
	if b.UrgentAlerts > 0 {
		urgentStr = fmt.Sprintf("*⚠️ 緊急アラート %d件* の対応が必要です。\n", b.UrgentAlerts)
	}
	body, _ := json.Marshal(map[string]any{
		"text": fmt.Sprintf("*SOC デイリーブリーフィング — %s*", b.GeneratedAt.Format("2006/01/02")),
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("SOC デイリーブリーフィング %s", b.GeneratedAt.Format("2006/01/02")),
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf(
						"%s📊 新規アラート: *%d件* | 🚨 緊急: *%d件* | 📁 インシデント: *%d件*\n"+
							"🤖 AI自動クローズ: *%d件* | 🖥️ オフライン端末: *%d台*\n"+
							"🎯 上位テクニック: %s\n"+
							"→ %s",
						urgentStr,
						b.NewAlertsToday, b.UrgentAlerts, b.OpenIncidents,
						b.AutoClosedToday, b.OfflineEndpoints,
						joinOrNone(b.TopTechniques),
						b.RecommendedAction,
					),
				},
			},
		},
	})

	resp, err := http.Post(s.slackURL, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		fail(ctx, err, "DailyBriefingScheduler: Slack送信に失敗しました")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("DailyBriefingScheduler: Slack webhook が非200を返しました", "status", resp.Status)
	} else {
		slog.Info("DailyBriefingScheduler: Slack送信成功")
	}
}

// sendWebhook posts the briefing as JSON to a generic webhook endpoint.
func (s *DailyBriefingScheduler) sendWebhook(ctx context.Context, b *BriefingSummary) {
	body, _ := json.Marshal(b)
	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		fail(ctx, err, "DailyBriefingScheduler: Webhook送信に失敗しました")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("DailyBriefingScheduler: Webhook が非200を返しました", "status", resp.Status)
	} else {
		slog.Info("DailyBriefingScheduler: Webhook送信成功")
	}
}

func joinOrNone(ss []string) string {
	if len(ss) == 0 {
		return "なし"
	}
	return strings.Join(ss, ", ")
}

// SendEmailViaSMTP はSMTP経由でメールを送信する共通ユーティリティ。
func SendEmailViaSMTP(cfg *EmailConfig, subject, body string) error {
	recipients := strings.Split(cfg.To, ",")
	for i, r := range recipients {
		recipients[i] = strings.TrimSpace(r)
	}
	header := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n",
		cfg.From, strings.Join(recipients, ", "),
		mime.QEncoding.Encode("UTF-8", subject),
	)
	var auth smtp.Auth
	if cfg.User != "" {
		auth = smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	}
	addr := cfg.Host + ":" + cfg.Port
	return smtp.SendMail(addr, auth, cfg.From, recipients, []byte(header+body))
}

// sendEmail sends the daily briefing via SMTP.
func (s *DailyBriefingScheduler) sendEmail(ctx context.Context, b *BriefingSummary, plainText string) {
	cfg := s.emailCfg
	subject := fmt.Sprintf("SOC デイリーブリーフィング %s", b.GeneratedAt.Format("2006/01/02"))

	// メールヘッダーと本文を組み立て
	recipients := strings.Split(cfg.To, ",")
	for i, r := range recipients {
		recipients[i] = strings.TrimSpace(r)
	}

	header := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n",
		cfg.From,
		strings.Join(recipients, ", "),
		mime.QEncoding.Encode("UTF-8", subject),
	)
	body := header + plainText

	var auth smtp.Auth
	if cfg.User != "" {
		auth = smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	}

	addr := cfg.Host + ":" + cfg.Port
	if err := smtp.SendMail(addr, auth, cfg.From, recipients, []byte(body)); err != nil {
		fail(ctx, err, "DailyBriefingScheduler: メール送信に失敗しました")
		return
	}
	slog.Info("DailyBriefingScheduler: メール送信成功", "to", cfg.To)
}

package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// AlertDigestSender sends periodic alert digest summaries via NATS.
type AlertDigestSender struct {
	pool *pgxpool.Pool
	nc   *nats.Conn
}

// NewAlertDigestSender creates a new AlertDigestSender.
func NewAlertDigestSender(pool *pgxpool.Pool, nc *nats.Conn) *AlertDigestSender {
	return &AlertDigestSender{pool: pool, nc: nc}
}

// Run starts two tickers: daily at 08:00 JST (23:00 UTC) and weekly on Monday 08:00 JST (Sunday 23:00 UTC).
func (s *AlertDigestSender) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			h := now.Hour()
			wd := now.Weekday()

			// Daily digest: fires at 23:00 UTC (= 08:00 JST)
			if h == 23 {
				s.sendDailyDigest(ctx)
			}
			// Weekly digest: fires on Sunday 23:00 UTC (= Monday 08:00 JST)
			if wd == time.Sunday && h == 23 {
				s.sendWeeklyDigest(ctx)
			}
		}
	}
}

// alertsTableExists checks if the alerts table exists.
func (s *AlertDigestSender) alertsTableExists(ctx context.Context) bool {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'alerts'
		)`).Scan(&exists)
	return err == nil && exists
}

type digestAgentEntry struct {
	AgentID string `json:"agent_id"`
	Count   int    `json:"count"`
}

type digestAlertEntry struct {
	Title string `json:"title"`
	Count int    `json:"count"`
}

type digestPayload struct {
	Period    string             `json:"period"`
	Date      string             `json:"date"`
	Critical  int                `json:"critical"`
	High      int                `json:"high"`
	Medium    int                `json:"medium"`
	Low       int                `json:"low"`
	TopAgents []digestAgentEntry `json:"top_agents"`
	TopAlerts []digestAlertEntry `json:"top_alerts"`
	Total     int                `json:"total"`
}

func (s *AlertDigestSender) buildDigest(ctx context.Context, period string, since time.Time) (*digestPayload, error) {
	if !s.alertsTableExists(ctx) {
		return nil, fmt.Errorf("alerts table does not exist")
	}

	// Count alerts by severity bucket
	var critical, high, medium, low int
	_ = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE created_at >= $1 AND severity >= 9`, since).Scan(&critical)
	_ = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE created_at >= $1 AND severity >= 7 AND severity < 9`, since).Scan(&high)
	_ = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE created_at >= $1 AND severity >= 5 AND severity < 7`, since).Scan(&medium)
	_ = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE created_at >= $1 AND severity < 5`, since).Scan(&low)

	total := critical + high + medium + low

	// Top 5 agents by alert count
	rows, err := s.pool.Query(ctx,
		`SELECT agent_id::text, COUNT(*) AS cnt
		 FROM alerts
		 WHERE created_at >= $1 AND agent_id IS NOT NULL
		 GROUP BY agent_id
		 ORDER BY cnt DESC
		 LIMIT 5`, since)
	var topAgents []digestAgentEntry
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e digestAgentEntry
			if scanErr := rows.Scan(&e.AgentID, &e.Count); scanErr == nil {
				topAgents = append(topAgents, e)
			}
		}
	}
	if topAgents == nil {
		topAgents = []digestAgentEntry{}
	}

	// Top 3 alert types by title
	rows2, err := s.pool.Query(ctx,
		`SELECT title, COUNT(*) AS cnt
		 FROM alerts
		 WHERE created_at >= $1
		 GROUP BY title
		 ORDER BY cnt DESC
		 LIMIT 3`, since)
	var topAlerts []digestAlertEntry
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var e digestAlertEntry
			if scanErr := rows2.Scan(&e.Title, &e.Count); scanErr == nil {
				topAlerts = append(topAlerts, e)
			}
		}
	}
	if topAlerts == nil {
		topAlerts = []digestAlertEntry{}
	}

	return &digestPayload{
		Period:    period,
		Date:      time.Now().UTC().Format("2006-01-02"),
		Critical:  critical,
		High:      high,
		Medium:    medium,
		Low:       low,
		TopAgents: topAgents,
		TopAlerts: topAlerts,
		Total:     total,
	}, nil
}

// recordRun persists one digest send into alert_digest_runs for the history UI.
// Best effort: a missing table (pre-migration-258) only logs a warning.
func (s *AlertDigestSender) recordRun(ctx context.Context, period string, totalAlerts int, status string) {
	// recipients_count from the persisted config for this period (0 if unset).
	recipients := 0
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT config FROM alert_digest_config WHERE id = 1`).Scan(&raw); err == nil {
		var cfg struct {
			Daily struct {
				Recipients []string `json:"recipients"`
			} `json:"daily"`
			Weekly struct {
				Recipients []string `json:"recipients"`
			} `json:"weekly"`
		}
		if json.Unmarshal(raw, &cfg) == nil {
			if period == "daily" {
				recipients = len(cfg.Daily.Recipients)
			} else {
				recipients = len(cfg.Weekly.Recipients)
			}
		}
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO alert_digest_runs (type, recipients_count, total_alerts, status)
		VALUES ($1, $2, $3, $4)`, period, recipients, totalAlerts, status); err != nil {
		slog.Warn("ダイジェスト実行履歴の記録に失敗しました", "error", err)
	}
}

func (s *AlertDigestSender) sendDailyDigest(ctx context.Context) {
	since := time.Now().UTC().Add(-24 * time.Hour)
	payload, err := s.buildDigest(ctx, "daily", since)
	if err != nil {
		slog.Warn("日次ダイジェスト: データ取得に失敗しました", "error", err)
		s.recordRun(ctx, "daily", 0, "failed")
		return
	}
	defer s.recordRun(ctx, "daily", payload.Total, "delivered")

	msg := fmt.Sprintf(
		"[EDR Daily Digest] %s | Critical: %d, High: %d, Medium: %d, Low: %d | Total: %d",
		payload.Date, payload.Critical, payload.High, payload.Medium, payload.Low, payload.Total,
	)
	slog.Info("日次アラートダイジェスト", "date", payload.Date, "total", payload.Total,
		"critical", payload.Critical, "high", payload.High, "message", msg)

	if s.nc != nil {
		data, _ := json.Marshal(payload)
		if pubErr := s.nc.Publish("digest.daily", data); pubErr != nil {
			slog.Warn("digest.daily NATSパブリッシュに失敗しました", "error", pubErr)
		}
	}
}

func (s *AlertDigestSender) sendWeeklyDigest(ctx context.Context) {
	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	payload, err := s.buildDigest(ctx, "weekly", since)
	if err != nil {
		slog.Warn("週次ダイジェスト: データ取得に失敗しました", "error", err)
		s.recordRun(ctx, "weekly", 0, "failed")
		return
	}
	defer s.recordRun(ctx, "weekly", payload.Total, "delivered")

	msg := fmt.Sprintf(
		"[EDR Weekly Digest] Week of %s | Critical: %d, High: %d, Medium: %d, Low: %d | Total: %d",
		payload.Date, payload.Critical, payload.High, payload.Medium, payload.Low, payload.Total,
	)
	slog.Info("週次アラートダイジェスト", "date", payload.Date, "total", payload.Total,
		"critical", payload.Critical, "high", payload.High, "message", msg)

	if s.nc != nil {
		data, _ := json.Marshal(payload)
		if pubErr := s.nc.Publish("digest.weekly", data); pubErr != nil {
			slog.Warn("digest.weekly NATSパブリッシュに失敗しました", "error", pubErr)
		}
	}
}

// SendNow triggers a digest immediately for the given period ("daily" or "weekly").
func (s *AlertDigestSender) SendNow(ctx context.Context, period string) error {
	switch period {
	case "daily":
		s.sendDailyDigest(ctx)
	case "weekly":
		s.sendWeeklyDigest(ctx)
	default:
		return fmt.Errorf("unknown period: %s (use 'daily' or 'weekly')", period)
	}
	return nil
}

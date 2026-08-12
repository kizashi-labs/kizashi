package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SecurityMetricsCollector periodically snapshots security KPIs into
// security_metrics_history so the metrics/trend dashboard has real data.
// Previously the table was only ever written by manual entry, so the page was
// always empty (and the UI fell back to fabricated mock values).
type SecurityMetricsCollector struct {
	pool     *pgxpool.Pool
	interval time.Duration
}

// NewSecurityMetricsCollector creates a collector. interval <= 0 defaults to 1h.
func NewSecurityMetricsCollector(pool *pgxpool.Pool, interval time.Duration) *SecurityMetricsCollector {
	if interval <= 0 {
		interval = time.Hour
	}
	return &SecurityMetricsCollector{pool: pool, interval: interval}
}

// Run collects an initial snapshot shortly after start, then every interval.
func (c *SecurityMetricsCollector) Run(ctx context.Context) {
	slog.Info("SecurityMetricsCollector: 開始", "interval", c.interval)

	// Initial snapshot after a short delay (avoid DB load right at boot).
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
		c.runOnce(ctx)
	}

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.runOnce(ctx)
		}
	}
}

// runOnce records one snapshot of each KPI. Each metric is collected
// defensively: a query error (e.g. a missing table) skips that metric and logs
// a warning rather than aborting the whole snapshot.
func (c *SecurityMetricsCollector) runOnce(ctx context.Context) {
	type metric struct {
		name, unit, query string
	}
	metrics := []metric{
		{"total_agents", "count", `SELECT COUNT(*) FROM agents`},
		{"online_agents", "count", `SELECT COUNT(*) FROM agents WHERE last_seen > NOW() - INTERVAL '10 minutes'`},
		{"open_alerts", "count", `SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved','false_positive','closed')`},
		{"alert_count", "count", `SELECT COUNT(*) FROM alerts WHERE created_at > NOW() - INTERVAL '24 hours'`},
		{"critical_alerts", "count", `SELECT COUNT(*) FROM alerts WHERE severity >= 8 AND created_at > NOW() - INTERVAL '24 hours'`},
		{"open_incidents", "count", `SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')`},
	}

	recorded := 0
	for _, m := range metrics {
		var v float64
		if err := c.pool.QueryRow(ctx, m.query).Scan(&v); err != nil {
			slog.Warn("SecurityMetricsCollector: 集計に失敗しました", "metric", m.name, "error", err)
			continue
		}
		if _, err := c.pool.Exec(ctx, `
			INSERT INTO security_metrics_history (metric_name, metric_value, metric_unit)
			VALUES ($1, $2, $3)
		`, m.name, v, m.unit); err != nil {
			slog.Warn("SecurityMetricsCollector: 記録に失敗しました", "metric", m.name, "error", err)
			continue
		}
		recorded++
	}
	slog.Info("SecurityMetricsCollector: スナップショット記録完了", "recorded", recorded, "total", len(metrics))
}

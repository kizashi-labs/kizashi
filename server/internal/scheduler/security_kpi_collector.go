package scheduler

import (
	"errors"

	"context"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// kpiSpec is a built-in security KPI: its definition plus the SQL that computes
// its current value from live data. Both seeding and collection are driven by
// this single list.
type kpiSpec struct {
	name        string
	description string
	category    string // detection, response, prevention, compliance, risk
	unit        string
	direction   string // higher=better, lower=better
	target      float64
	warning     float64
	valueQuery  string
}

// defaultKPISpecs are the KPIs seeded and auto-measured out of the box. They are
// all computable from existing tables (agents, alerts, incidents).
var defaultKPISpecs = []kpiSpec{
	{
		name: "エージェント稼働率", description: "オンラインのエージェント割合", category: "prevention", unit: "%",
		direction: "higher", target: 95, warning: 80,
		valueQuery: `SELECT CASE WHEN COUNT(*)=0 THEN 0
		             ELSE ROUND(100.0*COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '10 minutes')/COUNT(*),2) END
		             FROM agents`,
	},
	{
		name: "重大アラート未対応数", description: "深刻度8以上で未解決のアラート件数", category: "response", unit: "件",
		direction: "lower", target: 0, warning: 5,
		valueQuery: `SELECT COUNT(*) FROM alerts WHERE severity >= 8 AND status NOT IN ('resolved','false_positive','closed')`,
	},
	{
		name: "未対応インシデント数", description: "未解決のインシデント件数", category: "response", unit: "件",
		direction: "lower", target: 0, warning: 5,
		valueQuery: `SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')`,
	},
	{
		name: "アラート対応率", description: "過去7日のアラートのうち対応済みの割合", category: "response", unit: "%",
		direction: "higher", target: 90, warning: 70,
		valueQuery: `SELECT CASE WHEN COUNT(*)=0 THEN 100
		             ELSE ROUND(100.0*COUNT(*) FILTER (WHERE status IN ('resolved','false_positive','closed'))/COUNT(*),2) END
		             FROM alerts WHERE created_at > NOW() - INTERVAL '7 days'`,
	},
	{
		name: "平均初動対応時間", description: "過去7日に解決したアラートの平均対応時間（分）", category: "response", unit: "分",
		direction: "lower", target: 60, warning: 240,
		valueQuery: `SELECT COALESCE(ROUND(EXTRACT(EPOCH FROM AVG(resolved_at - created_at))/60.0,2),0)
		             FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at > NOW() - INTERVAL '7 days'`,
	},
	{
		name: "誤検知率", description: "過去7日のアラートのうち誤検知の割合", category: "detection", unit: "%",
		direction: "lower", target: 5, warning: 15,
		valueQuery: `SELECT CASE WHEN COUNT(*)=0 THEN 0
		             ELSE ROUND(100.0*COUNT(*) FILTER (WHERE status='false_positive')/COUNT(*),2) END
		             FROM alerts WHERE created_at > NOW() - INTERVAL '7 days'`,
	},
}

// SecurityKPICollector seeds the built-in KPI definitions and records a daily
// measurement for each one, so the KPI dashboard shows real, self-updating data
// instead of an empty table. Admin-defined KPIs are left untouched.
type SecurityKPICollector struct {
	pool     *pgxpool.Pool
	interval time.Duration
}

// NewSecurityKPICollector creates a collector. interval <= 0 defaults to 24h.
func NewSecurityKPICollector(pool *pgxpool.Pool, interval time.Duration) *SecurityKPICollector {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &SecurityKPICollector{pool: pool, interval: interval}
}

// Run seeds defaults, records an initial measurement shortly after start, then
// records one per interval.
func (c *SecurityKPICollector) Run(ctx context.Context) {
	slog.Info("SecurityKPICollector: 開始", "interval", c.interval)
	trackRun(ctx, "security_kpi_collector", c.seedDefaults)

	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
		trackRun(ctx, "security_kpi_collector", c.runOnce)
	}

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "security_kpi_collector", c.runOnce)
		}
	}
}

// seedDefaults inserts the built-in KPI definitions if absent (matched by name).
// It never overwrites an existing definition, so admin edits to targets persist.
func (c *SecurityKPICollector) seedDefaults(ctx context.Context) {
	seeded := 0
	for _, s := range defaultKPISpecs {
		// Explicit casts: $1 is used both in the SELECT list and the WHERE clause,
		// and a bare SELECT $1 gives Postgres no type to infer, which otherwise
		// fails with 42P08 "inconsistent types deduced for parameter $1".
		ct, err := c.pool.Exec(ctx, `
			INSERT INTO security_kpi_definitions
			    (name, description, category, unit, target_value, warning_threshold, direction, is_active)
			SELECT $1::varchar, $2::text, $3::varchar, $4::varchar, $5::numeric, $6::numeric, $7::varchar, true
			WHERE NOT EXISTS (SELECT 1 FROM security_kpi_definitions WHERE name=$1::varchar)
		`, s.name, s.description, s.category, s.unit, s.target, s.warning, s.direction)
		if err != nil {
			fail(ctx, err, "SecurityKPICollector: 既定KPIの登録に失敗しました", "kpi", s.name)
			continue
		}
		if ct.RowsAffected() > 0 {
			seeded++
		}
	}
	if seeded > 0 {
		slog.Info("SecurityKPICollector: 既定KPIを登録しました", "count", seeded)
	}
}

// runOnce computes and records today's measurement for each built-in KPI. One
// row per KPI per day: today's row is replaced so re-runs/restarts are idempotent.
func (c *SecurityKPICollector) runOnce(ctx context.Context) {
	recorded := 0
	for _, s := range defaultKPISpecs {
		var kpiID string
		if err := c.pool.QueryRow(ctx,
			`SELECT id FROM security_kpi_definitions WHERE name=$1 AND is_active=true LIMIT 1`,
			s.name).Scan(&kpiID); err != nil {
			// 管理者が無効にしたKPIと、定義を引けなかったKPIは別です。
			// 前者は意図した状態、後者は測れていない状態です。
			if !errors.Is(err, pgx.ErrNoRows) {
				fail(ctx, err, "SecurityKPICollector: KPI定義を引けませんでした", "kpi", s.name)
			}
			continue
		}

		var v float64
		if err := c.pool.QueryRow(ctx, s.valueQuery).Scan(&v); err != nil {
			fail(ctx, err, "SecurityKPICollector: 集計に失敗しました", "kpi", s.name)
			continue
		}

		tx, err := c.pool.Begin(ctx)
		if err != nil {
			fail(ctx, err, "SecurityKPICollector: トランザクションを開始できませんでした", "kpi", s.name)
			continue
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM security_kpi_measurements WHERE kpi_id=$1 AND period=CURRENT_DATE`, kpiID); err != nil {
			_ = tx.Rollback(ctx)
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO security_kpi_measurements (kpi_id, value, period, notes)
			 VALUES ($1,$2,CURRENT_DATE,$3)`, kpiID, v, "自動収集"); err != nil {
			_ = tx.Rollback(ctx)
			fail(ctx, err, "SecurityKPICollector: 記録に失敗しました", "kpi", s.name)
			continue
		}
		if err := tx.Commit(ctx); err != nil {
			fail(ctx, err, "SecurityKPICollector: 測定値を確定できませんでした", "kpi", s.name)
			continue
		}
		recorded++
	}
	slog.Info("SecurityKPICollector: 測定値を記録しました", "recorded", recorded, "total", len(defaultKPISpecs))
}

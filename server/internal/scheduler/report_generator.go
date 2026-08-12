package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReportGenerator runs scheduled reports based on the scheduled_reports table.
// It checks every 5 minutes for reports that are due to run.
type ReportGenerator struct {
	pool      *pgxpool.Pool
	reportDir string
}

// NewReportGenerator creates a ReportGenerator.
func NewReportGenerator(pool *pgxpool.Pool, reportDir string) *ReportGenerator {
	return &ReportGenerator{pool: pool, reportDir: reportDir}
}

// Run starts the generator ticker loop. Designed to be called as a goroutine.
func (g *ReportGenerator) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	slog.Info("レポートジェネレーター起動", "dir", g.reportDir)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.generate(ctx)
		}
	}
}

// scheduledReportRow holds one row from scheduled_reports.
type scheduledReportRow struct {
	id         string
	name       string
	reportType string
	config     []byte
	schedule   string
	format     string
	recipients []string
}

// generate queries the scheduled_reports table and processes any due reports.
func (g *ReportGenerator) generate(ctx context.Context) {
	// 1. Check if scheduled_reports table exists.
	var tableExists bool
	err := g.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'scheduled_reports'
		)`,
	).Scan(&tableExists)
	if err != nil || !tableExists {
		slog.Debug("scheduled_reportsテーブルが存在しないためレポート生成をスキップします")
		return
	}

	// 2. Introspect columns so we adapt gracefully to schema differences.
	cols, err := g.tableColumns(ctx, "scheduled_reports")
	if err != nil {
		slog.Warn("scheduled_reportsカラム情報の取得に失敗しました", "error", err)
		return
	}

	rows, err := g.queryDueReports(ctx, cols)
	if err != nil {
		slog.Warn("期限切れレポートのクエリに失敗しました", "error", err)
		return
	}

	if len(rows) == 0 {
		return
	}

	slog.Info("期限切れスケジュールレポートを処理します", "count", len(rows))
	for _, r := range rows {
		if err := g.processReport(ctx, r); err != nil {
			slog.Warn("レポート生成に失敗しました", "id", r.id, "name", r.name, "error", err)
		}
	}
}

// tableColumns returns the set of column names present in the given table.
func (g *ReportGenerator) tableColumns(ctx context.Context, tableName string) (map[string]bool, error) {
	rows, err := g.pool.Query(ctx,
		`SELECT column_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = $1`,
		tableName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]bool)
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			continue
		}
		cols[col] = true
	}
	return cols, rows.Err()
}

// queryDueReports builds a SELECT that uses only the columns we know exist,
// then returns the parsed rows.
func (g *ReportGenerator) queryDueReports(ctx context.Context, cols map[string]bool) ([]scheduledReportRow, error) {
	// Mandatory columns — if the table doesn't have even these we skip.
	if !cols["id"] || !cols["name"] {
		slog.Debug("scheduled_reportsに必須カラムがないためスキップします")
		return nil, nil
	}

	// Build SELECT list from available columns.
	selectCols := []string{"id::text", "name"}
	if cols["report_type"] {
		selectCols = append(selectCols, "report_type")
	} else {
		selectCols = append(selectCols, "''::text AS report_type")
	}
	if cols["config"] {
		selectCols = append(selectCols, "config")
	} else {
		selectCols = append(selectCols, "NULL::jsonb AS config")
	}
	if cols["schedule"] {
		selectCols = append(selectCols, "schedule")
	} else if cols["frequency"] {
		selectCols = append(selectCols, "frequency AS schedule")
	} else {
		selectCols = append(selectCols, "'daily'::text AS schedule")
	}
	if cols["format"] {
		selectCols = append(selectCols, "format")
	} else {
		selectCols = append(selectCols, "'txt'::text AS format")
	}
	if cols["recipients"] {
		selectCols = append(selectCols, "recipients")
	} else {
		selectCols = append(selectCols, "ARRAY[]::text[] AS recipients")
	}

	// Build WHERE clause.
	var whereFragments []string
	if cols["enabled"] {
		whereFragments = append(whereFragments, "enabled = true")
	}
	if cols["next_run_at"] {
		whereFragments = append(whereFragments, "(next_run_at IS NULL OR next_run_at <= NOW())")
	}

	where := ""
	if len(whereFragments) > 0 {
		where = "WHERE " + strings.Join(whereFragments, " AND ")
	}

	query := fmt.Sprintf(
		`SELECT %s FROM scheduled_reports %s LIMIT 10`,
		strings.Join(selectCols, ", "),
		where,
	)

	pgRows, err := g.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("scheduled_reportsクエリ失敗: %w", err)
	}
	defer pgRows.Close()

	var result []scheduledReportRow
	for pgRows.Next() {
		var r scheduledReportRow
		var configRaw []byte
		if err := pgRows.Scan(
			&r.id,
			&r.name,
			&r.reportType,
			&configRaw,
			&r.schedule,
			&r.format,
			&r.recipients,
		); err != nil {
			slog.Warn("scheduled_reportsのスキャンに失敗しました", "error", err)
			continue
		}
		r.config = configRaw
		result = append(result, r)
	}
	return result, pgRows.Err()
}

// processReport generates a file for one scheduled report and updates the DB.
func (g *ReportGenerator) processReport(ctx context.Context, r scheduledReportRow) error {
	// Ensure the output directory exists.
	if err := os.MkdirAll(g.reportDir, 0755); err != nil {
		return fmt.Errorf("レポートディレクトリの作成に失敗しました: %w", err)
	}

	ext := r.format
	if ext == "" {
		ext = "txt"
	}
	safeName := strings.NewReplacer(" ", "_", "/", "_", "\\", "_").Replace(r.name)
	filename := fmt.Sprintf("report_%s_%s.%s",
		safeName,
		time.Now().UTC().Format("20060102_150405"),
		ext,
	)
	outPath := filepath.Join(g.reportDir, filename)

	// Build report content.
	content, err := g.buildReportContent(ctx, r)
	if err != nil {
		return fmt.Errorf("レポート内容の生成に失敗しました: %w", err)
	}

	if err := os.WriteFile(outPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("レポートファイルの書き込みに失敗しました: %w", err)
	}
	slog.Info("レポートファイルを生成しました", "path", outPath)

	// Update next_run_at.
	next := computeNextRunFromSchedule(r.schedule, time.Now().UTC())
	_, _ = g.pool.Exec(ctx,
		`UPDATE scheduled_reports SET next_run_at = $1 WHERE id = $2`,
		next, r.id,
	)

	// Insert into reports table if it exists.
	g.insertReportRecord(ctx, r.name, outPath)

	return nil
}

// buildReportContent assembles the text report body.
func (g *ReportGenerator) buildReportContent(ctx context.Context, r scheduledReportRow) (string, error) {
	var sb strings.Builder
	now := time.Now().UTC()

	// Header section.
	sb.WriteString("========================================\n")
	sb.WriteString("  EDR PLATFORM — SCHEDULED REPORT\n")
	sb.WriteString("========================================\n")
	sb.WriteString(fmt.Sprintf("  Report Name : %s\n", r.name))
	sb.WriteString(fmt.Sprintf("  Type        : %s\n", r.reportType))
	sb.WriteString(fmt.Sprintf("  Generated At: %s\n", now.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Period      : Last 24 hours (ending %s)\n", now.Format("2006-01-02 15:04 UTC")))
	if len(r.config) > 0 && r.config != nil {
		var cfgMap map[string]interface{}
		if json.Unmarshal(r.config, &cfgMap) == nil && len(cfgMap) > 0 {
			sb.WriteString(fmt.Sprintf("  Config      : %s\n", string(r.config)))
		}
	}
	sb.WriteString("========================================\n\n")

	// Summary stats section.
	sb.WriteString("SUMMARY STATISTICS\n")
	sb.WriteString("──────────────────────────────────────\n")

	var alertCount int
	_ = g.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours'`,
	).Scan(&alertCount)
	sb.WriteString(fmt.Sprintf("  Alerts (last 24h)  : %d\n", alertCount))

	var agentCount int
	_ = g.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&agentCount)
	sb.WriteString(fmt.Sprintf("  Total Agents       : %d\n", agentCount))

	var onlineCount int
	_ = g.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM agents WHERE status = 'online'`,
	).Scan(&onlineCount)
	sb.WriteString(fmt.Sprintf("  Online Agents      : %d\n", onlineCount))

	var criticalCount int
	_ = g.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at >= NOW() - INTERVAL '24 hours'`,
	).Scan(&criticalCount)
	sb.WriteString(fmt.Sprintf("  Critical Alerts    : %d\n", criticalCount))
	sb.WriteString("\n")

	// Recent alerts table.
	sb.WriteString("RECENT ALERTS (last 50)\n")
	sb.WriteString("──────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("%-36s  %-10s  %-8s  %-24s  %s\n",
		"ID", "SEVERITY", "STATUS", "CREATED AT", "TITLE"))
	sb.WriteString(strings.Repeat("-", 110) + "\n")

	alertRows, err := g.pool.Query(ctx,
		`SELECT id::text, COALESCE(severity,''), COALESCE(status,''), created_at, COALESCE(title,'')
		 FROM alerts
		 ORDER BY created_at DESC
		 LIMIT 50`,
	)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var id, severity, status, title string
			var createdAt time.Time
			if scanErr := alertRows.Scan(&id, &severity, &status, &createdAt, &title); scanErr != nil {
				continue
			}
			// Truncate long titles.
			if len(title) > 40 {
				title = title[:37] + "..."
			}
			sb.WriteString(fmt.Sprintf("%-36s  %-10s  %-8s  %-24s  %s\n",
				id, severity, status, createdAt.UTC().Format("2006-01-02 15:04:05"), title))
		}
	} else {
		sb.WriteString("  (アラートデータを取得できませんでした)\n")
	}
	sb.WriteString("\n")
	sb.WriteString("========================================\n")
	sb.WriteString("  EDR Platform 自動レポートシステム\n")
	sb.WriteString("========================================\n")

	return sb.String(), nil
}

// computeNextRunFromSchedule advances t by the interval implied by schedule.
func computeNextRunFromSchedule(schedule string, t time.Time) time.Time {
	switch strings.ToLower(schedule) {
	case "weekly":
		return t.Add(7 * 24 * time.Hour)
	case "monthly":
		return t.Add(30 * 24 * time.Hour)
	default: // "daily" and anything else
		return t.Add(24 * time.Hour)
	}
}

// insertReportRecord inserts a row into the reports table if it exists.
func (g *ReportGenerator) insertReportRecord(ctx context.Context, name, filePath string) {
	var exists bool
	_ = g.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'reports'
		)`,
	).Scan(&exists)
	if !exists {
		return
	}

	_, err := g.pool.Exec(ctx,
		`INSERT INTO reports (name, file_path, generated_at)
		 VALUES ($1, $2, NOW())`,
		name, filePath,
	)
	if err != nil {
		slog.Debug("reportsテーブルへの挿入に失敗しました", "error", err)
	}
}

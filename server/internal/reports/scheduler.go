package reports

// ScheduledReport manages periodic report generation and delivery.

import (
	"bytes"
	"context"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"html"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/email"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"

	"github.com/edr-platform/server/internal/tick"
)

// ScheduledReport defines a repeating report job.
type ScheduledReport struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	ReportType string     `json:"report_type"`
	Schedule   string     `json:"schedule"`   // cron: "0 8 * * 1" = every Monday 8am
	Format     string     `json:"format"`     // json/csv
	Recipients []string   `json:"recipients"` // email addresses
	Enabled    bool       `json:"enabled"`
	LastRun    *time.Time `json:"last_run"`
	NextRun    time.Time  `json:"next_run"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Scheduler manages scheduled report jobs.
type Scheduler struct {
	mu        sync.RWMutex
	pool      *pgxpool.Pool
	generator *Generator
	mailer    *email.Sender
	reports   []*ScheduledReport
}

// NewScheduler creates a new Scheduler.
func NewScheduler(pool *pgxpool.Pool, generator *Generator, mailer *email.Sender) *Scheduler {
	return &Scheduler{
		pool:      pool,
		generator: generator,
		mailer:    mailer,
		reports:   []*ScheduledReport{},
	}
}

// parseCron parses a simplified cron expression "0 H * * D" where
// H is the hour (0-23) and D is day-of-week (0=Sunday, 1=Monday … 6=Saturday).
// Returns the next scheduled time after now.
func parseCron(expr string) (time.Time, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return time.Time{}, fmt.Errorf("cron: expected 5 fields, got %d", len(parts))
	}

	// Only support "0 H * * D" format
	if parts[0] != "0" {
		return time.Time{}, fmt.Errorf("cron: only minute=0 is supported")
	}
	if parts[2] != "*" || parts[3] != "*" {
		return time.Time{}, fmt.Errorf("cron: only wildcard month/dom supported")
	}

	hour, err := strconv.Atoi(parts[1])
	if err != nil || hour < 0 || hour > 23 {
		return time.Time{}, fmt.Errorf("cron: invalid hour %q", parts[1])
	}

	// day-of-week: 0-6 or "*" (any)
	dow := -1 // -1 means any day
	if parts[4] != "*" {
		dow, err = strconv.Atoi(parts[4])
		if err != nil || dow < 0 || dow > 6 {
			return time.Time{}, fmt.Errorf("cron: invalid day-of-week %q", parts[4])
		}
	}

	now := time.Now().UTC()
	// Start from the next hour boundary
	candidate := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)

	// Advance to today if we haven't passed the hour yet, otherwise tomorrow
	if !candidate.After(now) {
		candidate = candidate.Add(24 * time.Hour)
	}

	// Find the next day that matches day-of-week (if restricted)
	if dow >= 0 {
		for int(candidate.Weekday()) != dow {
			candidate = candidate.Add(24 * time.Hour)
		}
	}

	return candidate, nil
}

// isDue returns true if the schedule should fire at the given time.
func isDue(schedule *ScheduledReport, now time.Time) bool {
	if !schedule.Enabled {
		return false
	}
	return !schedule.NextRun.After(now)
}

// AddSchedule persists a scheduled report and registers it with the scheduler.
func (s *Scheduler) AddSchedule(ctx context.Context, report *ScheduledReport) error {
	if report.ID == "" {
		report.ID = uuid.New().String()
	}
	if report.Format == "" {
		report.Format = "json"
	}
	if report.Recipients == nil {
		report.Recipients = []string{}
	}
	report.CreatedAt = time.Now().UTC()

	// Compute next run
	nextRun, err := parseCron(report.Schedule)
	if err != nil {
		return fmt.Errorf("スケジュールの解析に失敗しました: %w", err)
	}
	report.NextRun = nextRun

	s.mu.Lock()
	s.reports = append(s.reports, report)
	s.mu.Unlock()

	// Persist to DB if available
	if s.pool != nil {
		tableExists := store.TableIsThere(ctx, s.pool, "scheduled_reports")
		if tableExists {
			_, err = s.pool.Exec(ctx, `
				INSERT INTO scheduled_reports (id, name, report_type, schedule, format, recipients,
				                               enabled, next_run, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`,
				report.ID, report.Name, report.ReportType, report.Schedule, report.Format,
				report.Recipients, report.Enabled, report.NextRun, report.CreatedAt)
			if err != nil {
				slog.Warn("scheduler: failed to persist schedule", "id", report.ID, "error", err)
			}
		}
	}

	slog.Info("scheduler: added schedule", "id", report.ID, "name", report.Name, "next_run", report.NextRun)
	return nil
}

// RemoveSchedule removes a scheduled report by ID.
func (s *Scheduler) RemoveSchedule(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	newReports := make([]*ScheduledReport, 0, len(s.reports))
	for _, r := range s.reports {
		if r.ID == id {
			found = true
		} else {
			newReports = append(newReports, r)
		}
	}
	if !found {
		return fmt.Errorf("スケジュール %s が見つかりません", id)
	}

	// **DB を先に消します。**
	//
	// 記憶から先に消して DELETE を捨てていました。消えたように見えて、
	// **次の再起動で読み直され、また配信が始まります。** 順序を入れ替えて
	// あるのは、書けなかったときに記憶と DB を食い違わせないためです ——
	// 消せなかったなら、消えていないと答えます。
	if s.pool != nil && store.TableIsThere(ctx, s.pool, "scheduled_reports") {
		if _, err := s.pool.Exec(ctx, `DELETE FROM scheduled_reports WHERE id = $1`, id); err != nil {
			return fmt.Errorf("スケジュールを削除できませんでした（再起動で戻ります）: %w", err)
		}
	}
	s.reports = newReports
	slog.Info("scheduler: removed schedule", "id", id)
	return nil
}

// ListSchedules returns all registered scheduled reports.
func (s *Scheduler) ListSchedules(ctx context.Context) ([]*ScheduledReport, error) {
	// Try to load from DB first
	if s.pool != nil {
		tableExists := store.TableIsThere(ctx, s.pool, "scheduled_reports")
		if tableExists {
			rows, err := s.pool.Query(ctx, `
				SELECT id, name, report_type, schedule, format,
				       COALESCE(recipients,'{}'), enabled, last_run, next_run, created_at
				FROM scheduled_reports ORDER BY created_at DESC`)
			if err == nil {
				var dbReports []*ScheduledReport
				defer rows.Close()
				for rows.Next() {
					r := &ScheduledReport{}
					if err := rows.Scan(&r.ID, &r.Name, &r.ReportType, &r.Schedule, &r.Format,
						&r.Recipients, &r.Enabled, &r.LastRun, &r.NextRun, &r.CreatedAt); err == nil {
						dbReports = append(dbReports, r)
					}
				}
				if err := rows.Err(); err != nil {
					return nil, err
				}
				if dbReports != nil {
					return dbReports, nil
				}
				return []*ScheduledReport{}, nil
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.reports == nil {
		return []*ScheduledReport{}, nil
	}
	cp := make([]*ScheduledReport, len(s.reports))
	copy(cp, s.reports)
	return cp, nil
}

// UpdateSchedule updates an existing scheduled report.
func (s *Scheduler) UpdateSchedule(ctx context.Context, report *ScheduledReport) error {
	nextRun, err := parseCron(report.Schedule)
	if err != nil {
		return fmt.Errorf("スケジュールの解析に失敗しました: %w", err)
	}
	report.NextRun = nextRun

	// **DB を先に書きます。** 記憶だけ書き換えて UPDATE を捨てると、
	// 名前も宛先も次回実行も、次の再起動で古い値に戻ります。
	if s.pool != nil && store.TableIsThere(ctx, s.pool, "scheduled_reports") {
		if _, err := s.pool.Exec(ctx, `
				UPDATE scheduled_reports SET
					name=$2, report_type=$3, schedule=$4, format=$5,
					recipients=$6, enabled=$7, next_run=$8, updated_at=NOW()
				WHERE id=$1`,
			report.ID, report.Name, report.ReportType, report.Schedule, report.Format,
			report.Recipients, report.Enabled, report.NextRun); err != nil {
			return fmt.Errorf("スケジュールを更新できませんでした（再起動で戻ります）: %w", err)
		}
	}

	s.mu.Lock()
	for i, r := range s.reports {
		if r.ID == report.ID {
			s.reports[i] = report
			break
		}
	}
	s.mu.Unlock()
	return nil
}

// ToggleSchedule enables or disables a scheduled report.
func (s *Scheduler) ToggleSchedule(ctx context.Context, id string, enabled bool) error {
	// **DB を先に書きます。** 止めたはずのレポートが、再起動でまた
	// 有効になります —— 画面は記憶を映すので、止まったように見えます。
	if s.pool != nil && store.TableIsThere(ctx, s.pool, "scheduled_reports") {
		if _, err := s.pool.Exec(ctx,
			`UPDATE scheduled_reports SET enabled=$2, updated_at=NOW() WHERE id=$1`,
			id, enabled); err != nil {
			return fmt.Errorf("スケジュールの有効・無効を切り替えられませんでした（再起動で戻ります）: %w", err)
		}
	}

	s.mu.Lock()
	for _, r := range s.reports {
		if r.ID == id {
			r.Enabled = enabled
			break
		}
	}
	s.mu.Unlock()
	return nil
}

// Run is the main scheduler loop. Should be called as a goroutine.
// Every minute it checks for due schedules and generates their reports.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("scheduler: starting report scheduler")
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler: stopping")
			return
		case now := <-ticker.C:
			tick.Run(ctx, "report_scheduler", func(ctx context.Context) { s.checkAndRun(ctx, now) })
		}
	}
}

// checkAndRun finds due schedules and executes them.
func (s *Scheduler) checkAndRun(ctx context.Context, now time.Time) {
	s.mu.RLock()
	due := make([]*ScheduledReport, 0)
	for _, r := range s.reports {
		if isDue(r, now) {
			cp := *r
			due = append(due, &cp)
		}
	}
	s.mu.RUnlock()

	for _, r := range due {
		go s.runReport(ctx, r, now)
	}
}

// runReport generates a single scheduled report and logs the result.
func (s *Scheduler) runReport(ctx context.Context, r *ScheduledReport, now time.Time) {
	slog.Info("scheduler: running scheduled report", "id", r.ID, "name", r.Name, "type", r.ReportType)

	spec := &ReportSpec{
		ID:     r.ID,
		Type:   r.ReportType,
		Title:  r.Name,
		Format: r.Format,
		DateRange: DateRange{
			Start: now.Add(-7 * 24 * time.Hour),
			End:   now,
		},
	}

	result, err := s.generator.Generate(ctx, spec)
	if err != nil {
		tick.Fail(ctx, err, "scheduler: report generation failed", "id", r.ID)
	} else {
		slog.Info("scheduler: report generated",
			"id", r.ID, "name", r.Name,
			"size_bytes", result.FileSizeBytes,
			"format", r.Format)
	}

	// Send the report to each recipient via SMTP (gracefully skips if SMTP is not configured).
	for _, recipient := range r.Recipients {
		if err := s.sendReportEmail(ctx, recipient, r, result); err != nil {
			tick.Fail(ctx, err, "scheduler: レポートメール送信に失敗しました",
				"id", r.ID, "recipient", recipient)
		} else {
			slog.Info("scheduler: レポートメールを送信しました",
				"id", r.ID, "recipient", recipient)
		}
	}

	// Update last_run and compute next_run
	nextRun, err := parseCron(r.Schedule)
	if err != nil {
		tick.Fail(ctx, err, "scheduler: failed to compute next run", "id", r.ID)
		nextRun = now.Add(24 * time.Hour)
	}

	s.mu.Lock()
	for _, sr := range s.reports {
		if sr.ID == r.ID {
			sr.LastRun = &now
			sr.NextRun = nextRun
			break
		}
	}
	s.mu.Unlock()

	if s.pool != nil {
		tableExists := store.TableIsThere(ctx, s.pool, "scheduled_reports")
		if tableExists {
			// **記憶の側は上で進めてあります。** ここが書けないと、
			// 次の再起動で `last_run`／`next_run` が古いまま読み直され、
			// **同じ期間のレポートをもう一度送ります。**
			if _, err := s.pool.Exec(ctx, `
				UPDATE scheduled_reports SET last_run=$2, next_run=$3, updated_at=NOW() WHERE id=$1`,
				r.ID, now, nextRun); err != nil {
				tick.Fail(ctx, err, "scheduler: 実行時刻を記録できませんでした。再起動後に同じレポートをもう一度送ります",
					"id", r.ID)
			}
		}
	}
}

// sendReportEmail sends a single report notification email. It is a no-op when
// the mailer is nil (i.e. SMTP_HOST is not configured).
func (s *Scheduler) sendReportEmail(ctx context.Context, recipient string, r *ScheduledReport, result *ReportResult) error {
	if s.mailer == nil {
		slog.Debug("scheduler: SMTPが未設定のためメール送信をスキップします",
			"recipient", recipient, "report_id", r.ID)
		return nil
	}

	var buf bytes.Buffer
	buf.WriteString("<html><body>")
	buf.WriteString(fmt.Sprintf("<h2>%s</h2>", html.EscapeString(r.Name)))
	buf.WriteString(fmt.Sprintf("<p>レポートタイプ: <strong>%s</strong></p>", html.EscapeString(r.ReportType)))
	buf.WriteString(fmt.Sprintf("<p>生成日時: %s</p>", time.Now().UTC().Format("2006-01-02 15:04 UTC")))
	if result != nil {
		buf.WriteString(fmt.Sprintf("<p>ファイルサイズ: %d bytes</p>", result.FileSizeBytes))
	}
	buf.WriteString("<p>このメールは Kizashi スケジュールレポートシステムから自動送信されました。</p>")
	buf.WriteString("</body></html>")

	subject := fmt.Sprintf("[Kizashi] スケジュールレポート: %s", r.Name)
	return s.mailer.Send(ctx, recipient, subject, buf.String())
}

// LoadFromDB loads schedules persisted in the DB at startup.
func (s *Scheduler) LoadFromDB(ctx context.Context) {
	if s.pool == nil {
		return
	}
	tableExists := store.TableIsThere(ctx, s.pool, "scheduled_reports")
	if !tableExists {
		return
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, report_type, schedule, format,
		       COALESCE(recipients,'{}'), enabled, last_run, next_run, created_at
		FROM scheduled_reports WHERE enabled = true ORDER BY created_at`)
	if err != nil {
		metrics.BackgroundFailed("report_scheduler_load", err, "scheduler: failed to load from DB")
		return
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		r := &ScheduledReport{}
		if err := rows.Scan(&r.ID, &r.Name, &r.ReportType, &r.Schedule, &r.Format,
			&r.Recipients, &r.Enabled, &r.LastRun, &r.NextRun, &r.CreatedAt); err == nil {
			s.reports = append(s.reports, r)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("レポートスケジュールの読み込みが途中で終わりました。読めなかったスケジュールは実行されません", "error", err)
	}
	slog.Info("scheduler: loaded schedules from DB", "count", len(s.reports))
}

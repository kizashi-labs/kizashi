package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DataRetentionCleaner は古いデータを定期的に削除してDBサイズを管理する。
//   - alerts: resolved/false_positive で保持期間を超えたものを削除
//   - playbook_runs: 古い実行ログを削除
//   - darkweb_findings: 古い検知結果を削除
type DataRetentionCleaner struct {
	auditRetainDays    int // 0 = 監査ログは消さない（既定）
	pool               *pgxpool.Pool
	alertRetainDays    int // resolved/false_positive アラートの保持日数（デフォルト90）
	playbookRetainDays int // playbook実行ログの保持日数（デフォルト180）
	darkwebRetainDays  int // ダークウェブ検知結果の保持日数（デフォルト365）
}

// NewDataRetentionCleaner はクリーナーを生成する。
// 各保持日数は 0 を指定するとデフォルト値が使用される。
// WithAuditRetention sets audit_logs retention in days. 0 disables deletion.
//
// 監査ログの削除は既定で**無効**。監査は「その期間に何も無かった」ことの証拠に
// 使われるので、黙って消える既定にはしない。保持期間を決めるのは運用判断で、
// AUDIT_RETAIN_DAYS を明示的に設定したときだけ消す。
func (c *DataRetentionCleaner) WithAuditRetention(days int) *DataRetentionCleaner {
	c.auditRetainDays = days
	return c
}

func NewDataRetentionCleaner(pool *pgxpool.Pool, alertDays, playbookDays, darkwebDays int) *DataRetentionCleaner {
	if alertDays <= 0 {
		alertDays = 90
	}
	if playbookDays <= 0 {
		playbookDays = 180
	}
	if darkwebDays <= 0 {
		darkwebDays = 365
	}
	return &DataRetentionCleaner{
		pool:               pool,
		alertRetainDays:    alertDays,
		playbookRetainDays: playbookDays,
		darkwebRetainDays:  darkwebDays,
	}
}

// Run は毎日午前2:00にクリーンアップを実行する。
func (c *DataRetentionCleaner) Run(ctx context.Context) {
	slog.Info("DataRetentionCleaner: 開始",
		"alert_retain_days", c.alertRetainDays,
		"playbook_retain_days", c.playbookRetainDays,
	)

	// 起動後5分で初回実行（DB起動直後の負荷を避ける）
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
		trackRun(ctx, "data_retention_cleaner", c.runOnce)
	}

	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next.Sub(now)):
			trackRun(ctx, "data_retention_cleaner", c.runOnce)
		}
	}
}

func (c *DataRetentionCleaner) runOnce(ctx context.Context) {
	slog.Info("DataRetentionCleaner: クリーンアップ開始")
	c.cleanAlerts(ctx)
	c.cleanPlaybookRuns(ctx)
	c.cleanDarkwebFindings(ctx)
	c.cleanAuditLogs(ctx)
	slog.Info("DataRetentionCleaner: クリーンアップ完了")
}

// cleanAlerts は resolved/false_positive のアラートを保持期間後に削除する。
// open/investigating のアラートは削除しない。
func (c *DataRetentionCleaner) cleanAlerts(ctx context.Context) {
	cutoff := time.Now().AddDate(0, 0, -c.alertRetainDays)
	tag, err := c.pool.Exec(ctx, `
		DELETE FROM alerts
		WHERE status IN ('resolved', 'false_positive', 'closed')
		  AND updated_at < $1`,
		cutoff,
	)
	if err != nil {
		fail(ctx, err, "DataRetentionCleaner: アラート削除に失敗しました")
		return
	}
	deleted := tag.RowsAffected()
	if deleted > 0 {
		slog.Info("DataRetentionCleaner: 古いアラートを削除しました",
			"deleted", deleted,
			"older_than_days", c.alertRetainDays,
		)
	}
}

// cleanPlaybookRuns は古いPlaybook実行ログを削除する。
func (c *DataRetentionCleaner) cleanPlaybookRuns(ctx context.Context) {
	cutoff := time.Now().AddDate(0, 0, -c.playbookRetainDays)
	tag, err := c.pool.Exec(ctx, `
		DELETE FROM playbook_runs
		WHERE ran_at < $1`,
		cutoff,
	)
	if err != nil {
		fail(ctx, err, "DataRetentionCleaner: Playbook実行ログ削除に失敗しました")
		return
	}
	deleted := tag.RowsAffected()
	if deleted > 0 {
		slog.Info("DataRetentionCleaner: 古いPlaybook実行ログを削除しました",
			"deleted", deleted,
			"older_than_days", c.playbookRetainDays,
		)
	}
}

// cleanDarkwebFindings は古いダークウェブ検知結果を削除する。
func (c *DataRetentionCleaner) cleanDarkwebFindings(ctx context.Context) {
	cutoff := time.Now().AddDate(0, 0, -c.darkwebRetainDays)
	tag, err := c.pool.Exec(ctx, `
		DELETE FROM darkweb_findings
		WHERE found_at < $1`,
		cutoff,
	)
	if err != nil {
		fail(ctx, err, "DataRetentionCleaner: ダークウェブ検知結果削除に失敗しました")
		return
	}
	deleted := tag.RowsAffected()
	if deleted > 0 {
		slog.Info("DataRetentionCleaner: 古いダークウェブ検知結果を削除しました",
			"deleted", deleted,
			"older_than_days", c.darkwebRetainDays,
		)
	}
}

// cleanAuditLogs は AUDIT_RETAIN_DAYS が設定されているときだけ古い監査ログを消す。
func (c *DataRetentionCleaner) cleanAuditLogs(ctx context.Context) {
	if c.auditRetainDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -c.auditRetainDays)
	tag, err := c.pool.Exec(ctx, `
		DELETE FROM audit_logs
		WHERE created_at < $1`,
		cutoff,
	)
	if err != nil {
		fail(ctx, err, "DataRetentionCleaner: 監査ログ削除に失敗しました")
		return
	}
	if deleted := tag.RowsAffected(); deleted > 0 {
		slog.Info("DataRetentionCleaner: 古い監査ログを削除しました",
			"deleted", deleted,
			"older_than_days", c.auditRetainDays,
		)
	}
}

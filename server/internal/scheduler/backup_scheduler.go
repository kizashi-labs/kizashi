package scheduler

// BackupScheduler runs automatic database backups on a configurable interval.
// It uses pg_dump via exec.Command and stores backup metadata in the backups table.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/backup"
	"github.com/edr-platform/server/internal/metrics"
)

// pgDumpCompleteMarker is the trailer pg_dump writes at the end of a plain-format
// dump. Its presence proves the dump ran to completion rather than being truncated
// (disk full, killed mid-write), which pg_dump's exit code alone does not guarantee.
const pgDumpCompleteMarker = "PostgreSQL database dump complete"

// minBackupBytes is a floor below which a "successful" dump is treated as
// suspicious (an empty/near-empty file is never a real backup of this schema).
const minBackupBytes = 512

// BackupScheduler runs pg_dump on a configurable interval and tracks backup
// metadata in the backups table (if it exists).
type BackupScheduler struct {
	pool      *pgxpool.Pool
	backupDir string
	interval  time.Duration
}

// NewBackupScheduler creates a BackupScheduler.
func NewBackupScheduler(pool *pgxpool.Pool, backupDir string, interval time.Duration) *BackupScheduler {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &BackupScheduler{
		pool:      pool,
		backupDir: backupDir,
		interval:  interval,
	}
}

// Run starts the backup ticker loop. Designed to be called as a goroutine.
func (s *BackupScheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	slog.Info("バックアップスケジューラー起動", "interval", s.interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "backup_scheduler", s.runBackup)
		}
	}
}

// runBackup performs a single pg_dump backup cycle:
//  1. Inserts a pending backup record.
//  2. Runs pg_dump using the DATABASE_URL environment variable.
//  3. Verifies the dump is complete, then marks the record completed/failed.
//  4. Prunes records and files older than the 7 most recent backups.
//
// This used to open with a check that the backups table exists, returning at
// Debug level when it did not. No migration created that table, so the check
// was false on every cycle and pg_dump never ran — silently, for the life of
// the deployment. Migration 371 creates the table; the check is gone because a
// missing table is now a schema fault worth surfacing, not a state to tolerate.
func (s *BackupScheduler) runBackup(ctx context.Context) {
	// Ensure the backup directory exists.
	if err := os.MkdirAll(s.backupDir, 0750); err != nil {
		fail(ctx, err, "バックアップディレクトリの作成に失敗しました", "dir", s.backupDir)
		return
	}

	filename := fmt.Sprintf("backup_%s.sql", time.Now().UTC().Format("20060102_150405"))
	outPath := filepath.Join(s.backupDir, filename)

	// 1. Insert a pending record.
	var backupID string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO backups (filename, status, started_at)
		 VALUES ($1, $2, NOW())
		 RETURNING id::text`,
		filename, backup.StatusPending,
	).Scan(&backupID)
	if err != nil {
		fail(ctx, err, "バックアップレコードの挿入に失敗しました")
		return
	}

	// 2. Run pg_dump.
	dbURL := os.Getenv("DATABASE_URL")
	cmd := exec.CommandContext(ctx, "pg_dump", dbURL, "-f", outPath)
	pgErr := cmd.Run()

	if pgErr != nil {
		s.markFailed(ctx, backupID, "pg_dump: "+pgErr.Error())
		// **この回はバックアップを1つも取れていません。** DB の
		// backups 行には failed が残りますが、それを見に行く人が
		// いなければ、外から見えるのは「回った」だけです。
		fail(ctx, pgErr, "pg_dumpに失敗しました")
		return
	}

	// 2b. Verify integrity: pg_dump's exit code does not guarantee a complete file
	// (a dump truncated by a full disk or a kill can still exit 0). Reject a dump
	// that is empty or missing the completion marker so a corrupt backup is never
	// recorded as "completed" and discovered only during a restore.
	fileSize, verifyErr := verifyBackupIntegrity(outPath)
	if verifyErr != nil {
		s.markFailed(ctx, backupID, "integrity: "+verifyErr.Error())
		_ = os.Remove(outPath) // don't leave a corrupt file masquerading as a backup
		fail(ctx, verifyErr, "バックアップの整合性検証に失敗しました", "filename", filename)
		return
	}

	// 3. On verified success: record size, mark completed, publish SLO metrics.
	// **書けないと、取れたバックアップが「実行中」のまま残ります。**
	// しかも次の行で SLO の成功時刻を押すので、**記録は未完了なのに
	// 計測は成功**という食い違いになります。
	if _, err := s.pool.Exec(ctx,
		`UPDATE backups
		 SET status = $3, file_size_bytes = $1, finished_at = NOW(), updated_at = NOW()
		 WHERE id = $2`,
		fileSize, backupID, backup.StatusCompleted,
	); err != nil {
		fail(ctx, err, "バックアップの完了を記録できませんでした", "filename", filename)
		return
	}
	metrics.BackupLastSuccessTimestamp.Set(float64(time.Now().Unix()))
	slog.Info("バックアップ完了", "filename", filename, "size_bytes", fileSize)

	// 4. Retain only the last 7 backups — delete older records and their files.
	s.pruneOldBackups(ctx)
}

// markFailed records a backup as failed and increments the failure metric.
func (s *BackupScheduler) markFailed(ctx context.Context, backupID, reason string) {
	// **失敗の記録が書けないと、その失敗はどこにも残りません。**
	if _, err := s.pool.Exec(ctx,
		`UPDATE backups
		 SET status = $3, error_message = $1, finished_at = NOW(), updated_at = NOW()
		 WHERE id = $2`,
		reason, backupID, backup.StatusFailed,
	); err != nil {
		fail(ctx, err, "バックアップの失敗を記録できませんでした", "backup_id", backupID)
	}
	metrics.BackupFailures.Inc()
}

// verifyBackupIntegrity checks that a plain-format pg_dump file is non-trivial and
// ran to completion (ends with pg_dump's completion marker). Returns the file size
// on success. Reading only the tail keeps it cheap regardless of dump size.
func verifyBackupIntegrity(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	size := info.Size()
	if size < minBackupBytes {
		return size, fmt.Errorf("dump too small (%d bytes) — likely empty/truncated", size)
	}

	// #nosec G304 -- path is a server-generated backup filename under backupDir
	// (timestamped in runBackup), never user input.
	f, err := os.Open(path)
	if err != nil {
		return size, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Read the last chunk; the completion marker lives in the final few lines.
	const tail = 256
	readAt := size - tail
	if readAt < 0 {
		readAt = 0
	}
	buf := make([]byte, size-readAt)
	if _, err := f.ReadAt(buf, readAt); err != nil {
		return size, fmt.Errorf("read tail: %w", err)
	}
	if !bytes.Contains(buf, []byte(pgDumpCompleteMarker)) {
		return size, fmt.Errorf("missing pg_dump completion marker — dump truncated")
	}
	return size, nil
}

// pruneOldBackups keeps the 7 most recent backups and removes older ones from
// the database and the filesystem.
func (s *BackupScheduler) pruneOldBackups(ctx context.Context) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM backups
		 WHERE id IN (
		     SELECT id FROM backups
		     ORDER BY started_at DESC
		     OFFSET 7
		 )
		 RETURNING filename`,
	)
	if err != nil {
		fail(ctx, err, "古いバックアップの削除に失敗しました")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var filename string
		if scanErr := rows.Scan(&filename); scanErr != nil {
			continue
		}
		path := filepath.Join(s.backupDir, filename)
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			fail(ctx, rmErr, "バックアップファイルの削除に失敗しました", "path", path)
		} else {
			slog.Info("古いバックアップを削除しました", "filename", filename)
		}
	}
	if err := rows.Err(); err != nil {
		fail(ctx, err, "削除済みバックアップのファイル名を読み切れませんでした。DBの行は消えていますが、対応するファイルがディスクに残っている可能性があります")
	}
}

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
			s.runBackup(ctx)
		}
	}
}

// runBackup performs a single pg_dump backup cycle:
//  1. Checks that the backups table exists (skips gracefully if not).
//  2. Inserts a pending backup record.
//  3. Runs pg_dump using the DATABASE_URL environment variable.
//  4. Updates the record to completed/failed with file size / error message.
//  5. Prunes records and files older than the 7 most recent backups.
func (s *BackupScheduler) runBackup(ctx context.Context) {
	// 1. Verify the backups table exists — skip gracefully when it doesn't.
	var tableExists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'backups'
		)`,
	).Scan(&tableExists)
	if err != nil || !tableExists {
		slog.Debug("backupsテーブルが存在しないため自動バックアップをスキップします")
		return
	}

	// Ensure the backup directory exists.
	if err := os.MkdirAll(s.backupDir, 0750); err != nil {
		slog.Error("バックアップディレクトリの作成に失敗しました", "dir", s.backupDir, "error", err)
		return
	}

	filename := fmt.Sprintf("backup_%s.sql", time.Now().UTC().Format("20060102_150405"))
	outPath := filepath.Join(s.backupDir, filename)

	// 2. Insert a pending record.
	var backupID string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO backups (filename, status, started_at)
		 VALUES ($1, 'pending', NOW())
		 RETURNING id::text`,
		filename,
	).Scan(&backupID)
	if err != nil {
		slog.Error("バックアップレコードの挿入に失敗しました", "error", err)
		return
	}

	// 3. Run pg_dump.
	dbURL := os.Getenv("DATABASE_URL")
	cmd := exec.CommandContext(ctx, "pg_dump", dbURL, "-f", outPath)
	pgErr := cmd.Run()

	if pgErr != nil {
		s.markFailed(ctx, backupID, "pg_dump: "+pgErr.Error())
		slog.Error("pg_dumpに失敗しました", "error", pgErr)
		return
	}

	// 3b. Verify integrity: pg_dump's exit code does not guarantee a complete file
	// (a dump truncated by a full disk or a kill can still exit 0). Reject a dump
	// that is empty or missing the completion marker so a corrupt backup is never
	// recorded as "completed" and discovered only during a restore.
	fileSize, verifyErr := verifyBackupIntegrity(outPath)
	if verifyErr != nil {
		s.markFailed(ctx, backupID, "integrity: "+verifyErr.Error())
		_ = os.Remove(outPath) // don't leave a corrupt file masquerading as a backup
		slog.Error("バックアップの整合性検証に失敗しました", "filename", filename, "error", verifyErr)
		return
	}

	// 4. On verified success: record size, mark completed, publish SLO metrics.
	_, _ = s.pool.Exec(ctx,
		`UPDATE backups
		 SET status = 'completed', file_size_bytes = $1, finished_at = NOW(), updated_at = NOW()
		 WHERE id = $2`,
		fileSize, backupID,
	)
	metrics.BackupLastSuccessTimestamp.Set(float64(time.Now().Unix()))
	slog.Info("バックアップ完了", "filename", filename, "size_bytes", fileSize)

	// 5. Retain only the last 7 backups — delete older records and their files.
	s.pruneOldBackups(ctx)
}

// markFailed records a backup as failed and increments the failure metric.
func (s *BackupScheduler) markFailed(ctx context.Context, backupID, reason string) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE backups
		 SET status = 'failed', error_message = $1, finished_at = NOW(), updated_at = NOW()
		 WHERE id = $2`,
		reason, backupID,
	)
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
		slog.Debug("古いバックアップの削除に失敗しました", "error", err)
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
			slog.Warn("バックアップファイルの削除に失敗しました", "path", path, "error", rmErr)
		} else {
			slog.Info("古いバックアップを削除しました", "filename", filename)
		}
	}
}

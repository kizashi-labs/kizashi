package scheduler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/backup"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The NIST CSF Recover function was scored by asking whether a backup_schedules
// table existed and carried an enabled row:
//
//	SELECT COUNT(*) FROM information_schema.tables
//	WHERE table_schema='public' AND table_name='backup_schedules'
//
// Measured against a database built by running store.RunMigrations over all
// migrations: backup_schedules MISSING. No migration creates it and no code
// writes it, so the guard was false on every deployment and Recover was pinned
// at 30.0 — the floor — for every tenant for ever. Because NIST is the mean of
// five functions, that removed a fixed amount from every overall score, and no
// amount of diligent backing up could move it.
//
// It is scored from `backups` now, which BackupScheduler actually writes. These
// gates pin the three bands and, above all, that a real completed backup no
// longer scores the same as none at all.
//
// Every test here holds pg_advisory_lock(backup.EvidenceLockKey) as
// internal/backup/status.go requires: `go test ./...` runs packages
// concurrently against one database and internal/scorecard counts these same
// tables, so without the lock the two packages delete each other's fixtures.

// recoverFixture opens a pool, takes the evidence lock on a dedicated
// connection, and empties `backups` for the duration of one test.
func recoverFixture(t *testing.T) (*ComplianceScorer, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	// A dedicated connection: an advisory lock belongs to the session that took
	// it, and a pooled query could unlock from a different one.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, backup.EvidenceLockKey); err != nil {
		conn.Release()
		t.Fatalf("advisory lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, backup.EvidenceLockKey)
		conn.Release()
	})

	if _, err := pool.Exec(ctx, `DELETE FROM backups`); err != nil {
		t.Fatalf("clear backups: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM backups`)
	})

	return &ComplianceScorer{pool: pool}, pool
}

// seedBackup inserts one backup row that finished `age` ago.
func seedBackup(t *testing.T, pool *pgxpool.Pool, status string, age time.Duration) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO backups (filename, status, started_at, finished_at)
		VALUES ($1, $2, NOW() - $3::interval, NOW() - $3::interval)`,
		"recover-fixture-"+status, status, age.String()); err != nil {
		t.Fatalf("seed backup (%s, %s): %v", status, age, err)
	}
}

// With no backup on record at all, the floor is the honest answer.
func TestRecoverScoresTheFloorWhenNothingHasBeenBackedUp(t *testing.T) {
	s, _ := recoverFixture(t)

	if got := s.recoverScore(context.Background()); got != recoverScoreFloor {
		t.Errorf("バックアップ実績が無い場合のRecoverが %v、期待は %v", got, recoverScoreFloor)
	}
}

// This is the defect: a completed backup used to score identically to none.
func TestARecentCompletedBackupScoresAboveTheFloor(t *testing.T) {
	s, pool := recoverFixture(t)
	seedBackup(t, pool, backup.StatusCompleted, time.Hour)

	got := s.recoverScore(context.Background())
	if got == recoverScoreFloor {
		t.Fatalf("完了したバックアップがあるのにRecoverが下限 %v のままです。"+
			"これが backup_schedules を見ていたときの症状です", got)
	}
	if got != recoverScoreFresh {
		t.Errorf("直近の完了バックアップに対するRecoverが %v、期待は %v", got, recoverScoreFresh)
	}
}

// A backup that succeeded long ago is evidence of capability, not of a live
// one — it scores between the two.
func TestAStaleCompletedBackupScoresBetween(t *testing.T) {
	s, pool := recoverFixture(t)
	seedBackup(t, pool, backup.StatusCompleted, recoverFreshWindow+48*time.Hour)

	got := s.recoverScore(context.Background())
	if got != recoverScoreStale {
		t.Errorf("古い完了バックアップに対するRecoverが %v、期待は %v", got, recoverScoreStale)
	}
	if got >= recoverScoreFresh || got <= recoverScoreFloor {
		t.Errorf("古いバックアップのスコア %v が下限と上限の間にありません", got)
	}
}

// A failed or still-pending backup is not evidence that recovery is possible.
// StatusCompleted is written only after the dump passes its integrity check.
func TestOnlyCompletedBackupsCount(t *testing.T) {
	for _, status := range []string{backup.StatusFailed, backup.StatusPending} {
		t.Run(status, func(t *testing.T) {
			s, pool := recoverFixture(t)
			seedBackup(t, pool, status, time.Hour)

			if got := s.recoverScore(context.Background()); got != recoverScoreFloor {
				t.Errorf("status=%s のバックアップでRecoverが %v になりました。"+
					"完了していないバックアップは復旧可能性の証拠になりません", status, got)
			}
		})
	}
}

// The freshness boundary is the configured window, not an accident of rounding.
func TestTheFreshnessBoundaryIsTheConfiguredWindow(t *testing.T) {
	s, pool := recoverFixture(t)
	// Just inside the window.
	seedBackup(t, pool, backup.StatusCompleted, recoverFreshWindow-time.Hour)
	if got := s.recoverScore(context.Background()); got != recoverScoreFresh {
		t.Errorf("ウィンドウ内のバックアップが %v、期待は %v", got, recoverScoreFresh)
	}

	if _, err := pool.Exec(context.Background(), `DELETE FROM backups`); err != nil {
		t.Fatalf("clear: %v", err)
	}
	// Just outside it.
	seedBackup(t, pool, backup.StatusCompleted, recoverFreshWindow+time.Hour)
	if got := s.recoverScore(context.Background()); got != recoverScoreStale {
		t.Errorf("ウィンドウ外のバックアップが %v、期待は %v", got, recoverScoreStale)
	}
}

// The most recent completed backup decides the band, not the oldest.
func TestTheMostRecentCompletedBackupDecides(t *testing.T) {
	s, pool := recoverFixture(t)
	seedBackup(t, pool, backup.StatusCompleted, recoverFreshWindow+72*time.Hour)
	seedBackup(t, pool, backup.StatusCompleted, 2*time.Hour)

	if got := s.recoverScore(context.Background()); got != recoverScoreFresh {
		t.Errorf("最新の完了バックアップが直近なのに %v、期待は %v", got, recoverScoreFresh)
	}
}

// The bands must stay ordered and inside the 0-100 range the NIST mean assumes.
func TestTheRecoverBandsAreOrdered(t *testing.T) {
	if !(recoverScoreFloor < recoverScoreStale && recoverScoreStale < recoverScoreFresh) {
		t.Errorf("Recoverのバンドが順序どおりではありません: %v, %v, %v",
			recoverScoreFloor, recoverScoreStale, recoverScoreFresh)
	}
	for _, v := range []float64{recoverScoreFloor, recoverScoreStale, recoverScoreFresh} {
		if v < 0 || v > 100 {
			t.Errorf("Recoverのバンド %v が 0-100 の範囲外です", v)
		}
	}
}

// A scoring input that cannot be read must not become a confident score.
//
// The old code discarded its query errors with `_ =`, which is how a missing
// table became a silent 30.0 in the first place. The failure mode to guard
// against is the opposite one too: an unreadable backups table must not be
// scored as though a backup had just completed.
func TestAnUnreadableBackupsTableScoresTheFloorNotAGuess(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Closing the pool makes every query fail, standing in for any reason the
	// evidence cannot be read.
	pool.Close()

	s := &ComplianceScorer{pool: pool}
	got := s.recoverScore(context.Background())
	if got != recoverScoreFloor {
		t.Errorf("バックアップ実績を読めないのにRecoverが %v になりました。"+
			"読めなかったことを高いスコアの根拠にしてはいけません", got)
	}
}

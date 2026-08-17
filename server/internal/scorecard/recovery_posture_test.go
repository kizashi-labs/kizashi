package scorecard

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/backup"
)

// NIST CSF RC.RP-2 and ISO 27001 A.17.1.1–A.17.1.3 are the four controls that
// answer "are backups being taken?". All four counted
//
//	backup_manifests WHERE status = 'success'
//
// and nothing in this repository has ever written 'success': internal/backup
// writes 'completed', and so does the column default. Grepping the tree, the
// word appeared in exactly these two queries and nowhere else. The count was
// therefore structurally zero, and the four controls reported
// 30/non_compliant on every deployment regardless of the truth.
//
// Reproduced before the fix: a manifest inserted through the producer's own
// statement, then RC.RP-2 read back as
//
//	score=30 status=non_compliant evidence="0 successful backups in last 30 days"
//
// A wrong word in a WHERE clause returns no rows rather than an error, so a
// compliance report built on one is confidently, quietly wrong. These tests
// insert backups the way the two producers insert them and require the score to
// move.

func scorePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// lockBackupEvidence takes the cross-package advisory lock described on
// backup.EvidenceLockKey and holds it until the test ends. The scorer counts
// whole tables, so these tests must own them for their duration; internal/
// scheduler writes to `backups` from a package that runs concurrently.
func lockBackupEvidence(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, backup.EvidenceLockKey); err != nil {
		conn.Release()
		t.Fatalf("lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, backup.EvidenceLockKey)
		conn.Release()
	})
}

// clearBackupEvidence removes every row both evidence tables hold, so a test
// that asserts "no backups" is not reading another test's fixture. Safe only
// while the evidence lock is held.
func clearBackupEvidence(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, tbl := range []string{"backup_manifests", "backups"} {
		if _, err := pool.Exec(ctx, `DELETE FROM `+tbl); err != nil {
			t.Fatalf("clear %s: %v", tbl, err)
		}
	}
}

// insertManifest writes a backup_manifests row the way internal/backup does.
func insertManifest(t *testing.T, pool *pgxpool.Pool, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO backup_manifests (version, tables, record_count, size_bytes, status)
		 VALUES ('test', ARRAY['agents'], '{}'::jsonb, 4096, $1)`, status); err != nil {
		t.Fatalf("insert manifest: %v", err)
	}
}

// insertDump writes a backups row the way scheduler.BackupScheduler does.
func insertDump(t *testing.T, pool *pgxpool.Pool, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO backups (filename, status, file_size_bytes, finished_at)
		 VALUES ('scorecard-fixture.sql', $1, 8192, NOW())`, status); err != nil {
		t.Fatalf("insert dump: %v", err)
	}
}

// recoverControl runs the real Recover scoring and returns one control.
func recoverControl(t *testing.T, pool *pgxpool.Pool, id string) *Control {
	t.Helper()
	for _, c := range NewScorer(pool).scoreRecover(context.Background()) {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s not produced", id)
	return nil
}

// isoControl runs the real ISO scoring and returns one control.
func isoControl(t *testing.T, pool *pgxpool.Pool, id string) *Control {
	t.Helper()
	s := NewScorer(pool)
	controls := s.buildISO27001Controls(context.Background())
	s.scoreISO27001Controls(context.Background(), controls)
	for _, c := range controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s not produced", id)
	return nil
}

// TestASuccessfulConfigBackupIsCompliaceEvidence is the core gate: the exact
// row internal/backup writes has to satisfy the controls that ask about it.
func TestASuccessfulConfigBackupIsComplianceEvidence(t *testing.T) {
	pool := scorePool(t)
	lockBackupEvidence(t, pool)
	clearBackupEvidence(t, pool)
	insertManifest(t, pool, backup.StatusCompleted)
	t.Cleanup(func() { clearBackupEvidence(t, pool) })

	rc := recoverControl(t, pool, "RC.RP-2")
	if rc.Status == "non_compliant" {
		t.Errorf("RC.RP-2 is %s (score %.0f, evidence %q) with a completed backup "+
			"in the table. The control counts a status no producer writes, so it "+
			"reports non-compliance to the auditor no matter what the platform does.",
			rc.Status, rc.Score, rc.Evidence)
	}
	for _, id := range []string{"A.17.1.1", "A.17.1.2", "A.17.1.3"} {
		iso := isoControl(t, pool, id)
		if iso.Status == "non_compliant" {
			t.Errorf("%s is %s (score %.0f, evidence %q) with a completed backup",
				id, iso.Status, iso.Score, iso.Evidence)
		}
	}
}

// TestTheNightlyDumpIsAlsoComplianceEvidence. The pg_dump the scheduler runs is
// the platform's actual database backup; the config manifest is an export of a
// handful of settings tables. A deployment whose only backup is the nightly
// dump — the normal case — still reported nothing.
func TestTheNightlyDumpIsAlsoComplianceEvidence(t *testing.T) {
	pool := scorePool(t)
	lockBackupEvidence(t, pool)
	clearBackupEvidence(t, pool)
	insertDump(t, pool, backup.StatusCompleted)
	t.Cleanup(func() { clearBackupEvidence(t, pool) })

	rc := recoverControl(t, pool, "RC.RP-2")
	if rc.Status == "non_compliant" {
		t.Errorf("RC.RP-2 is %s (evidence %q): the nightly database dump is not "+
			"counted as a backup", rc.Status, rc.Evidence)
	}
}

// TestNoBackupsStillReportsNonCompliant is the floor. Without it the fix could
// be "always report compliant", which is the same lie in the other direction —
// and the worse one, because it tells an operator they are protected.
func TestNoBackupsStillReportsNonCompliant(t *testing.T) {
	pool := scorePool(t)
	lockBackupEvidence(t, pool)
	clearBackupEvidence(t, pool)
	t.Cleanup(func() { clearBackupEvidence(t, pool) })

	rc := recoverControl(t, pool, "RC.RP-2")
	if rc.Status != "non_compliant" {
		t.Errorf("RC.RP-2 is %s (score %.0f) with no backups at all", rc.Status, rc.Score)
	}
	iso := isoControl(t, pool, "A.17.1.1")
	if iso.Status == "compliant" {
		t.Errorf("A.17.1.1 is %s with no backups at all", iso.Status)
	}
}

// TestAFailedBackupIsNotEvidence. A failed dump is a row in the same table; if
// the count does not filter on status the controls go compliant precisely when
// backups are broken.
func TestAFailedBackupIsNotEvidence(t *testing.T) {
	pool := scorePool(t)
	lockBackupEvidence(t, pool)
	clearBackupEvidence(t, pool)
	insertDump(t, pool, backup.StatusFailed)
	insertManifest(t, pool, backup.StatusFailed)
	t.Cleanup(func() { clearBackupEvidence(t, pool) })

	rc := recoverControl(t, pool, "RC.RP-2")
	if rc.Status != "non_compliant" {
		t.Errorf("RC.RP-2 is %s (evidence %q) when every backup in the last 30 days "+
			"failed", rc.Status, rc.Evidence)
	}
}

// TestOldBackupsAreNotEvidence. "Backup and recovery procedures are tested" is a
// statement about the present; a dump from last year must not keep the control
// green.
func TestOldBackupsAreNotEvidence(t *testing.T) {
	pool := scorePool(t)
	lockBackupEvidence(t, pool)
	clearBackupEvidence(t, pool)
	t.Cleanup(func() { clearBackupEvidence(t, pool) })
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO backups (filename, status, started_at)
		 VALUES ('stale.sql', $1, NOW() - INTERVAL '400 days')`, backup.StatusCompleted); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO backup_manifests (version, status, created_at)
		 VALUES ('stale', $1, NOW() - INTERVAL '400 days')`, backup.StatusCompleted); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rc := recoverControl(t, pool, "RC.RP-2")
	if rc.Status != "non_compliant" {
		t.Errorf("RC.RP-2 is %s (evidence %q) when the newest backup is 400 days old",
			rc.Status, rc.Evidence)
	}
}

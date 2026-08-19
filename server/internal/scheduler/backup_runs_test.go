package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/backup"
)

// BackupScheduler opened every cycle with
//
//	SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'backups')
//
// and returned at Debug level when the answer was false. No migration created
// that table, so the answer was false on every cycle since the scheduler was
// written: pg_dump has never run. Reproduced against the migrated schema before
// migration 371 — a complete runBackup cycle wrote zero files and zero rows,
// logged nothing above Debug, and left the metrics untouched.
//
// A backup that silently never runs is discovered during the restore, which is
// the one moment it cannot be fixed. These tests drive the real cycle against a
// real database and assert a file exists on disk afterwards.

func backupPool(t *testing.T) *pgxpool.Pool {
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
// backup.EvidenceLockKey. internal/scorecard clears both evidence tables to
// assert "no backups → non_compliant", and that package runs concurrently with
// this one against the same database; without the lock it deletes the pending
// row a cycle here is about to update.
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

// backupRow is one row of the backups table, read back after a cycle.
type backupRow struct {
	filename string
	status   string
	size     *int64
	errMsg   *string
	finished *time.Time
}

// readBackupRows returns the rows this test's cycle wrote, identified by the
// filenames present in dir. Other packages run against the same database, so
// scoping by filename rather than counting the table keeps the assertion about
// this test's own work.
func readBackupRows(t *testing.T, pool *pgxpool.Pool, names []string) []backupRow {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT filename, status, file_size_bytes, error_message, finished_at
		   FROM backups WHERE filename = ANY($1)`, names)
	if err != nil {
		t.Fatalf("read backups: %v", err)
	}
	defer rows.Close()
	var out []backupRow
	for rows.Next() {
		var r backupRow
		if err := rows.Scan(&r.filename, &r.status, &r.size, &r.errMsg, &r.finished); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// fakePgDump puts a script named pg_dump at the front of PATH so the cycle can
// be driven without depending on the real binary's version or on the test
// database being dumpable. body is a shell script; "$3" is the output path
// because runBackup invokes `pg_dump <url> -f <path>`.
func fakePgDump(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pg_dump"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake pg_dump: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// cleanupBackups removes this test's rows so the table does not grow across runs
// and so pruneOldBackups in another test is not counting our leftovers.
func cleanupBackups(t *testing.T, pool *pgxpool.Pool, names []string) {
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM backups WHERE filename = ANY($1)`, names)
	})
}

// dirFiles lists the plain files in dir.
func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestABackupCycleActuallyProducesABackup is the core gate: it fails on any
// build where the backups table is missing or the skip-if-absent guard is back,
// because both make the cycle return before pg_dump is reached.
func TestABackupCycleActuallyProducesABackup(t *testing.T) {
	pool := backupPool(t)
	lockBackupEvidence(t, pool)
	// A dump large enough to clear minBackupBytes and carrying the completion
	// marker, i.e. what a healthy pg_dump produces.
	fakePgDump(t, `printf '%0.s-' $(seq 1 1000) > "$3"; echo "" >> "$3"; echo "-- PostgreSQL database dump complete" >> "$3"`)

	dir := t.TempDir()
	t.Setenv("DATABASE_URL", os.Getenv("TEST_DATABASE_URL"))
	NewBackupScheduler(pool, dir, time.Hour).runBackup(context.Background())

	files := dirFiles(t, dir)
	if len(files) == 0 {
		t.Fatal("a complete backup cycle produced no file. The scheduler returned " +
			"before pg_dump — the nightly backup does not exist, and nothing in the " +
			"logs or the metrics says so.")
	}
	cleanupBackups(t, pool, files)

	rows := readBackupRows(t, pool, files)
	if len(rows) != 1 {
		t.Fatalf("got %d backup rows for %v, want 1", len(rows), files)
	}
	if rows[0].status != backup.StatusCompleted {
		t.Errorf("status = %q, want %q — a verified dump was not recorded as evidence",
			rows[0].status, backup.StatusCompleted)
	}
	if rows[0].size == nil || *rows[0].size <= 0 {
		t.Error("file_size_bytes was not recorded, so nothing downstream can tell a " +
			"real dump from an empty one")
	}
	if rows[0].finished == nil {
		t.Error("finished_at was not recorded, so backup age cannot be monitored")
	}
}

// TestATruncatedDumpIsNotRecordedAsABackup. pg_dump can exit 0 having written a
// partial file (disk full, killed mid-write). Recording that as completed is
// worse than recording nothing: it is the row an operator reads before deciding
// they are safe to restore.
func TestATruncatedDumpIsNotRecordedAsABackup(t *testing.T) {
	pool := backupPool(t)
	lockBackupEvidence(t, pool)
	// Large enough to pass the size floor, but with no completion marker.
	fakePgDump(t, `printf '%0.s-' $(seq 1 1000) > "$3"; exit 0`)

	dir := t.TempDir()
	t.Setenv("DATABASE_URL", os.Getenv("TEST_DATABASE_URL"))
	NewBackupScheduler(pool, dir, time.Hour).runBackup(context.Background())

	// The row is keyed on the filename the cycle chose; the file itself is
	// deliberately deleted, so recover the name from the table by timestamp.
	names := recentFilenames(t, pool)
	cleanupBackups(t, pool, names)
	rows := readBackupRows(t, pool, names)
	if len(rows) != 1 {
		t.Fatalf("got %d backup rows, want 1", len(rows))
	}
	if rows[0].status != backup.StatusFailed {
		t.Errorf("a dump missing pg_dump's completion marker was recorded as %q",
			rows[0].status)
	}
	if rows[0].errMsg == nil || !strings.Contains(*rows[0].errMsg, "integrity") {
		t.Errorf("error_message = %v, want the integrity failure so an operator "+
			"can see why", rows[0].errMsg)
	}
	if files := dirFiles(t, dir); len(files) != 0 {
		t.Errorf("the corrupt dump %v was left on disk, where it looks like a backup", files)
	}
}

// recentFilenames returns backups rows created in the last minute — this test's
// own, since no other test in this package writes to the table.
func recentFilenames(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT filename FROM backups WHERE started_at > NOW() - INTERVAL '1 minute'`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, f)
	}
	return out
}

// TestAFailedDumpIsRecordedAsFailed covers the other arm: pg_dump itself
// erroring. Both arms have to reach the table, or a failing backup is
// indistinguishable from one that never started.
func TestAFailedDumpIsRecordedAsFailed(t *testing.T) {
	pool := backupPool(t)
	lockBackupEvidence(t, pool)
	fakePgDump(t, `echo "connection refused" >&2; exit 1`)

	dir := t.TempDir()
	t.Setenv("DATABASE_URL", os.Getenv("TEST_DATABASE_URL"))
	NewBackupScheduler(pool, dir, time.Hour).runBackup(context.Background())

	names := recentFilenames(t, pool)
	cleanupBackups(t, pool, names)
	rows := readBackupRows(t, pool, names)
	if len(rows) != 1 {
		t.Fatalf("got %d backup rows, want 1", len(rows))
	}
	if rows[0].status != backup.StatusFailed {
		t.Errorf("status = %q after pg_dump exited non-zero, want %q",
			rows[0].status, backup.StatusFailed)
	}
	if rows[0].errMsg == nil || !strings.Contains(*rows[0].errMsg, "pg_dump") {
		t.Errorf("error_message = %v, want the pg_dump failure", rows[0].errMsg)
	}
}

// TestTheStatusesWrittenAreOnesTheSchemaAccepts. Every status this scheduler
// writes goes through a CHECK constraint. A value the constraint rejects fails
// the UPDATE with 23514, which runBackup discards into `_, _ =`, so the row
// would silently stay 'pending' for ever.
func TestTheStatusesWrittenAreOnesTheSchemaAccepts(t *testing.T) {
	pool := backupPool(t)
	lockBackupEvidence(t, pool)
	for _, s := range []string{backup.StatusPending, backup.StatusCompleted, backup.StatusFailed} {
		name := "constraint-probe-" + s
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO backups (filename, status) VALUES ($1, $2)`, name, s); err != nil {
			t.Errorf("the schema rejects status %q, which the scheduler writes: %v", s, err)
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM backups WHERE filename = $1`, name)
	}
}

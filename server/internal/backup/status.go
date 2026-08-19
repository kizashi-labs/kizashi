package backup

// The words a backup row's status column may hold.
//
// Two tables record backups and both use this vocabulary:
//
//	backup_manifests  logical config export   (internal/backup)
//	backups           nightly pg_dump         (internal/scheduler)
//
// It is spelled out here because a consumer once invented a fourth word. The
// compliance scorecard counted `backup_manifests WHERE status = 'success'` to
// answer NIST CSF RC.RP-2 and ISO 27001 A.17.1.1–A.17.1.3. Nothing has ever
// written 'success' — the producer writes StatusCompleted, and so does the
// column default — so the count was structurally always zero and all four
// controls scored 30/non_compliant on every deployment, however many backups
// had in fact succeeded. A wrong word in a WHERE clause returns no rows rather
// than an error, so there was nothing to notice.
//
// New readers must compare against these constants, and BackupStatusVocabulary
// in internal/store guards the SQL that cannot.
const (
	// StatusPending is written when a backup starts, before it is known to work.
	StatusPending = "pending"
	// StatusCompleted means the backup finished AND passed its integrity check.
	// It is the only status that counts as evidence a backup exists.
	StatusCompleted = "completed"
	// StatusFailed means the dump or the integrity check failed.
	StatusFailed = "failed"
)

// EvidenceLockKey serialises test packages that mutate the two backup evidence
// tables. `go test ./...` runs packages concurrently against one database, and
// the compliance scorer counts whole tables — internal/scorecard has to start
// from a known-empty table to assert "no backups → non_compliant", while
// internal/scheduler is inserting its own rows there at the same time. Without
// a lock the two packages delete each other's fixtures.
//
// Any test touching `backups` or `backup_manifests` must hold
// pg_advisory_lock(EvidenceLockKey) on a dedicated connection for its duration.
// The value is arbitrary; it only has to be unique among the advisory locks
// this codebase takes.
const EvidenceLockKey int64 = 0x6261636b7570 // "backup" in ASCII

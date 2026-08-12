package dedup

import (
	"context"
	"testing"
)

// Cross-engine duplicates must actually be merged.
//
// Regression test for the `dedup_key IS NULL` filter this pass used to carry,
// which withheld from it every alert the title pass had already keyed — and,
// worse, the survivors of its own merges, leaving each merged group unable to
// absorb a later duplicate.
//
// Measured on a 20-agent / 1.67-host-day benign soak, counting what an analyst
// is left looking at rather than rows (merged rows are resolved and retained,
// so a row count cannot see deduplication at all):
//
//	old dedup, 301 rules (production today)  232 open
//	old dedup, 535 rules (P4-6 alone)        260 open   <- +28
//	new dedup, 535 rules                     225 open   <- absorbs it
//
// The fixture reproduces the shape P4-6 creates — the two engines disagree on
// BOTH the title's case and the severity, so the title pass cannot group them
// either:
//
//	[SIGMA] Suspicious chmod of Executable in /tmp  severity 4  (server-detect)
//	[Sigma] Suspicious chmod of Executable in /tmp  severity 3  (server-api)
func TestCrossEngineDuplicatesMerge(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('xeng-dedup', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE agent_id=$1::uuid", agentID) })

	const tech = "T1222.002"
	seed := func(title string, sev int, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := pool.Exec(ctx,
				`INSERT INTO alerts (agent_id, severity, title, description, status, source,
				                     mitre_technique, created_at)
				 VALUES ($1::uuid, $2, $3, 'x', 'open', 'custom', $4, NOW())`,
				agentID, sev, title, tech); err != nil {
				t.Fatalf("seed alert: %v", err)
			}
		}
	}
	// Three from each engine: enough that the title pass has real groups to
	// collapse, so the test also proves the reorder did not break that pass.
	seed("[SIGMA] Suspicious chmod of Executable in /tmp", 4, 3)
	seed("[Sigma] Suspicious chmod of Executable in /tmp", 3, 3)

	openCount := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM alerts WHERE agent_id=$1::uuid AND status='open'`,
			agentID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if got := openCount(); got != 6 {
		t.Fatalf("fixture is wrong: %d open alerts before dedup, want 6", got)
	}

	// tick(), not the two passes spelled out here: the ORDER is the thing under
	// test, so the test must not restate it.
	d := NewAlertDeduplicator(pool)
	d.tick(ctx)

	got := openCount()
	if got != 1 {
		var rows string
		r, _ := pool.Query(ctx,
			`SELECT title, severity, COALESCE(dedup_key,'-') FROM alerts
			  WHERE agent_id=$1::uuid AND status='open' ORDER BY severity DESC`, agentID)
		for r.Next() {
			var ti, dk string
			var sv int
			_ = r.Scan(&ti, &sv, &dk)
			rows += "\n    " + ti + " sev=" + string(rune('0'+sv)) + " key=" + dk[:min(8, len(dk))]
		}
		r.Close()
		t.Errorf("%d alerts still open after one dedup tick, want 1.\n"+
			"Both engines reported the SAME detection on the SAME event, so exactly one "+
			"alert should survive. Two survivors means the cross-engine pass did not run "+
			"or was starved by the title pass — check the order in tick() and that "+
			"deduplicateByTechnique does not filter on `dedup_key IS NULL`.%s", got, rows)
	}

	// The surviving alert must be the higher-severity one. Keeping the API's
	// level-derived severity 3 over the DB rule's declared 4 would quietly
	// downgrade the finding in the SOC queue.
	var sev int
	if err := pool.QueryRow(ctx,
		`SELECT severity FROM alerts WHERE agent_id=$1::uuid AND status='open'`,
		agentID).Scan(&sev); err == nil && sev != 4 {
		t.Errorf("surviving alert has severity %d, want 4 — the merge must keep the "+
			"highest-severity view of the event, not whichever engine happened to be first", sev)
	}
}

// A merged group must stay mergeable: a duplicate that arrives after the merge
// has to collapse into the alert that was kept.
//
// This is why the `dedup_key IS NULL` filter could not simply be left in place
// while reordering tick(). Reordering alone fixes the FIRST tick and breaks
// every one after it — the kept alert carries a key from that first merge, so
// it would be excluded from the next pass and a late duplicate would have
// nothing to merge into, sitting open forever.
func TestCrossEngineMergeStaysOpenToLateDuplicates(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('xeng-late', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE agent_id=$1::uuid", agentID) })

	const tech = "T1105"
	ins := func(title string, sev int) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO alerts (agent_id, severity, title, description, status, source,
			                     mitre_technique, created_at)
			 VALUES ($1::uuid, $2, $3, 'x', 'open', 'custom', $4, NOW())`,
			agentID, sev, title, tech); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}
	openCount := func() int {
		t.Helper()
		var n int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM alerts WHERE agent_id=$1::uuid AND status='open'`,
			agentID).Scan(&n)
		return n
	}

	d := NewAlertDeduplicator(pool)

	ins("[SIGMA] curl/wget Download to Temp Directory (Linux)", 6)
	ins("[Sigma] curl/wget Download to Temp Directory (Linux)", 5)
	d.tick(ctx)
	if got := openCount(); got != 1 {
		t.Fatalf("first tick left %d open, want 1", got)
	}

	// A late duplicate from the other engine, still inside the 6m window.
	ins("[Sigma] curl/wget Download to Temp Directory (Linux)", 5)
	d.tick(ctx)
	if got := openCount(); got != 1 {
		t.Errorf("%d alerts open after a late duplicate, want 1. The alert kept by the "+
			"first merge must remain eligible as the anchor for later duplicates; if the "+
			"cross-engine pass excludes rows that already have a dedup_key, every merge "+
			"after the first one silently stops working", got)
	}
}

// The title pass must group case-insensitively, because DedupKey does.
//
// TestDedupKey_CaseInsensitiveTitle already asserts the KEY ignores case. It
// could not catch this: the key is not what forms the groups — the SQL is, and
// its `GROUP BY title` was case-SENSITIVE. A unit test that only calls the
// function cannot see a contract the query beside it breaks.
//
// The fixture is the shape P4-6 creates: one detection, two engines, titles
// differing in case alone, everything else already aligned. It is deliberately
// OUTSIDE the cross-engine pass's reach — no mitre_technique — so only the title
// pass can merge it, which is the point. In the soak the two copies arrived 7-8
// minutes apart on average, well past the 6-minute cross-engine window, so the
// 1-hour title pass is the only one that can reach them.
func TestTitlePassIgnoresCase(t *testing.T) {
	pool := covPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('case-dedup', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM agents WHERE id=$1", agentID) })
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM alerts WHERE agent_id=$1::uuid", agentID) })

	for _, title := range []string{
		"[SIGMA] Suspicious chmod of Executable in /tmp",
		"[Sigma] Suspicious chmod of Executable in /tmp",
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO alerts (agent_id, severity, title, description, status, source, created_at)
			 VALUES ($1::uuid, 4, $2, 'x', 'open', 'custom', NOW())`, agentID, title); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
	}

	NewAlertDeduplicator(pool).tick(ctx)

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM alerts WHERE agent_id=$1::uuid AND status='open'`,
		agentID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("%d alerts still open, want 1. The two rows differ ONLY in the case of "+
			"the title, and DedupKey lowercases it — so the grouping query must lowercase "+
			"it too, or the key's case-insensitivity is a promise nothing keeps", n)
	}
}

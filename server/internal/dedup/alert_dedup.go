package dedup

import (
	"context"
	"crypto/md5" //nolint:gosec // G501: 重複排除のフィンガープリント用。暗号用途ではない
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertDeduplicator merges duplicate alerts to reduce noise.
// Two alerts are considered duplicates if they have the same title, severity,
// source, and agent_id within a dedup window.
type AlertDeduplicator struct {
	pool            *pgxpool.Pool
	windowSize      time.Duration
	techniqueWindow time.Duration // tight window for cross-engine same-technique merge
	interval        time.Duration
}

func NewAlertDeduplicator(pool *pgxpool.Pool) *AlertDeduplicator {
	return &AlertDeduplicator{
		pool:       pool,
		windowSize: 1 * time.Hour, // merge same-title alerts within 1 hour
		// techniqueWindow MUST exceed `interval`, otherwise cross-engine duplicates age out
		// of the window before a tick runs and are never merged (caught in live testing).
		// 6m window + 2m interval guarantees a tick fires while the pair is still in-window,
		// while staying tight enough that distinct later incidents are not over-merged.
		techniqueWindow: 6 * time.Minute,
		interval:        2 * time.Minute,
	}
}

// Run starts the deduplication loop.
func (d *AlertDeduplicator) Run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	slog.Info("アラート重複排除エンジン起動", "window", d.windowSize)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.tick(ctx)
		}
	}
}

// tick is one deduplication pass. Extracted from Run so tests exercise the
// production order rather than restating it.
//
// The order is title-then-technique, unchanged. An earlier version of this fix
// also swapped them, on the reasoning that the coarser cross-engine merge
// "belongs first". Mutation testing did not support that: with the dedup_key
// filter removed (see deduplicateByTechnique) the regression tests pass in
// EITHER order, because both orders converge on the same single surviving
// alert — title-first collapses each engine's repeats and then merges the two
// survivors; technique-first merges everything at once and leaves the title
// pass nothing to do. The swap was reverted rather than kept on an argument the
// tests could not confirm.
func (d *AlertDeduplicator) tick(ctx context.Context) {
	d.deduplicate(ctx)
	d.deduplicateByTechnique(ctx)
}

// TechniqueDedupKey fingerprints a cross-engine same-technique group (a technique seen
// on one agent within the tight window), independent of the rule title.
func TechniqueDedupKey(technique, agentID string) string {
	h := md5.New() //nolint:gosec // G401: dedup fingerprint, not cryptographic
	_, _ = fmt.Fprintf(h, "tech|%s|%s",
		strings.ToLower(strings.TrimSpace(technique)), agentID)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// DedupKey generates a fingerprint for an alert.
func DedupKey(title, severity, source, agentID string) string {
	h := md5.New() //nolint:gosec // G401: アラート重複排除のキー生成。暗号用途ではない
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s",
		strings.ToLower(strings.TrimSpace(title)),
		strings.ToLower(severity),
		strings.ToLower(source),
		agentID,
	)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (d *AlertDeduplicator) deduplicate(ctx context.Context) {
	// Find groups of similar alerts within the window
	// GROUP BY lower(title), not title.
	//
	// DedupKey() lowercases the title, and TestDedupKey_CaseInsensitiveTitle
	// asserts that it does — but the KEY is not what forms the groups; this SQL
	// is. The function's contract said case-insensitive while the grouping right
	// next to it was case-sensitive, and the test could not see the difference
	// because it only ever called the function.
	//
	// That gap became load-bearing when the `rules` table was wired into the API
	// path (P4-6). The two engines title the same detection differently in case
	// alone —
	//
	//   [SIGMA] Suspicious chmod of Executable in /tmp   (server-detect)
	//   [Sigma] Suspicious chmod of Executable in /tmp   (server-api)
	//
	// — so they landed in different groups and were never merged. Measured: with
	// severity and source already aligned, lowering the title was the last thing
	// standing between 539 alerts and the 486 baseline on a benign fleet.
	rows, err := d.pool.Query(ctx, `
        SELECT
            MIN(title) as title,
            severity,
            source,
            COALESCE(agent_id::TEXT, ''),
            COUNT(*) as cnt,
            MIN(id::TEXT) as keep_id,
            ARRAY_AGG(id::TEXT ORDER BY created_at) as all_ids
        FROM alerts
        WHERE status = 'open'
          AND created_at >= NOW() - $1::INTERVAL
          AND dedup_key IS NULL
        GROUP BY lower(title), severity, source, COALESCE(agent_id::TEXT, '')
        HAVING COUNT(*) > 1
        LIMIT 100`,
		fmt.Sprintf("%d seconds", int(d.windowSize.Seconds())),
	)
	if err != nil {
		slog.Debug("重複排除クエリ失敗 (dedup_keyカラム未存在の可能性)", "error", err)
		return
	}
	defer rows.Close()

	type dupGroup struct {
		title, severity, source, agentID string
		keepID                           string
		allIDs                           []string
	}
	var groups []dupGroup
	for rows.Next() {
		var g dupGroup
		var cnt int
		if err := rows.Scan(&g.title, &g.severity, &g.source, &g.agentID, &cnt, &g.keepID, &g.allIDs); err != nil {
			continue
		}
		groups = append(groups, g)
	}
	rows.Close()

	for _, g := range groups {
		key := DedupKey(g.title, g.severity, g.source, g.agentID)

		// Mark the kept alert with dedup_key and count
		dupIDs := make([]string, 0)
		for _, id := range g.allIDs {
			if id != g.keepID {
				dupIDs = append(dupIDs, id)
			}
		}

		// Update kept alert
		_, _ = d.pool.Exec(ctx,
			`UPDATE alerts SET dedup_key=$1, dedup_count=COALESCE(dedup_count,0)+$2, updated_at=NOW()
             WHERE id=$3::UUID`,
			key, len(dupIDs), g.keepID,
		)

		// Close duplicate alerts
		for _, dupID := range dupIDs {
			_, _ = d.pool.Exec(ctx,
				`UPDATE alerts SET status='resolved', dedup_key=$1,
                 description=COALESCE(description,'') || ' [重複排除: ' || $2 || ' に統合]',
                 updated_at=NOW() WHERE id=$3::UUID`,
				key, g.keepID, dupID,
			)
		}

		if len(dupIDs) > 0 {
			slog.Info("重複アラートを統合", "title", g.title, "merged", len(dupIDs), "kept", g.keepID)
		}
	}
}

// deduplicateByTechnique merges CROSS-ENGINE duplicates: the API builtin Sigma engine and
// the detection-server DB rule engine often both alert on the SAME event under DIFFERENT
// titles but the SAME mitre_technique (e.g. "PsExec Remote Execution" vs "PsExec Lateral
// Movement", both T1021.002). The title-based pass cannot catch these. This pass groups
// open, not-yet-deduped alerts by (mitre_technique, agent_id) within a TIGHT window
// (techniqueWindow) so only near-simultaneous duplicates — not distinct later incidents —
// are merged. The highest-severity alert is kept; the rest are resolved and linked (rows
// retained, never deleted).
func (d *AlertDeduplicator) deduplicateByTechnique(ctx context.Context) {
	rows, err := d.pool.Query(ctx, `
        SELECT
            mitre_technique,
            COALESCE(agent_id::TEXT, ''),
            COUNT(*) AS cnt,
            COUNT(DISTINCT title) AS distinct_titles,
            (ARRAY_AGG(id::TEXT ORDER BY severity DESC, created_at ASC))[1] AS keep_id,
            ARRAY_AGG(id::TEXT) AS all_ids
        FROM alerts
        WHERE status = 'open'
          AND mitre_technique IS NOT NULL
          AND mitre_technique <> ''
          AND created_at >= NOW() - $1::INTERVAL
        GROUP BY mitre_technique, COALESCE(agent_id::TEXT, '')
        HAVING COUNT(*) > 1 AND COUNT(DISTINCT title) > 1
        LIMIT 100`,
		// This pass used to carry `AND dedup_key IS NULL`, which withheld from it
		// every alert deduplicate() had already touched.
		//
		// deduplicate() runs first and stamps a dedup_key on each group it
		// merges — including the ONE alert it keeps. Those alerts then fell
		// outside this pass. So did the survivors of this pass's OWN merges, which
		// is worse: the kept row anchors its group, so once it carried a key, a
		// duplicate arriving later had nothing to merge into.
		//
		// ⚠️ This pass was NOT dead, and an earlier revision of this comment said
		// it was. That claim came from counting `status = 'resolved'` rows — but
		// the FP-soak scorer relabels every alert to 'false_positive' when it
		// finishes, so the count read zero for a reason unrelated to dedup.
		// Counting the merge marker left in `description` instead: on a 20-agent /
		// 1.67-host-day benign soak the PRE-FIX code merged 122 alerts here with
		// the API on builtins only, and 226 with the `rules` table also loaded.
		// Removing the filter changed how the work splits between the two passes,
		// it did not switch this one on.
		//
		// The figure that matters is how many alerts an analyst is left looking
		// at, not the row count. Merged rows are resolved and RETAINED, so the
		// soak's headline number cannot see this pass at all — measure
		// `status = 'open'`, or the merge markers, and never the row total.
		//
		// The kept alert must also stay eligible for LATER duplicates: it anchors
		// the group, and excluding it would make every merge after the first one
		// stop working. Re-merging a settled group is not a risk — the alerts
		// this pass resolves leave `status = 'open'`, so a settled group is a
		// single row and fails `COUNT(*) > 1`.
		fmt.Sprintf("%d seconds", int(d.techniqueWindow.Seconds())),
	)
	if err != nil {
		slog.Debug("technique重複排除クエリ失敗", "error", err)
		return
	}
	defer rows.Close()

	type techGroup struct {
		technique, agentID, keepID string
		allIDs                     []string
	}
	var groups []techGroup
	for rows.Next() {
		var g techGroup
		var cnt, distinctTitles int
		if err := rows.Scan(&g.technique, &g.agentID, &cnt, &distinctTitles, &g.keepID, &g.allIDs); err != nil {
			continue
		}
		groups = append(groups, g)
	}
	rows.Close()

	for _, g := range groups {
		key := TechniqueDedupKey(g.technique, g.agentID)

		dupIDs := make([]string, 0, len(g.allIDs))
		for _, id := range g.allIDs {
			if id != g.keepID {
				dupIDs = append(dupIDs, id)
			}
		}
		if len(dupIDs) == 0 {
			continue
		}

		// Keep the highest-severity alert; tag it with the technique dedup key + count.
		_, _ = d.pool.Exec(ctx,
			`UPDATE alerts SET dedup_key=$1, dedup_count=COALESCE(dedup_count,0)+$2, updated_at=NOW()
             WHERE id=$3::UUID`,
			key, len(dupIDs), g.keepID,
		)
		// Resolve the cross-engine duplicates, linking them to the kept alert.
		for _, dupID := range dupIDs {
			_, _ = d.pool.Exec(ctx,
				`UPDATE alerts SET status='resolved', dedup_key=$1,
                 description=COALESCE(description,'') || ' [二重エンジン重複排除: ' || $2 || ' に統合]',
                 updated_at=NOW() WHERE id=$3::UUID`,
				key, g.keepID, dupID,
			)
		}
		slog.Info("二重エンジン重複アラートを統合", "technique", g.technique, "merged", len(dupIDs), "kept", g.keepID)
	}
}

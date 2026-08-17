package compliance

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Check represents a single CIS benchmark check result.
type Check struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"` // "critical", "high", "medium", "low"
	Passed   bool   `json:"passed"`
	// Assessed records whether the check could be evaluated at all.
	//
	// Every check here passes when its query counts zero violations, and every
	// query used to discard its error. A dropped connection, a cancelled
	// request or a timeout therefore left the count at zero and the check
	// reported PASSED — the endpoint was declared compliant precisely when the
	// platform could not tell.
	//
	// The failure mode ran the wrong way round: the eight queries share one
	// 10-second budget, so the busier the endpoint — the more events it has,
	// the slower the counts, the more there is to find — the likelier it was to
	// be reported perfectly clean.
	Assessed bool `json:"assessed"`
}

// ScoreResult holds the computed CIS compliance score for an agent.
type ScoreResult struct {
	AgentID string
	Score   int
	// Total counts the checks that could be evaluated, not the checks that
	// exist. A score of 100 over two assessed checks is not the same claim as a
	// score of 100 over eight, and the difference has to survive to the caller.
	Total    int
	Passed   int
	Assessed int
	Checks   []Check
}

// ErrNothingAssessed is returned when not one check could be evaluated.
//
// The alternative is a ScoreResult of 100 with everything "passing", which
// ComputeScore would then persist into compliance_scores with a timestamp — a
// fabricated compliance record that outlives the outage that produced it.
var ErrNothingAssessed = errors.New("compliance: no check could be evaluated")

// countCheck runs one counting query and reports whether it could be answered.
//
// It exists so the error cannot be dropped by omission: a caller gets the count
// and the assessed flag together, and there is no shape of this call that
// yields a usable count without also saying whether it is real.
func countCheck(ctx context.Context, pool *pgxpool.Pool, id, sql string, args ...any) (int, bool) {
	var n int
	if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		slog.Warn("compliance: 判定できませんでした", "check", id, "error", err)
		return 0, false
	}
	return n, true
}

// verdict builds a check from a count that may not have been obtained.
func verdict(id, title, severity string, n int, assessed bool, pass func(int) bool) Check {
	return Check{
		ID:       id,
		Title:    title,
		Severity: severity,
		Passed:   assessed && pass(n),
		Assessed: assessed,
	}
}

// noneFound is the pass condition almost every check here uses: zero
// violations observed in the window.
func noneFound(n int) bool { return n == 0 }

// tally reduces the checks to a score, and does it over the checks that were
// actually assessed.
//
// Dividing by len(checks) instead would count an unevaluable check as a
// failure — the opposite lie from the original one, but a lie all the same: an
// endpoint whose queries timed out would be reported as badly non-compliant
// rather than as unknown. The two divisors agree whenever everything could be
// assessed, which is why this is a function with its own test rather than four
// lines inline: the healthy path cannot tell them apart.
func tally(checks []Check) (score, passed, assessed int) {
	for _, c := range checks {
		if !c.Assessed {
			continue
		}
		assessed++
		if c.Passed {
			passed++
		}
	}
	if assessed == 0 {
		return 0, 0, 0
	}
	return (passed * 100) / assessed, passed, assessed
}

// ScoreAgent computes CIS score from agent events data.
// It queries the events table for the agent and evaluates checks like:
// CIS-1.1: Process with elevated privileges seen (check process_events for root/SYSTEM)
// CIS-2.1: Autorun persistence detected (check file_events for startup locations)
// CIS-3.1: Network connections to suspicious ports (check network_events)
// CIS-4.1: Failed authentication attempts (check auth_events)
// Returns a ScoreResult with pass/fail for each check.
func ScoreAgent(ctx context.Context, pool *pgxpool.Pool, agentID string) (*ScoreResult, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	checks := make([]Check, 0, 8)

	// CIS-1.1: Elevated privilege process execution
	// Passes if NO process events show root/SYSTEM privilege usage in last 7 days
	elevatedCount, elevatedCountOK := countCheck(queryCtx, pool, "CIS-1.1", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    raw_data->>'username' ILIKE 'root'
		    OR raw_data->>'username' ILIKE 'SYSTEM'
		    OR raw_data->>'username' ILIKE 'NT AUTHORITY%'
		    -- elevated という真偽値キーは収集していません。Windows の昇格は
		    -- integrity_level (Sysmon と同じ Untrusted|Low|Medium|High|System)
		    -- で表されます。High は UAC で昇格した管理者プロセス、System は
		    -- SYSTEM 権限で、どちらも上の username 判定では拾えません
		    -- (昇格した一般管理者アカウントは root でも SYSTEM でもない)。
		    OR raw_data->>'integrity_level' IN ('High', 'System')
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-1.1", "Elevated privilege process execution", "critical", elevatedCount, elevatedCountOK, noneFound))

	// CIS-1.2: Suspicious process spawned by common LOLBin parents
	// Passes if NO process events show cmd/powershell spawned by office/browser processes
	lolbinCount, lolbinCountOK := countCheck(queryCtx, pool, "CIS-1.2", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    (raw_data->>'parent_name' ILIKE '%winword%'
		     OR raw_data->>'parent_name' ILIKE '%excel%'
		     OR raw_data->>'parent_name' ILIKE '%outlook%'
		     OR raw_data->>'parent_name' ILIKE '%chrome%'
		     OR raw_data->>'parent_name' ILIKE '%firefox%')
		    AND (raw_data->>'process_name' ILIKE '%powershell%'
		         OR raw_data->>'process_name' ILIKE '%cmd.exe%'
		         OR raw_data->>'process_name' ILIKE '%wscript%'
		         OR raw_data->>'process_name' ILIKE '%cscript%')
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-1.2", "Suspicious child process from office/browser parent", "high", lolbinCount, lolbinCountOK, noneFound))

	// CIS-2.1: Autorun/persistence file writes
	// Passes if NO file events targeting startup/autorun locations in last 7 days
	persistenceCount, persistenceCountOK := countCheck(queryCtx, pool, "CIS-2.1", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'file'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    raw_data->>'path' ILIKE '%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%'
		    OR raw_data->>'path' ILIKE '%/etc/init.d/%'
		    OR raw_data->>'path' ILIKE '%/etc/cron%'
		    OR raw_data->>'path' ILIKE '%\\System32\\Tasks\\%'
		    OR raw_data->>'path' ILIKE '%/Library/LaunchAgents/%'
		    OR raw_data->>'path' ILIKE '%/Library/LaunchDaemons/%'
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-2.1", "Autorun/persistence location file write detected", "high", persistenceCount, persistenceCountOK, noneFound))

	// CIS-3.1: Network connections to suspicious/high-risk ports
	// Passes if NO network events to known C2/risky ports in last 7 days
	suspiciousPortCount, suspiciousPortCountOK := countCheck(queryCtx, pool, "CIS-3.1", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'network'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    (raw_data->>'dst_port')::int IN (4444, 1337, 31337, 8888, 9999, 6666, 6667, 6668, 6669)
		    -- is_suspicious は dns イベントにしかありません (DnsEvent の
		    -- DGA/homograph 判定)。ネットワークイベントで対応するのは
		    -- threat_intel_matched — エージェント側の脅威インテル照合結果です。
		    OR (raw_data->>'threat_intel_matched')::boolean = true
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-3.1", "Network connection to suspicious ports", "critical", suspiciousPortCount, suspiciousPortCountOK, noneFound))

	// CIS-3.2: Outbound connections on non-standard ports
	// Passes if fewer than 10 distinct non-standard outbound connections in last 7 days
	nonStandardPortCount, nonStandardPortCountOK := countCheck(queryCtx, pool, "CIS-3.2", `
		SELECT COUNT(DISTINCT raw_data->>'dst_port')
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'network'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND raw_data->>'direction' = 'outbound'
		  AND (raw_data->>'dst_port')::int NOT IN (80, 443, 22, 25, 53, 110, 143, 993, 995, 587, 465, 8080, 8443)
		  AND (raw_data->>'dst_port')::int > 1024
	`, agentID)
	checks = append(checks, verdict(
		"CIS-3.2", "Excessive outbound non-standard port connections", "medium", nonStandardPortCount, nonStandardPortCountOK, func(n int) bool { return n < 10 }))

	// CIS-4.1: Failed authentication attempts
	// Passes if fewer than 5 failed auth events in last 24 hours
	failedAuthCount, failedAuthCountOK := countCheck(queryCtx, pool, "CIS-4.1", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'auth'
		  AND time >= NOW() - INTERVAL '24 hours'
		  AND (
		    raw_data->>'success' = 'false'
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-4.1", "Failed authentication attempts (brute-force indicator)", "high", failedAuthCount, failedAuthCountOK, func(n int) bool { return n < 5 }))

	// CIS-5.1: Registry modification to security-critical keys
	// Passes if NO registry events targeting security-disabling keys in last 7 days
	registryCount, registryCountOK := countCheck(queryCtx, pool, "CIS-5.1", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'registry'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    raw_data->>'key_path' ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%'
		    OR raw_data->>'key_path' ILIKE '%\\System\\CurrentControlSet\\Services%'
		    OR raw_data->>'key_path' ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows Defender%'
		    OR raw_data->>'key_path' ILIKE '%DisableAntiSpyware%'
		    OR raw_data->>'key_path' ILIKE '%DisableRealtimeMonitoring%'
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-5.1", "Security-critical registry key modification", "critical", registryCount, registryCountOK, noneFound))

	// CIS-6.1: DNS queries to known malicious/suspicious domains
	// Passes if NO dns events to suspicious TLDs or known DGA patterns in last 7 days
	dnsSuspiciousCount, dnsSuspiciousCountOK := countCheck(queryCtx, pool, "CIS-6.1", `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'dns'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    raw_data->>'query' ILIKE '%.onion'
		    OR raw_data->>'query' ILIKE '%.bit'
		    OR raw_data->>'query' ILIKE '%.cc'
		    OR raw_data->>'is_suspicious' = 'true'
		    OR LENGTH(SPLIT_PART(raw_data->>'query', '.', 1)) > 30
		  )
	`, agentID)
	checks = append(checks, verdict(
		"CIS-6.1", "Suspicious DNS queries (DGA/malicious domains)", "high", dnsSuspiciousCount, dnsSuspiciousCountOK, noneFound))

	score, passed, assessed := tally(checks)
	if assessed == 0 {
		// Refused rather than returned. A ScoreResult here would be 0 checks of
		// 0 passed, which the handler would persist as a compliance record for
		// an assessment that never happened.
		return nil, ErrNothingAssessed
	}
	if assessed < len(checks) {
		slog.Warn("compliance: 一部の判定ができませんでした",
			"agent_id", agentID, "assessed", assessed, "total", len(checks))
	}

	return &ScoreResult{
		AgentID:  agentID,
		Score:    score,
		Total:    assessed,
		Passed:   passed,
		Assessed: assessed,
		Checks:   checks,
	}, nil
}

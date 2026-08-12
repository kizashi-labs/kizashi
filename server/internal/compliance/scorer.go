package compliance

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Check represents a single CIS benchmark check result.
type Check struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"` // "critical", "high", "medium", "low"
	Passed   bool   `json:"passed"`
}

// ScoreResult holds the computed CIS compliance score for an agent.
type ScoreResult struct {
	AgentID string
	Score   int
	Total   int
	Passed  int
	Checks  []Check
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
	var elevatedCount int
	_ = pool.QueryRow(queryCtx, `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    raw_data->>'user' ILIKE 'root'
		    OR raw_data->>'user' ILIKE 'SYSTEM'
		    OR raw_data->>'user' ILIKE 'NT AUTHORITY%'
		    OR (raw_data->>'elevated')::boolean = true
		  )
	`, agentID).Scan(&elevatedCount)
	checks = append(checks, Check{
		ID:       "CIS-1.1",
		Title:    "Elevated privilege process execution",
		Severity: "critical",
		Passed:   elevatedCount == 0,
	})

	// CIS-1.2: Suspicious process spawned by common LOLBin parents
	// Passes if NO process events show cmd/powershell spawned by office/browser processes
	var lolbinCount int
	_ = pool.QueryRow(queryCtx, `
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
		    AND (raw_data->>'name' ILIKE '%powershell%'
		         OR raw_data->>'name' ILIKE '%cmd.exe%'
		         OR raw_data->>'name' ILIKE '%wscript%'
		         OR raw_data->>'name' ILIKE '%cscript%')
		  )
	`, agentID).Scan(&lolbinCount)
	checks = append(checks, Check{
		ID:       "CIS-1.2",
		Title:    "Suspicious child process from office/browser parent",
		Severity: "high",
		Passed:   lolbinCount == 0,
	})

	// CIS-2.1: Autorun/persistence file writes
	// Passes if NO file events targeting startup/autorun locations in last 7 days
	var persistenceCount int
	_ = pool.QueryRow(queryCtx, `
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
	`, agentID).Scan(&persistenceCount)
	checks = append(checks, Check{
		ID:       "CIS-2.1",
		Title:    "Autorun/persistence location file write detected",
		Severity: "high",
		Passed:   persistenceCount == 0,
	})

	// CIS-3.1: Network connections to suspicious/high-risk ports
	// Passes if NO network events to known C2/risky ports in last 7 days
	var suspiciousPortCount int
	_ = pool.QueryRow(queryCtx, `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'network'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    (raw_data->>'dst_port')::int IN (4444, 1337, 31337, 8888, 9999, 6666, 6667, 6668, 6669)
		    OR (raw_data->>'is_suspicious')::boolean = true
		  )
	`, agentID).Scan(&suspiciousPortCount)
	checks = append(checks, Check{
		ID:       "CIS-3.1",
		Title:    "Network connection to suspicious ports",
		Severity: "critical",
		Passed:   suspiciousPortCount == 0,
	})

	// CIS-3.2: Outbound connections on non-standard ports
	// Passes if fewer than 10 distinct non-standard outbound connections in last 7 days
	var nonStandardPortCount int
	_ = pool.QueryRow(queryCtx, `
		SELECT COUNT(DISTINCT raw_data->>'dst_port')
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'network'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND raw_data->>'direction' = 'outbound'
		  AND (raw_data->>'dst_port')::int NOT IN (80, 443, 22, 25, 53, 110, 143, 993, 995, 587, 465, 8080, 8443)
		  AND (raw_data->>'dst_port')::int > 1024
	`, agentID).Scan(&nonStandardPortCount)
	checks = append(checks, Check{
		ID:       "CIS-3.2",
		Title:    "Excessive outbound non-standard port connections",
		Severity: "medium",
		Passed:   nonStandardPortCount < 10,
	})

	// CIS-4.1: Failed authentication attempts
	// Passes if fewer than 5 failed auth events in last 24 hours
	var failedAuthCount int
	_ = pool.QueryRow(queryCtx, `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'auth'
		  AND time >= NOW() - INTERVAL '24 hours'
		  AND (
		    raw_data->>'success' = 'false'
		    OR raw_data->>'result' ILIKE '%fail%'
		    OR raw_data->>'result' ILIKE '%denied%'
		  )
	`, agentID).Scan(&failedAuthCount)
	checks = append(checks, Check{
		ID:       "CIS-4.1",
		Title:    "Failed authentication attempts (brute-force indicator)",
		Severity: "high",
		Passed:   failedAuthCount < 5,
	})

	// CIS-5.1: Registry modification to security-critical keys
	// Passes if NO registry events targeting security-disabling keys in last 7 days
	var registryCount int
	_ = pool.QueryRow(queryCtx, `
		SELECT COUNT(*)
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'registry'
		  AND time >= NOW() - INTERVAL '7 days'
		  AND (
		    raw_data->>'key' ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%'
		    OR raw_data->>'key' ILIKE '%\\System\\CurrentControlSet\\Services%'
		    OR raw_data->>'key' ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows Defender%'
		    OR raw_data->>'key' ILIKE '%DisableAntiSpyware%'
		    OR raw_data->>'key' ILIKE '%DisableRealtimeMonitoring%'
		  )
	`, agentID).Scan(&registryCount)
	checks = append(checks, Check{
		ID:       "CIS-5.1",
		Title:    "Security-critical registry key modification",
		Severity: "critical",
		Passed:   registryCount == 0,
	})

	// CIS-6.1: DNS queries to known malicious/suspicious domains
	// Passes if NO dns events to suspicious TLDs or known DGA patterns in last 7 days
	var dnsSuspiciousCount int
	_ = pool.QueryRow(queryCtx, `
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
	`, agentID).Scan(&dnsSuspiciousCount)
	checks = append(checks, Check{
		ID:       "CIS-6.1",
		Title:    "Suspicious DNS queries (DGA/malicious domains)",
		Severity: "high",
		Passed:   dnsSuspiciousCount == 0,
	})

	// Calculate score
	passed := 0
	for _, c := range checks {
		if c.Passed {
			passed++
		}
	}
	total := len(checks)
	score := 0
	if total > 0 {
		score = (passed * 100) / total
	}

	return &ScoreResult{
		AgentID: agentID,
		Score:   score,
		Total:   total,
		Passed:  passed,
		Checks:  checks,
	}, nil
}

package compliance

// Real-time endpoint compliance assessment

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceCheck represents a single compliance check result for an endpoint.
type ComplianceCheck struct {
	CheckID     string    `json:"check_id"`
	Category    string    `json:"category"` // patching/antivirus/encryption/firewall/logging
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // pass/fail/warning/unknown
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	Framework   string    `json:"framework"` // CIS/NIST/PCI-DSS
	Control     string    `json:"control"`   // e.g. "CIS 1.1"
	CheckedAt   time.Time `json:"checked_at"`
}

// AgentCompliance holds the full compliance assessment for a single agent.
type AgentCompliance struct {
	AgentID      string             `json:"agent_id"`
	Hostname     string             `json:"hostname"`
	OS           string             `json:"os"`
	Score        int                `json:"score"` // 0-100
	PassCount    int                `json:"pass_count"`
	FailCount    int                `json:"fail_count"`
	Checks       []*ComplianceCheck `json:"checks"`
	LastAssessed time.Time          `json:"last_assessed"`
}

// ComplianceStats holds fleet-wide compliance statistics.
type ComplianceStats struct {
	FleetScore  int            `json:"fleet_score"`
	PassRate    float64        `json:"pass_rate"`
	FailRate    float64        `json:"fail_rate"`
	TopFailures []string       `json:"top_failures"`
	ByCategory  map[string]int `json:"by_category"`
}

// Checker performs real-time compliance assessment of agents.
type Checker struct {
	pool *pgxpool.Pool
}

// NewChecker creates a new Checker.
func NewChecker(pool *pgxpool.Pool) *Checker {
	return &Checker{pool: pool}
}

// builtinChecks defines the 10 built-in compliance checks.
var builtinChecks = []struct {
	id          string
	category    string
	title       string
	description string
	remediation string
	framework   string
	control     string
}{
	{
		id:          "agent_alive",
		category:    "monitoring",
		title:       "Agent Heartbeat",
		description: "Agent must have checked in within the last 5 minutes.",
		remediation: "Verify agent service is running and has network connectivity.",
		framework:   "CIS",
		control:     "CIS 1.1",
	},
	{
		id:          "events_flowing",
		category:    "logging",
		title:       "Events Flowing",
		description: "Agent must have produced events within the last hour.",
		remediation: "Check agent event collection configuration.",
		framework:   "CIS",
		control:     "CIS 6.2",
	},
	{
		id:          "av_running",
		category:    "antivirus",
		title:       "Antivirus Running",
		description: "Antivirus/EDR process should be visible in recent process events.",
		remediation: "Ensure antivirus software is installed and running.",
		framework:   "NIST",
		control:     "NIST SI-3",
	},
	{
		id:          "firewall_enabled",
		category:    "firewall",
		title:       "Firewall Enabled",
		description: "Host-based firewall should be active.",
		remediation: "Enable the host firewall via OS settings.",
		framework:   "CIS",
		control:     "CIS 9.1",
	},
	{
		id:          "disk_encryption",
		category:    "encryption",
		title:       "Disk Encryption",
		description: "Full-disk encryption (BitLocker/FileVault/LUKS) should be active.",
		remediation: "Enable full-disk encryption.",
		framework:   "PCI-DSS",
		control:     "PCI-DSS 3.5",
	},
	{
		id:          "logging_enabled",
		category:    "logging",
		title:       "Audit Logging Enabled",
		description: "System audit logging should be enabled.",
		remediation: "Enable auditd/Windows Event Log audit policy.",
		framework:   "NIST",
		control:     "NIST AU-2",
	},
	{
		id:          "patch_status",
		category:    "patching",
		title:       "Patch Status",
		description: "No critical vulnerabilities older than 30 days should exist.",
		remediation: "Apply pending OS patches.",
		framework:   "CIS",
		control:     "CIS 3.1",
	},
	{
		id:          "admin_accounts",
		category:    "access_control",
		title:       "Minimal Admin Accounts",
		description: "Excessive administrative accounts should not be present.",
		remediation: "Review and remove unnecessary admin accounts.",
		framework:   "CIS",
		control:     "CIS 4.1",
	},
	{
		id:          "password_policy",
		category:    "access_control",
		title:       "Password Policy Enforced",
		description: "Password policy should meet minimum complexity requirements.",
		remediation: "Configure password policy with minimum length ≥12 and complexity.",
		framework:   "NIST",
		control:     "NIST IA-5",
	},
	{
		id:          "screen_lock",
		category:    "access_control",
		title:       "Screen Lock Configured",
		description: "Screen lock / idle timeout should be set.",
		remediation: "Enable screen lock with idle timeout ≤15 minutes.",
		framework:   "CIS",
		control:     "CIS 16.11",
	},
}

// AssessAgent evaluates compliance for a single agent.
func (c *Checker) AssessAgent(ctx context.Context, agentID string) (*AgentCompliance, error) {
	if c.pool == nil {
		return nil, nil
	}

	// Fetch agent details.
	// agents の OS 列は `os_type` (migration 001)。`os` は存在せず、この
	// クエリが毎回 `column "os" does not exist` で失敗するため、AssessAgent は
	// events の判定に到達する前にエラーで抜けていた = コンプライアンス評価が
	// 全エージェントで機能していなかった。
	var hostname, os string
	var lastSeen time.Time
	err := c.pool.QueryRow(ctx, `
		SELECT COALESCE(hostname,''), COALESCE(os_type,'unknown'), COALESCE(last_seen, NOW()-INTERVAL '1 year')
		FROM agents
		WHERE id = $1`, agentID,
	).Scan(&hostname, &os, &lastSeen)
	if err != nil {
		slog.Warn("compliance: AssessAgent agent lookup failed", "agent_id", agentID, "error", err)
		return nil, err
	}

	now := time.Now().UTC()
	agentAlive := now.Sub(lastSeen) < 5*time.Minute

	// Check if events are flowing (any event in last hour).
	// events の時刻列は `time` (migration 002 の hypertable パーティションキー)。
	// `created_at` は存在せず、このクエリは毎回
	// `column "created_at" does not exist` で失敗していた。エラーを握りつぶして
	// いるため recentEvents は 0 のままで、eventsFlowing が常に false になり、
	// エージェントが正常に送信していてもコンプライアンス判定が落ちていた。
	var recentEvents int
	if err := c.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM events
		WHERE agent_id = $1 AND time > NOW() - INTERVAL '1 hour'`,
		agentID,
	).Scan(&recentEvents); err != nil {
		slog.Warn("compliance: 直近イベント数の取得に失敗", "agent_id", agentID, "error", err)
	}
	eventsFlowing := recentEvents > 0

	// Check AV process presence (look for known AV process names in last 24h).
	// 上と同じく時刻列は `time`。AV が動いていても avRunning が常に false になっていた。
	var avEvents int
	if err := c.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM events
		WHERE agent_id = $1
		  AND event_type = 'process'
		  AND time > NOW() - INTERVAL '24 hours'
		  AND (
		      lower(raw_data->>'process_name') IN (
		          'msmpeng.exe','mssense.exe','msseces.exe','mscorsvw.exe',
		          'avguard','clamd','freshclam','sophos','cylancesvc',
		          'cbdefense','carbonblack','falcond','sensorservice'
		      )
		  )`,
		agentID,
	).Scan(&avEvents); err != nil {
		slog.Warn("compliance: AV プロセス数の取得に失敗", "agent_id", agentID, "error", err)
	}
	avRunning := avEvents > 0

	// Disk encryption: check endpoint_hardening table if available.
	var encryptionEnabled bool
	_ = c.pool.QueryRow(ctx, `
		SELECT COALESCE(disk_encryption_enabled, false)
		FROM endpoint_hardening
		WHERE agent_id = $1
		ORDER BY created_at DESC LIMIT 1`,
		agentID,
	).Scan(&encryptionEnabled)

	// Firewall: check endpoint_hardening.
	var firewallEnabled bool
	_ = c.pool.QueryRow(ctx, `
		SELECT COALESCE(firewall_enabled, false)
		FROM endpoint_hardening
		WHERE agent_id = $1
		ORDER BY created_at DESC LIMIT 1`,
		agentID,
	).Scan(&firewallEnabled)

	// Patch status: check vuln_findings for critical unpatched vulns older than 30d.
	var criticalVulns int
	_ = c.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM vuln_findings
		WHERE agent_id = $1
		  AND severity = 'critical'
		  AND status != 'patched'
		  AND found_at < NOW() - INTERVAL '30 days'`,
		agentID,
	).Scan(&criticalVulns)
	patchOK := criticalVulns == 0

	checkResults := map[string]bool{
		"agent_alive":      agentAlive,
		"events_flowing":   eventsFlowing,
		"av_running":       avRunning,
		"firewall_enabled": firewallEnabled,
		"disk_encryption":  encryptionEnabled,
		"logging_enabled":  eventsFlowing, // proxy: if events flow, logging is on
		"patch_status":     patchOK,
		"admin_accounts":   true, // unknown → pass (warning state)
		"password_policy":  true, // unknown → pass
		"screen_lock":      true, // unknown → pass
	}

	checkEvidence := map[string]string{
		"agent_alive":      "Last seen: " + lastSeen.Format(time.RFC3339),
		"events_flowing":   "Recent events in last hour: " + itoa(recentEvents),
		"av_running":       "AV process events in last 24h: " + itoa(avEvents),
		"firewall_enabled": boolStr(firewallEnabled, "Firewall enabled", "Firewall not detected"),
		"disk_encryption":  boolStr(encryptionEnabled, "Disk encryption active", "Encryption not detected"),
		"logging_enabled":  boolStr(eventsFlowing, "Events are flowing", "No events in last hour"),
		"patch_status":     "Critical unpatched vulns >30d: " + itoa(criticalVulns),
		"admin_accounts":   "No data available",
		"password_policy":  "No data available",
		"screen_lock":      "No data available",
	}

	unknownChecks := map[string]bool{
		"admin_accounts":  true,
		"password_policy": true,
		"screen_lock":     true,
	}

	var checks []*ComplianceCheck
	passCount := 0
	failCount := 0

	for _, def := range builtinChecks {
		passed := checkResults[def.id]
		status := "pass"
		if unknownChecks[def.id] {
			status = "unknown"
		} else if !passed {
			status = "fail"
		}
		if status == "pass" {
			passCount++
		} else if status == "fail" {
			failCount++
		}

		checks = append(checks, &ComplianceCheck{
			CheckID:     def.id,
			Category:    def.category,
			Title:       def.title,
			Description: def.description,
			Status:      status,
			AgentID:     agentID,
			Hostname:    hostname,
			Evidence:    checkEvidence[def.id],
			Remediation: def.remediation,
			Framework:   def.framework,
			Control:     def.control,
			CheckedAt:   now,
		})
	}

	totalScored := passCount + failCount
	score := 0
	if totalScored > 0 {
		score = passCount * 100 / totalScored
	}

	return &AgentCompliance{
		AgentID:      agentID,
		Hostname:     hostname,
		OS:           os,
		Score:        score,
		PassCount:    passCount,
		FailCount:    failCount,
		Checks:       checks,
		LastAssessed: now,
	}, nil
}

// GetFleetCompliance returns compliance summary for all active agents.
func (c *Checker) GetFleetCompliance(ctx context.Context) ([]AgentCompliance, error) {
	if c.pool == nil {
		return []AgentCompliance{}, nil
	}

	rows, err := c.pool.Query(ctx, `
		SELECT id::text FROM agents
		WHERE last_seen > NOW() - INTERVAL '24 hours'
		ORDER BY hostname
		LIMIT 200`)
	if err != nil {
		slog.Warn("compliance: GetFleetCompliance agent list failed", "error", err)
		return []AgentCompliance{}, nil
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			agentIDs = append(agentIDs, id)
		}
	}

	var results []AgentCompliance
	for _, id := range agentIDs {
		ac, err := c.AssessAgent(ctx, id)
		if err != nil || ac == nil {
			continue
		}
		// Strip individual checks from the fleet summary to keep payload small.
		ac.Checks = nil
		results = append(results, *ac)
	}

	if results == nil {
		return []AgentCompliance{}, nil
	}
	return results, nil
}

// GetComplianceStats returns fleet-wide compliance statistics.
func (c *Checker) GetComplianceStats(ctx context.Context) ComplianceStats {
	stats := ComplianceStats{
		TopFailures: []string{},
		ByCategory:  map[string]int{},
	}
	if c.pool == nil {
		return stats
	}

	fleet, err := c.GetFleetCompliance(ctx)
	if err != nil || len(fleet) == 0 {
		return stats
	}

	totalScore := 0
	totalPass := 0
	totalChecks := 0
	for _, a := range fleet {
		totalScore += a.Score
		totalPass += a.PassCount
		totalChecks += a.PassCount + a.FailCount
	}

	if len(fleet) > 0 {
		stats.FleetScore = totalScore / len(fleet)
	}
	if totalChecks > 0 {
		stats.PassRate = float64(totalPass) / float64(totalChecks)
		stats.FailRate = 1 - stats.PassRate
	}

	return stats
}

// ── helpers ──────────────────────────────────────────────────────────────────

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	if neg {
		result = "-" + result
	}
	return result
}

func boolStr(b bool, trueVal, falseVal string) string {
	if b {
		return trueVal
	}
	return falseVal
}

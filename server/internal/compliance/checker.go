package compliance

// Real-time endpoint compliance assessment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
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

	// ディスク暗号化 / ファイアウォール / 未対応の重大脆弱性。
	//
	// 旧実装は `endpoint_hardening` と `vuln_findings` を引いていたが、どちらの名前の
	// テーブルもマイグレーションのどこにも作られていない。クエリは毎回エラーになり、
	// 握り潰された結果:
	//   - 暗号化 / ファイアウォール → false のまま「未対応」として全ホストを不合格に
	//   - 重大脆弱性 → 0 件のまま patchOK = true、つまり「測れていない」を「合格」として報告
	// 後者が一番まずい向きの誤りだった。
	//
	// **行が無い / 取得に失敗した場合は false ではなく unknown にする。** これは表記では
	// なく採点の問題で、unknown は分母から外れる（fail は外れない）。「まだ判っていない」を
	// 「未対応」として数えると、本当に未対応なホストと区別がつかなくなる。

	// 実表は endpoint_encryption (362)。agent_id が主キーなので 1 エージェント 1 行だが、
	// 将来行が増えても最新を採るよう reported_at で並べる。
	var encryptionEnabled bool
	encryptionKnown := true
	if err := c.pool.QueryRow(ctx, `
		SELECT encrypted
		FROM endpoint_encryption
		WHERE agent_id = $1
		ORDER BY reported_at DESC NULLS LAST LIMIT 1`,
		agentID,
	).Scan(&encryptionEnabled); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("compliance: ディスク暗号化の判定ができません（未計測として採点対象外）",
				"agent_id", agentID, "error", err)
		}
		encryptionKnown = false
	}

	// ファイアウォールの状態を持つ「列」はどのテーブルにも無いが、データ自体は存在する。
	// エージェントのハードニングコレクタが Check{ID: "firewall"} を出し
	// (agent/internal/hardening/collector_windows.go)、それを router.go の
	// ハードニングレポート受け口が hardening_assessments.findings に JSONB 配列として
	// 書いている (171)。列だけを探すと「収集経路が無い」と誤って結論するので注意。
	// 最新の評価行の firewall チェックだけを見る。
	var firewallEnabled, firewallKnown bool
	if err := c.pool.QueryRow(ctx, `
		SELECT (f->>'passed')::boolean
		FROM hardening_assessments ha,
		     LATERAL jsonb_array_elements(COALESCE(ha.findings, '[]'::jsonb)) AS f
		WHERE ha.agent_id = $1::uuid
		  AND jsonb_typeof(COALESCE(ha.findings, '[]'::jsonb)) = 'array'
		  AND f->>'id' = 'firewall'
		  AND f->>'passed' IS NOT NULL
		ORDER BY ha.assessed_at DESC NULLS LAST, ha.created_at DESC
		LIMIT 1`,
		agentID,
	).Scan(&firewallEnabled); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("compliance: ファイアウォールの判定ができません（未計測として採点対象外）",
				"agent_id", agentID, "error", err)
		}
	} else {
		firewallKnown = true
	}

	// 未対応の重大脆弱性 (30 日超)。
	//
	// vulnerabilities (016) と vulnerability_findings (161) の両方が実在するが、
	// **本番で書かれているのは vulnerabilities のほう**である:
	//   internal/scheduler/vulnerability_scanner.go / internal/sync/wazuh.go /
	//   internal/store/vulnerabilities.go がここに INSERT する。
	// vulnerability_findings に書く本番経路は存在しない (テストのみ)。空の表を読むと
	// 常に 0 件 = 合格になり、上に書いた「測れていないを合格として報告する」誤りに戻る。
	//
	// 時刻列は detected_at。status の CHECK 値は open / mitigated / patched / accepted
	// で、**数えてよいのは open だけ**。patched は当然として、accepted は
	// リスク受容済み、mitigated は緩和策適用済みで、どちらも「放置された重大
	// 脆弱性」ではない。
	//
	// `status != 'patched'` と書くと accepted と mitigated まで数に入る。
	// 判定としては安全側に倒れるように見えるが、**受容も緩和も済んでいる
	// ホストが未対応として並ぶと、本当に open な 1 件が埋もれる**。
	// 実 DB のある CI (checker_db_test.go) が open/patched/accepted の 3 件を
	// 入れて 1 件を期待しており、`!= 'patched'` では 2 件になる。
	var criticalVulns int
	patchKnown := true
	if err := c.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM vulnerabilities
		WHERE agent_id = $1
		  AND severity = 'critical'
		  AND status = 'open'
		  AND detected_at < NOW() - INTERVAL '30 days'`,
		agentID,
	).Scan(&criticalVulns); err != nil {
		slog.Warn("compliance: 未修正の重大脆弱性の集計に失敗", "agent_id", agentID, "error", err)
		patchKnown = false
	}
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
		"agent_alive":    "Last seen: " + lastSeen.Format(time.RFC3339),
		"events_flowing": "Recent events in last hour: " + itoa(recentEvents),
		"av_running":     "AV process events in last 24h: " + itoa(avEvents),
		"firewall_enabled": hardeningEvidence(firewallKnown, firewallEnabled,
			"Firewall enabled", "Firewall disabled"),
		"disk_encryption": hardeningEvidence(encryptionKnown, encryptionEnabled,
			"Disk encryption active", "Disk encryption off"),
		"logging_enabled": boolStr(eventsFlowing, "Events are flowing", "No events in last hour"),
		"patch_status": knownStr(patchKnown,
			"Critical unpatched vulns >30d: "+itoa(criticalVulns),
			"Vulnerability data unavailable"),
		"admin_accounts":  "No data available",
		"password_policy": "No data available",
		"screen_lock":     "No data available",
	}

	// unknown は pass にも fail にも数えず、スコアの分母から外れる。測っていない項目を
	// どちらかに倒すと、準拠・非準拠のいずれかを根拠なく主張することになる。実際に未対応な
	// ホストと「まだ報告が来ていないだけ」のホストが同じ点数になると、スコアが是正すべき
	// 対象を指さなくなる。
	unknownChecks := map[string]bool{
		"admin_accounts":  true,
		"password_policy": true,
		"screen_lock":     true,
	}
	// 取得に失敗したら「未対応 0 件」ではなく不明。0 のままだと patchOK が
	// true になり、何も測れていない端末を「良好」と報告してしまう。
	if !patchKnown {
		unknownChecks["patch_status"] = true
	}
	// A hardening check this platform does not collect is unknown, not failed.
	// The Linux collector reports no firewall or disk-encryption check at all,
	// and an agent that has never sent a hardening report has none either.
	if !encryptionKnown {
		unknownChecks["disk_encryption"] = true
	}
	if !firewallKnown {
		unknownChecks["firewall_enabled"] = true
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
		return nil, err
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			agentIDs = append(agentIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var results []AgentCompliance
	for _, id := range agentIDs {
		ac, err := c.AssessAgent(ctx, id)
		if err != nil {
			// 評価できなかった端末を黙って外すと、その端末は分母からも
			// 消えます。準拠率は「評価できた端末だけの準拠率」になり、
			// 分子と分母が同時に減るので、数字は動かないことすらあります。
			return nil, fmt.Errorf("端末 %s の準拠状況を評価できませんでした: %w", id, err)
		}
		if ac == nil {
			continue // 評価対象の情報が無い端末。0件は事実です。
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
//
// 読めなかったときは error を返します。以前はゼロ値の stats を返していて、
// 画面には FleetScore 0、PassRate 0 と出ます。準拠率0%は、準拠率を測る
// 画面が出しうる最も強い主張です。読めなかっただけのときにそれを出すと、
// 見た人は対応を始めます。
func (c *Checker) GetComplianceStats(ctx context.Context) (ComplianceStats, error) {
	stats := ComplianceStats{
		TopFailures: []string{},
		ByCategory:  map[string]int{},
	}
	if c.pool == nil {
		return stats, nil
	}

	fleet, err := c.GetFleetCompliance(ctx)
	if err != nil {
		return stats, err
	}
	if len(fleet) == 0 {
		// 端末が1台も無い = 測る対象が無い。ゼロは事実です。
		return stats, nil
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

	return stats, nil
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

// knownStr renders evidence for a check whose data source may have no row yet.
// The unmeasured wording has to be distinguishable from a measured failure —
// a reader who cannot tell them apart cannot act on either.
func knownStr(known bool, measured, unmeasured string) string {
	if known {
		return measured
	}
	return unmeasured
}

// hardeningEvidence describes a hardening control, keeping "not assessed"
// distinct from "assessed and failing".
func hardeningEvidence(assessed, passed bool, yes, no string) string {
	if !assessed {
		return "Not assessed on this platform"
	}
	return boolStr(passed, yes, no)
}

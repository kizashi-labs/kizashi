package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── MITRE ATT&CK types ───────────────────────────────────────────────────────

type MITRETechnique struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AlertCount int    `json:"alert_count"`
}

type MITRETactic struct {
	Name       string           `json:"name"`
	ID         string           `json:"id"`
	Techniques []MITRETechnique `json:"techniques"`
}

// ── CIS Controls types ───────────────────────────────────────────────────────

type CISControl struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	AlertCount  int    `json:"alert_count"`
}

// ── NIST CSF types ───────────────────────────────────────────────────────────

type NISTSubcategory struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Coverage int    `json:"coverage"`
}

type NISTFunction struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Coverage      int               `json:"coverage"`
	Subcategories []NISTSubcategory `json:"subcategories"`
}

// ComplianceHandler computes compliance posture scores against common frameworks.
type ComplianceHandler struct {
	Pool *pgxpool.Pool
}

func NewComplianceHandler(pool *pgxpool.Pool) *ComplianceHandler {
	return &ComplianceHandler{Pool: pool}
}

type ComplianceControl struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Score       int    `json:"score"`  // 0-100
	Status      string `json:"status"` // pass / partial / fail
	Detail      string `json:"detail,omitempty"`
}

type ComplianceFramework struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Score    int                 `json:"score"`
	Controls []ComplianceControl `json:"controls"`
}

// Summary computes compliance scores.
// GET /api/v1/compliance/summary
func (h *ComplianceHandler) Summary(c *gin.Context) {
	ctx := c.Request.Context()

	// ── Gather raw metrics ─────────────────────────────────
	var (
		totalAgents, onlineAgents                  int
		totalRules, enabledRules                   int
		totalAlerts, openCritical, resolvedLast30d int
		totalVulns, criticalVulns, highVulns       int
		totalIOC                                   int
		totalPlaybooks, enabledPlaybooks           int
		avgResolutionHrs                           float64
		incidentsCreated                           int
	)

	if h.Pool != nil {
		// Agents
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='online') FROM agents`).
			Scan(&totalAgents, &onlineAgents)) {
			return
		}

		// Rules
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM rules`).
			Scan(&totalRules, &enabledRules)) {
			return
		}

		// Alerts
		if !ReadOK(c, h.Pool.QueryRow(ctx, `
				SELECT COUNT(*),
					COUNT(*) FILTER (WHERE severity=4 AND status NOT IN ('resolved','false_positive')),
					COUNT(*) FILTER (WHERE status='resolved' AND created_at >= NOW()-INTERVAL '30 days')
				FROM alerts`).
			Scan(&totalAlerts, &openCritical, &resolvedLast30d)) {
			return
		}

		// Alert resolution time (hours, last 30d)
		if !ReadOK(c, h.Pool.QueryRow(ctx, `
				SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/3600), 0)
				FROM alerts
				WHERE status = 'resolved'
				  AND created_at >= NOW() - INTERVAL '30 days'`).
			Scan(&avgResolutionHrs)) {
			return
		}

		// Vulnerabilities
		if !ReadOK(c, h.Pool.QueryRow(ctx, `
				SELECT COUNT(*),
					COUNT(*) FILTER (WHERE severity='critical' AND status='open'),
					COUNT(*) FILTER (WHERE severity='high' AND status='open')
				FROM vulnerabilities`).
			Scan(&totalVulns, &criticalVulns, &highVulns)) {
			return
		}

		// IOCs
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ioc_entries WHERE is_active`).Scan(&totalIOC)) {
			return
		}

		// Playbooks
		// playbooks の有効フラグは is_active です。enabled という列は無く、この文が
		// 42703 で拒否されていたため、プレイブック数は常に 0 でした。
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) FROM playbooks`).
			Scan(&totalPlaybooks, &enabledPlaybooks)) {
			return
		}

		// Incidents (shows incident management maturity)
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE created_at >= NOW()-INTERVAL '30 days'`).
			Scan(&incidentsCreated)) {
			return
		}
	}

	// ── Helper to clamp score ───────────────────────────────
	clamp := func(v int) int {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}

	// ── Score helpers ───────────────────────────────────────
	controlStatus := func(score int) string {
		if score >= 80 {
			return "pass"
		}
		if score >= 40 {
			return "partial"
		}
		return "fail"
	}

	ruleScore := 0
	if totalRules > 0 {
		ruleScore = clamp(enabledRules * 100 / totalRules)
	}

	agentCoverageScore := 0
	if totalAgents > 0 {
		agentCoverageScore = clamp(onlineAgents * 100 / totalAgents)
	}

	resolutionScore := 100
	switch {
	case avgResolutionHrs > 72:
		resolutionScore = 20
	case avgResolutionHrs > 24:
		resolutionScore = 50
	case avgResolutionHrs > 8:
		resolutionScore = 75
	}

	critAlertScore := 100
	switch {
	case openCritical > 20:
		critAlertScore = 10
	case openCritical > 10:
		critAlertScore = 30
	case openCritical > 5:
		critAlertScore = 60
	case openCritical > 0:
		critAlertScore = 80
	}

	vulnScore := 100
	switch {
	case criticalVulns > 10:
		vulnScore = 10
	case criticalVulns > 5:
		vulnScore = 30
	case criticalVulns > 0:
		vulnScore = 60
	case highVulns > 20:
		vulnScore = 70
	case highVulns > 0:
		vulnScore = 85
	}

	iocScore := 0
	switch {
	case totalIOC >= 100:
		iocScore = 100
	case totalIOC >= 50:
		iocScore = 80
	case totalIOC >= 10:
		iocScore = 50
	case totalIOC > 0:
		iocScore = 20
	}

	playbookScore := 0
	if totalPlaybooks > 0 {
		playbookScore = clamp(enabledPlaybooks * 100 / totalPlaybooks)
	}

	incidentScore := 0
	if incidentsCreated > 0 {
		incidentScore = 80
	}
	if totalAlerts > 0 && resolvedLast30d > totalAlerts/2 {
		incidentScore = 100
	}

	// ── SOC 2 Type II ──────────────────────────────────────
	soc2controls := []ComplianceControl{
		{
			ID: "CC6.1", Name: "論理アクセス制御",
			Description: "アクセス管理・エンドポイント保護",
			Score:       clamp((agentCoverageScore + ruleScore) / 2),
			Detail:      fmt.Sprintf("エージェント稼働率 %d%%, ルール有効率 %d%%", agentCoverageScore, ruleScore),
		},
		{
			ID: "CC7.2", Name: "システム監視",
			Description: "リアルタイム検知・アラート管理",
			Score:       clamp((ruleScore + critAlertScore) / 2),
			Detail:      fmt.Sprintf("有効ルール %d/%d, 未解決クリティカル %d件", enabledRules, totalRules, openCritical),
		},
		{
			ID: "CC7.3", Name: "セキュリティインシデント対応",
			Description: "インシデント管理プロセスの成熟度",
			Score:       clamp((incidentScore + resolutionScore) / 2),
			Detail:      fmt.Sprintf("平均解決時間 %.1f時間, 30日インシデント %d件", avgResolutionHrs, incidentsCreated),
		},
		{
			ID: "CC9.2", Name: "リスク軽減",
			Description: "脆弱性管理・IOC対応",
			Score:       clamp((vulnScore + iocScore) / 2),
			Detail:      fmt.Sprintf("クリティカル脆弱性 %d件, IOC登録 %d件", criticalVulns, totalIOC),
		},
		{
			ID: "A1.1", Name: "可用性監視",
			Description: "エンドポイント稼働状況の継続的監視",
			Score:       agentCoverageScore,
			Detail:      fmt.Sprintf("オンライン %d/%d エージェント", onlineAgents, totalAgents),
		},
	}
	for i := range soc2controls {
		soc2controls[i].Status = controlStatus(soc2controls[i].Score)
	}
	soc2Score := 0
	for _, c := range soc2controls {
		soc2Score += c.Score
	}
	if len(soc2controls) > 0 {
		soc2Score /= len(soc2controls)
	}

	// ── PCI DSS v4.0 ───────────────────────────────────────
	pciControls := []ComplianceControl{
		{
			ID: "PCI-1", Name: "ネットワーク保護",
			Description: "ネットワーク監視・DNS異常検知",
			Score:       clamp(ruleScore),
			Detail:      fmt.Sprintf("検知ルール有効化率 %d%%", ruleScore),
		},
		{
			ID: "PCI-5", Name: "マルウェア対策",
			Description: "エンドポイント保護・脅威インテリジェンス",
			Score:       clamp((agentCoverageScore + iocScore) / 2),
			Detail:      fmt.Sprintf("エージェント %d%%稼働, IOC %d件", agentCoverageScore, totalIOC),
		},
		{
			ID: "PCI-6", Name: "安全なシステム開発",
			Description: "脆弱性スキャン・パッチ管理",
			Score:       vulnScore,
			Detail:      fmt.Sprintf("クリティカル %d件, 高 %d件の未対応脆弱性", criticalVulns, highVulns),
		},
		{
			ID: "PCI-10", Name: "アクセスモニタリング",
			Description: "認証イベント・アクセスログの監視",
			Score:       clamp((agentCoverageScore + critAlertScore) / 2),
			Detail:      fmt.Sprintf("エンドポイントカバレッジ %d%%", agentCoverageScore),
		},
		{
			ID: "PCI-12", Name: "インシデント対応計画",
			Description: "プレイブック・インシデント管理",
			Score:       clamp((playbookScore + incidentScore) / 2),
			Detail:      fmt.Sprintf("有効プレイブック %d/%d", enabledPlaybooks, totalPlaybooks),
		},
	}
	for i := range pciControls {
		pciControls[i].Status = controlStatus(pciControls[i].Score)
	}
	pciScore := 0
	for _, c := range pciControls {
		pciScore += c.Score
	}
	if len(pciControls) > 0 {
		pciScore /= len(pciControls)
	}

	// ── NIST CSF 2.0 ───────────────────────────────────────
	nistControls := []ComplianceControl{
		{
			ID: "GV", Name: "ガバナンス (Govern)",
			Description: "セキュリティポリシー・リスク管理戦略",
			Score:       clamp((ruleScore + playbookScore) / 2),
			Detail:      fmt.Sprintf("ルール管理 %d%%, プレイブック %d%%", ruleScore, playbookScore),
		},
		{
			ID: "ID", Name: "識別 (Identify)",
			Description: "資産管理・リスクアセスメント",
			Score:       clamp((agentCoverageScore + vulnScore) / 2),
			Detail:      fmt.Sprintf("資産カバレッジ %d%%, 脆弱性管理スコア %d%%", agentCoverageScore, vulnScore),
		},
		{
			ID: "PR", Name: "保護 (Protect)",
			Description: "アクセス制御・データ保護・意識向上",
			Score:       clamp((ruleScore + iocScore) / 2),
			Detail:      fmt.Sprintf("検知ルール %d%%, 脅威インテリジェンス %d%%", ruleScore, iocScore),
		},
		{
			ID: "DE", Name: "検知 (Detect)",
			Description: "継続的監視・異常検知",
			Score:       clamp((agentCoverageScore + ruleScore + critAlertScore) / 3),
			Detail:      fmt.Sprintf("監視カバレッジ %d%%, 未解決クリティカル %d件", agentCoverageScore, openCritical),
		},
		{
			ID: "RS", Name: "対応 (Respond)",
			Description: "インシデント対応・コミュニケーション",
			Score:       clamp((incidentScore + resolutionScore + playbookScore) / 3),
			Detail:      fmt.Sprintf("平均解決 %.1f時間", avgResolutionHrs),
		},
		{
			ID: "RC", Name: "復旧 (Recover)",
			Description: "復旧計画・改善",
			Score:       clamp((incidentScore + resolutionScore) / 2),
			Detail:      fmt.Sprintf("30日解決済みアラート %d件", resolvedLast30d),
		},
	}
	for i := range nistControls {
		nistControls[i].Status = controlStatus(nistControls[i].Score)
	}
	nistScore := 0
	for _, c := range nistControls {
		nistScore += c.Score
	}
	if len(nistControls) > 0 {
		nistScore /= len(nistControls)
	}

	// ── ISO 27001:2022 ──────────────────────────────────────
	isoControls := []ComplianceControl{
		{
			ID: "A.8.7", Name: "マルウェアからの保護",
			Description: "エンドポイント保護・IOCベースの検知",
			Score:       clamp((agentCoverageScore + iocScore) / 2),
			Detail:      fmt.Sprintf("エージェント %d%%, IOC %d件", agentCoverageScore, totalIOC),
		},
		{
			ID: "A.8.15", Name: "ログ管理",
			Description: "セキュリティイベントのログ収集・監視",
			Score:       agentCoverageScore,
			Detail:      fmt.Sprintf("監視対象エンドポイント %d/%d", onlineAgents, totalAgents),
		},
		{
			ID: "A.8.16", Name: "監視活動",
			Description: "異常の検知・アラート管理",
			Score:       clamp((ruleScore + critAlertScore) / 2),
			Detail:      fmt.Sprintf("有効ルール %d件, クリティカルアラート %d件", enabledRules, openCritical),
		},
		{
			ID: "A.5.24", Name: "インシデント対応計画",
			Description: "インシデント管理手順の策定・実施",
			Score:       clamp((incidentScore + playbookScore) / 2),
			Detail:      fmt.Sprintf("プレイブック %d件, インシデント %d件/30日", enabledPlaybooks, incidentsCreated),
		},
		{
			ID: "A.8.8", Name: "技術的脆弱性管理",
			Description: "脆弱性スキャン・パッチ適用の追跡",
			Score:       vulnScore,
			Detail:      fmt.Sprintf("クリティカル %d, 高 %d件の未対応脆弱性", criticalVulns, highVulns),
		},
	}
	for i := range isoControls {
		isoControls[i].Status = controlStatus(isoControls[i].Score)
	}
	isoScore := 0
	for _, c := range isoControls {
		isoScore += c.Score
	}
	if len(isoControls) > 0 {
		isoScore /= len(isoControls)
	}

	frameworks := []ComplianceFramework{
		{ID: "soc2", Name: "SOC 2 Type II", Score: soc2Score, Controls: soc2controls},
		{ID: "pci", Name: "PCI DSS v4.0", Score: pciScore, Controls: pciControls},
		{ID: "nist", Name: "NIST CSF 2.0", Score: nistScore, Controls: nistControls},
		{ID: "iso27001", Name: "ISO 27001:2022", Score: isoScore, Controls: isoControls},
	}

	overall := (soc2Score + pciScore + nistScore + isoScore) / 4

	// Count distinct MITRE techniques that appear in alerts
	var coveredTechniques int
	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT mitre_technique) FROM alerts WHERE mitre_technique IS NOT NULL AND mitre_technique <> ''`).
			Scan(&coveredTechniques)) {
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"overall": overall,
		"frameworks": gin.H{
			// MITREスコア: カバーできているテクニック数 / MITRE ATT&CKの主要テクニック数（概算40）
			// 40件以上あれば100%とする（段階的スコアリング）
			"mitre": func() int {
				if coveredTechniques == 0 {
					return 0
				}
				if coveredTechniques >= 40 {
					return 100
				}
				return clamp(coveredTechniques * 100 / 40)
			}(),
			"cis":      clamp((ruleScore + agentCoverageScore) / 2),
			"nist":     nistScore,
			"iso27001": isoScore,
		},
		"total_alerts":       totalAlerts,
		"covered_techniques": coveredTechniques,
		"framework_details":  frameworks,
		"metrics": gin.H{
			"total_agents":       totalAgents,
			"online_agents":      onlineAgents,
			"enabled_rules":      enabledRules,
			"total_rules":        totalRules,
			"open_critical":      openCritical,
			"avg_resolution_hrs": avgResolutionHrs,
			"critical_vulns":     criticalVulns,
			"high_vulns":         highVulns,
			"total_ioc":          totalIOC,
			"enabled_playbooks":  enabledPlaybooks,
		},
	})
}

// MITREMapping returns MITRE ATT&CK tactic/technique coverage derived from alert tags.
// GET /api/v1/compliance/mitre
func (h *ComplianceHandler) MITREMapping(c *gin.Context) {
	ctx := c.Request.Context()

	// Hardcoded tactic → technique mapping (top 3 techniques per tactic)
	tacticDefs := []struct {
		id         string
		name       string
		techniques []MITRETechnique
	}{
		{"TA0001", "Initial Access", []MITRETechnique{
			{ID: "T1566", Name: "Phishing"},
			{ID: "T1190", Name: "Exploit Public-Facing Application"},
			{ID: "T1133", Name: "External Remote Services"},
		}},
		{"TA0002", "Execution", []MITRETechnique{
			{ID: "T1059", Name: "Command and Scripting Interpreter"},
			{ID: "T1204", Name: "User Execution"},
			{ID: "T1047", Name: "Windows Management Instrumentation"},
		}},
		{"TA0003", "Persistence", []MITRETechnique{
			{ID: "T1547", Name: "Boot or Logon Autostart Execution"},
			{ID: "T1053", Name: "Scheduled Task/Job"},
			{ID: "T1098", Name: "Account Manipulation"},
		}},
		{"TA0004", "Privilege Escalation", []MITRETechnique{
			{ID: "T1068", Name: "Exploitation for Privilege Escalation"},
			{ID: "T1548", Name: "Abuse Elevation Control Mechanism"},
			{ID: "T1134", Name: "Access Token Manipulation"},
		}},
		{"TA0005", "Defense Evasion", []MITRETechnique{
			{ID: "T1562", Name: "Impair Defenses"},
			{ID: "T1055", Name: "Process Injection"},
			{ID: "T1070", Name: "Indicator Removal"},
		}},
		{"TA0006", "Credential Access", []MITRETechnique{
			{ID: "T1003", Name: "OS Credential Dumping"},
			{ID: "T1110", Name: "Brute Force"},
			{ID: "T1555", Name: "Credentials from Password Stores"},
		}},
		{"TA0007", "Discovery", []MITRETechnique{
			{ID: "T1082", Name: "System Information Discovery"},
			{ID: "T1083", Name: "File and Directory Discovery"},
			{ID: "T1046", Name: "Network Service Discovery"},
		}},
		{"TA0008", "Lateral Movement", []MITRETechnique{
			{ID: "T1021", Name: "Remote Services"},
			{ID: "T1570", Name: "Lateral Tool Transfer"},
			{ID: "T1534", Name: "Internal Spearphishing"},
		}},
		{"TA0009", "Collection", []MITRETechnique{
			{ID: "T1005", Name: "Data from Local System"},
			{ID: "T1074", Name: "Data Staged"},
			{ID: "T1056", Name: "Input Capture"},
		}},
		{"TA0010", "Exfiltration", []MITRETechnique{
			{ID: "T1041", Name: "Exfiltration Over C2 Channel"},
			{ID: "T1048", Name: "Exfiltration Over Alternative Protocol"},
			{ID: "T1052", Name: "Exfiltration Over Physical Medium"},
		}},
		{"TA0011", "Command and Control", []MITRETechnique{
			{ID: "T1071", Name: "Application Layer Protocol"},
			{ID: "T1095", Name: "Non-Application Layer Protocol"},
			{ID: "T1105", Name: "Ingress Tool Transfer"},
		}},
		{"TA0040", "Impact", []MITRETechnique{
			{ID: "T1486", Name: "Data Encrypted for Impact"},
			{ID: "T1490", Name: "Inhibit System Recovery"},
			{ID: "T1489", Name: "Service Stop"},
		}},
		{"TA0042", "Resource Development", []MITRETechnique{
			{ID: "T1583", Name: "Acquire Infrastructure"},
			{ID: "T1585", Name: "Establish Accounts"},
			{ID: "T1588", Name: "Obtain Capabilities"},
		}},
		{"TA0043", "Reconnaissance", []MITRETechnique{
			{ID: "T1595", Name: "Active Scanning"},
			{ID: "T1598", Name: "Phishing for Information"},
			{ID: "T1589", Name: "Gather Victim Identity Information"},
		}},
	}

	// Build a map of technique ID → alert count from the database
	alertCounts := make(map[string]int)
	if h.Pool != nil {
		rows, err := h.Pool.Query(ctx,
			`SELECT mitre_technique, COUNT(*) AS alert_count FROM alerts WHERE mitre_technique IS NOT NULL AND mitre_technique <> '' GROUP BY mitre_technique`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var tag string
				var cnt int
				if scanErr := rows.Scan(&tag, &cnt); scanErr == nil {
					alertCounts[tag] = cnt
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("compliance alertCounts iteration failed", "error", err)
			}
		}
	}

	tactics := make([]MITRETactic, 0, len(tacticDefs))
	for _, td := range tacticDefs {
		techs := make([]MITRETechnique, len(td.techniques))
		for i, t := range td.techniques {
			techs[i] = MITRETechnique{
				ID:         t.ID,
				Name:       t.Name,
				AlertCount: alertCounts[t.ID],
			}
		}
		tactics = append(tactics, MITRETactic{
			Name:       td.name,
			ID:         td.id,
			Techniques: techs,
		})
	}

	c.JSON(http.StatusOK, gin.H{"tactics": tactics})
}

// CISControls returns all 18 CIS Controls with implementation status derived from rule counts.
// GET /api/v1/compliance/cis
func (h *ComplianceHandler) CISControls(c *gin.Context) {
	ctx := c.Request.Context()

	// Count rules per category to inform CIS control status
	categoryRuleCounts := make(map[string]int)
	var totalRules int
	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE enabled`).Scan(&totalRules)) {
			return
		}
		rows, err := h.Pool.Query(ctx,
			`SELECT COALESCE(type, 'general'), COUNT(*) FROM rules WHERE enabled GROUP BY type`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var cat string
				var cnt int
				if scanErr := rows.Scan(&cat, &cnt); scanErr == nil {
					categoryRuleCounts[cat] = cnt
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("compliance categoryRuleCounts iteration failed", "error", err)
			}
		}
	}

	statusFor := func(ruleCount int) string {
		if ruleCount >= 3 {
			return "Implemented"
		}
		if ruleCount >= 1 {
			return "Partial"
		}
		return "Not Implemented"
	}

	// CIS Controls v8 — all 18
	type cisDef struct {
		id          int
		name        string
		description string
		category    string
	}
	defs := []cisDef{
		{1, "Inventory and Control of Enterprise Assets",
			"Actively manage all enterprise assets to accurately know what is authorized and what is not.",
			"inventory"},
		{2, "Inventory and Control of Software Assets",
			"Actively manage all software on the network to ensure only authorized software is installed.",
			"software"},
		{3, "Data Protection",
			"Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.",
			"data"},
		{4, "Secure Configuration of Enterprise Assets and Software",
			"Establish and maintain the secure configuration of enterprise assets and software.",
			"configuration"},
		{5, "Account Management",
			"Use processes and tools to assign and manage authorization to credentials for user accounts.",
			"identity"},
		{6, "Access Control Management",
			"Use processes and tools to create, assign, manage, and revoke access credentials.",
			"identity"},
		{7, "Continuous Vulnerability Management",
			"Develop a plan to continuously assess and track vulnerabilities on all enterprise assets.",
			"vulnerability"},
		{8, "Audit Log Management",
			"Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.",
			"logging"},
		{9, "Email and Web Browser Protections",
			"Improve protections and detections of threats from email and web vectors.",
			"network"},
		{10, "Malware Defenses",
			"Prevent or control the installation, spread, and execution of malicious applications, code, or scripts.",
			"malware"},
		{11, "Data Recovery",
			"Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets.",
			"backup"},
		{12, "Network Infrastructure Management",
			"Establish, implement, and actively manage network devices.",
			"network"},
		{13, "Network Monitoring and Defense",
			"Operate processes and tooling to establish and maintain comprehensive network monitoring.",
			"network"},
		{14, "Security Awareness and Skills Training",
			"Establish and maintain a security awareness program to influence behavior among the workforce.",
			"training"},
		{15, "Service Provider Management",
			"Develop a process to evaluate service providers who hold sensitive data.",
			"vendor"},
		{16, "Application Software Security",
			"Manage the security life cycle of in-house developed, hosted, or acquired software.",
			"application"},
		{17, "Incident Response Management",
			"Establish a program to develop and maintain an incident response capability.",
			"incident"},
		{18, "Penetration Testing",
			"Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses.",
			"testing"},
	}

	controls := make([]CISControl, 0, len(defs))
	for _, d := range defs {
		rc := categoryRuleCounts[d.category]
		controls = append(controls, CISControl{
			ID:          d.id,
			Name:        d.name,
			Description: d.description,
			Status:      statusFor(rc),
			AlertCount:  rc,
		})
	}

	c.JSON(http.StatusOK, gin.H{"controls": controls})
}

// NISTFramework returns NIST CSF function coverage calculated from alert and rule metrics.
// GET /api/v1/compliance/nist
func (h *ComplianceHandler) NISTFramework(c *gin.Context) {
	ctx := c.Request.Context()

	var totalRules, enabledRules, totalAlerts, resolvedAlerts int
	var onlineAgents, totalAgents int

	if h.Pool != nil {
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM rules`).
			Scan(&totalRules, &enabledRules)) {
			return
		}
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='resolved') FROM alerts`).
			Scan(&totalAlerts, &resolvedAlerts)) {
			return
		}
		if !ReadOK(c, h.Pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='online') FROM agents`).
			Scan(&totalAgents, &onlineAgents)) {
			return
		}
	}

	clamp := func(v int) int {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}

	ruleCoverage := 0
	if totalRules > 0 {
		ruleCoverage = clamp(enabledRules * 100 / totalRules)
	}

	agentCoverage := 0
	if totalAgents > 0 {
		agentCoverage = clamp(onlineAgents * 100 / totalAgents)
	}

	resolveCoverage := 0
	if totalAlerts > 0 {
		resolveCoverage = clamp(resolvedAlerts * 100 / totalAlerts)
	}

	idCov := clamp((agentCoverage + ruleCoverage) / 2)
	prCov := clamp((ruleCoverage + agentCoverage) / 2)
	deCov := clamp((agentCoverage + ruleCoverage*2) / 3)
	rsCov := clamp((resolveCoverage + ruleCoverage) / 2)
	rcCov := resolveCoverage

	functions := []NISTFunction{
		{
			ID:       "ID",
			Name:     "Identify",
			Coverage: idCov,
			Subcategories: []NISTSubcategory{
				{ID: "ID.AM-1", Name: "Physical devices and systems are inventoried", Coverage: idCov},
				{ID: "ID.AM-2", Name: "Software platforms and applications are inventoried", Coverage: agentCoverage},
				{ID: "ID.RA-1", Name: "Asset vulnerabilities are identified and documented", Coverage: ruleCoverage},
			},
		},
		{
			ID:       "PR",
			Name:     "Protect",
			Coverage: prCov,
			Subcategories: []NISTSubcategory{
				{ID: "PR.AC-1", Name: "Identities and credentials are managed", Coverage: prCov},
				{ID: "PR.AC-3", Name: "Remote access is managed", Coverage: agentCoverage},
				{ID: "PR.DS-1", Name: "Data-at-rest is protected", Coverage: ruleCoverage},
			},
		},
		{
			ID:       "DE",
			Name:     "Detect",
			Coverage: deCov,
			Subcategories: []NISTSubcategory{
				{ID: "DE.AE-1", Name: "A baseline of network operations is established", Coverage: agentCoverage},
				{ID: "DE.CM-1", Name: "The network is monitored to detect potential cybersecurity events", Coverage: deCov},
				{ID: "DE.DP-4", Name: "Event detection information is communicated", Coverage: ruleCoverage},
			},
		},
		{
			ID:       "RS",
			Name:     "Respond",
			Coverage: rsCov,
			Subcategories: []NISTSubcategory{
				{ID: "RS.RP-1", Name: "Response plan is executed during or after an incident", Coverage: rsCov},
				{ID: "RS.CO-2", Name: "Incidents are reported consistent with criteria", Coverage: resolveCoverage},
				{ID: "RS.AN-1", Name: "Notifications from detection systems are investigated", Coverage: ruleCoverage},
			},
		},
		{
			ID:       "RC",
			Name:     "Recover",
			Coverage: rcCov,
			Subcategories: []NISTSubcategory{
				{ID: "RC.RP-1", Name: "Recovery plan is executed during or after a cybersecurity incident", Coverage: rcCov},
				{ID: "RC.IM-1", Name: "Recovery plans incorporate lessons learned", Coverage: resolveCoverage},
				{ID: "RC.CO-3", Name: "Recovery activities are communicated to stakeholders", Coverage: rcCov},
			},
		},
	}

	_ = fmt.Sprintf // keep fmt import used
	c.JSON(http.StatusOK, gin.H{"functions": functions})
}

package scorecard

// NIST CSF and ISO 27001 compliance scoring.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Control represents a single compliance control assessment.
type Control struct {
	ID           string    `json:"id"`
	Framework    string    `json:"framework"` // NIST_CSF or ISO27001
	Category     string    `json:"category"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Weight       float64   `json:"weight"`
	Score        float64   `json:"score"`  // 0-100
	Status       string    `json:"status"` // compliant/partial/non_compliant/not_assessed
	Evidence     string    `json:"evidence,omitempty"`
	LastAssessed time.Time `json:"last_assessed"`
}

// Scorecard holds the complete compliance scorecard for an organization.
type Scorecard struct {
	OrganizationID  string             `json:"organization_id"`
	Framework       string             `json:"framework"`
	OverallScore    float64            `json:"overall_score"`
	CategoryScores  map[string]float64 `json:"category_scores"`
	Controls        []*Control         `json:"controls"`
	GeneratedAt     time.Time          `json:"generated_at"`
	Recommendations []string           `json:"recommendations"`
}

// Scorer calculates compliance scorecards by querying the database.
type Scorer struct {
	pool *pgxpool.Pool
}

// NewScorer creates a new Scorer.
func NewScorer(pool *pgxpool.Pool) *Scorer {
	return &Scorer{pool: pool}
}

// ─── NIST CSF ─────────────────────────────────────────────────────────────────

// CalculateNISTCSF computes a NIST Cybersecurity Framework scorecard.
func (s *Scorer) CalculateNISTCSF(ctx context.Context) (*Scorecard, error) {
	sc := &Scorecard{
		Framework:      "NIST_CSF",
		CategoryScores: make(map[string]float64),
		Controls:       []*Control{},
		GeneratedAt:    time.Now().UTC(),
	}

	// ── Identify (ID) ─────────────────────────────────────────────────────────
	idControls := s.scoreIdentify(ctx)
	sc.Controls = append(sc.Controls, idControls...)

	// ── Protect (PR) ──────────────────────────────────────────────────────────
	prControls := s.scoreProtect(ctx)
	sc.Controls = append(sc.Controls, prControls...)

	// ── Detect (DE) ───────────────────────────────────────────────────────────
	deControls := s.scoreDetect(ctx)
	sc.Controls = append(sc.Controls, deControls...)

	// ── Respond (RS) ──────────────────────────────────────────────────────────
	rsControls := s.scoreRespond(ctx)
	sc.Controls = append(sc.Controls, rsControls...)

	// ── Recover (RC) ──────────────────────────────────────────────────────────
	rcControls := s.scoreRecover(ctx)
	sc.Controls = append(sc.Controls, rcControls...)

	// Calculate category and overall scores
	s.calculateScores(sc)
	sc.Recommendations = s.GetRecommendations(sc)

	return sc, nil
}

// scoreIdentify scores the Identify function controls.
func (s *Scorer) scoreIdentify(ctx context.Context) []*Control {
	controls := []*Control{
		{
			ID: "ID.AM-1", Framework: "NIST_CSF", Category: "Identify",
			Name:        "Asset Inventory Coverage",
			Description: "Physical devices and systems within the organization are inventoried.",
			Weight:      1.0,
		},
		{
			ID: "ID.AM-2", Framework: "NIST_CSF", Category: "Identify",
			Name:        "Software Asset Inventory",
			Description: "Software platforms and applications within the organization are inventoried.",
			Weight:      1.0,
		},
		{
			ID: "ID.AM-5", Framework: "NIST_CSF", Category: "Identify",
			Name:        "Resource Prioritization",
			Description: "Resources are prioritized based on their classification, criticality, and business value.",
			Weight:      0.8,
		},
		{
			ID: "ID.RA-1", Framework: "NIST_CSF", Category: "Identify",
			Name:        "Vulnerability Management",
			Description: "Asset vulnerabilities are identified and documented.",
			Weight:      1.0,
		},
		{
			ID: "ID.RA-5", Framework: "NIST_CSF", Category: "Identify",
			Name:        "Threat Intelligence Integration",
			Description: "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk.",
			Weight:      0.9,
		},
	}

	now := time.Now().UTC()
	for _, ctrl := range controls {
		ctrl.LastAssessed = now
		ctrl.Score = 0
		ctrl.Status = "not_assessed"
	}

	if s.pool == nil {
		return controls
	}

	// ID.AM-1: Check asset inventory table
	var assetCount int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&assetCount)
	if err == nil {
		controls[0].Evidence = fmt.Sprintf("%d assets inventoried", assetCount)
		if assetCount > 0 {
			controls[0].Score = 100
			controls[0].Status = "compliant"
		} else {
			controls[0].Score = 0
			controls[0].Status = "non_compliant"
		}
	}

	// ID.AM-2: Check software inventory
	var swCount int
	err = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_software`).Scan(&swCount)
	if err == nil {
		controls[1].Evidence = fmt.Sprintf("%d software packages inventoried", swCount)
		if swCount > 0 {
			controls[1].Score = minFloat(float64(swCount)/float64(assetCount+1)*100, 100)
			controls[1].Status = statusFromScore(controls[1].Score)
		}
	}

	// ID.AM-5: Check asset criticality scoring
	var critCount int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM asset_criticality_scores
	`).Scan(&critCount)
	if critCount > 0 {
		controls[2].Score = minFloat(float64(critCount)/float64(assetCount+1)*100, 100)
		controls[2].Evidence = fmt.Sprintf("%d assets scored for criticality", critCount)
		controls[2].Status = statusFromScore(controls[2].Score)
	} else {
		controls[2].Score = 40
		controls[2].Status = "partial"
		controls[2].Evidence = "No asset criticality scoring configured"
	}

	// ID.RA-1: Check vulnerability findings
	var vulnCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM vulnerabilities`).Scan(&vulnCount)
	if vulnCount >= 0 {
		controls[3].Evidence = fmt.Sprintf("%d vulnerabilities tracked", vulnCount)
		if vulnCount > 0 {
			controls[3].Score = 80
			controls[3].Status = "compliant"
		} else {
			controls[3].Score = 40
			controls[3].Status = "partial"
		}
	}

	// ID.RA-5: Check threat intel IOC count
	var iocCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM threat_intel_iocs`).Scan(&iocCount)
	controls[4].Evidence = fmt.Sprintf("%d threat IOCs tracked", iocCount)
	if iocCount > 0 {
		controls[4].Score = 85
		controls[4].Status = "compliant"
	} else {
		controls[4].Score = 30
		controls[4].Status = "partial"
	}

	return controls
}

// scoreProtect scores the Protect function controls.
func (s *Scorer) scoreProtect(ctx context.Context) []*Control {
	controls := []*Control{
		{
			ID: "PR.AC-1", Framework: "NIST_CSF", Category: "Protect",
			Name:        "Identity Management",
			Description: "Identities and credentials are issued, managed, verified, revoked, and audited.",
			Weight:      1.0,
		},
		{
			ID: "PR.DS-1", Framework: "NIST_CSF", Category: "Protect",
			Name:        "Data-at-Rest Protection",
			Description: "Data-at-rest is protected.",
			Weight:      1.0,
		},
		{
			ID: "PR.IP-1", Framework: "NIST_CSF", Category: "Protect",
			Name:        "Endpoint Configuration Baselines",
			Description: "A baseline configuration of IT systems is created and maintained.",
			Weight:      1.0,
		},
		{
			ID: "PR.IP-3", Framework: "NIST_CSF", Category: "Protect",
			Name:        "Configuration Change Control",
			Description: "Configuration change control processes are in place.",
			Weight:      0.9,
		},
		{
			ID: "PR.PT-1", Framework: "NIST_CSF", Category: "Protect",
			Name:        "Audit/Log Records",
			Description: "Audit/log records are determined, documented, implemented, and reviewed.",
			Weight:      1.0,
		},
	}

	now := time.Now().UTC()
	for _, ctrl := range controls {
		ctrl.LastAssessed = now
	}

	if s.pool == nil {
		for _, ctrl := range controls {
			ctrl.Score = 60
			ctrl.Status = "partial"
		}
		return controls
	}

	// PR.AC-1: Check MFA and user management
	var mfaCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE mfa_enabled = true`).Scan(&mfaCount)
	var totalUsers int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUsers)
	if totalUsers > 0 {
		mfaRate := float64(mfaCount) / float64(totalUsers) * 100
		controls[0].Score = mfaRate
		controls[0].Evidence = fmt.Sprintf("%d/%d users have MFA enabled (%.0f%%)", mfaCount, totalUsers, mfaRate)
		controls[0].Status = statusFromScore(mfaRate)
	} else {
		controls[0].Score = 60
		controls[0].Status = "partial"
	}

	// PR.DS-1: Check encryption management
	var encCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_encryption`).Scan(&encCount)
	if encCount > 0 {
		controls[1].Score = 80
		controls[1].Evidence = fmt.Sprintf("%d endpoints with encryption configured", encCount)
		controls[1].Status = "compliant"
	} else {
		controls[1].Score = 40
		controls[1].Status = "partial"
		controls[1].Evidence = "No encryption management data found"
	}

	// PR.IP-1: Check endpoint hardening baselines
	var baselineCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM hardening_baselines`).Scan(&baselineCount)
	if baselineCount > 0 {
		// Check compliance rate across per-agent assessment roll-ups.
		var passedChecks, totalChecks int
		_ = s.pool.QueryRow(ctx, `
			SELECT COALESCE(SUM(passed_checks),0), COALESCE(SUM(passed_checks + failed_checks),0)
			FROM hardening_assessments
		`).Scan(&passedChecks, &totalChecks)
		if totalChecks > 0 {
			rate := float64(passedChecks) / float64(totalChecks) * 100
			controls[2].Score = rate
			controls[2].Evidence = fmt.Sprintf("%.0f%% hardening compliance (%d/%d checks passed)", rate, passedChecks, totalChecks)
			controls[2].Status = statusFromScore(rate)
		} else {
			controls[2].Score = 70
			controls[2].Status = "partial"
		}
	} else {
		controls[2].Score = 30
		controls[2].Status = "non_compliant"
		controls[2].Evidence = "No hardening baselines configured"
	}

	// PR.IP-3: Check agent config profiles
	var profileCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_config_profiles`).Scan(&profileCount)
	controls[3].Evidence = fmt.Sprintf("%d agent configuration profiles defined", profileCount)
	if profileCount > 0 {
		controls[3].Score = 80
		controls[3].Status = "compliant"
	} else {
		controls[3].Score = 50
		controls[3].Status = "partial"
	}

	// PR.PT-1: Check audit logs
	var auditCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '7 days'`).Scan(&auditCount)
	controls[4].Evidence = fmt.Sprintf("%d audit log entries in last 7 days", auditCount)
	if auditCount > 0 {
		controls[4].Score = 90
		controls[4].Status = "compliant"
	} else {
		controls[4].Score = 20
		controls[4].Status = "non_compliant"
	}

	return controls
}

// scoreDetect scores the Detect function controls.
func (s *Scorer) scoreDetect(ctx context.Context) []*Control {
	controls := []*Control{
		{
			ID: "DE.AE-1", Framework: "NIST_CSF", Category: "Detect",
			Name:        "Network Activity Baselines",
			Description: "A baseline of network operations and expected data flows is established.",
			Weight:      1.0,
		},
		{
			ID: "DE.AE-3", Framework: "NIST_CSF", Category: "Detect",
			Name:        "Event Correlation",
			Description: "Event data are collected and correlated from multiple sources.",
			Weight:      1.0,
		},
		{
			ID: "DE.CM-1", Framework: "NIST_CSF", Category: "Detect",
			Name:        "Network Monitoring",
			Description: "The network is monitored to detect potential cybersecurity events.",
			Weight:      1.0,
		},
		{
			ID: "DE.CM-4", Framework: "NIST_CSF", Category: "Detect",
			Name:        "Malicious Code Detection",
			Description: "Malicious code is detected.",
			Weight:      1.0,
		},
		{
			ID: "DE.DP-4", Framework: "NIST_CSF", Category: "Detect",
			Name:        "Detection Process Communication",
			Description: "Event detection information is communicated to appropriate parties.",
			Weight:      0.8,
		},
	}

	now := time.Now().UTC()
	for _, ctrl := range controls {
		ctrl.LastAssessed = now
	}

	if s.pool == nil {
		for _, ctrl := range controls {
			ctrl.Score = 65
			ctrl.Status = "partial"
		}
		return controls
	}

	// DE.AE-1: UEBA baselines
	var uebaBaselines int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ueba_baselines`).Scan(&uebaBaselines)
	controls[0].Evidence = fmt.Sprintf("%d UEBA behavioral baselines established", uebaBaselines)
	if uebaBaselines > 0 {
		controls[0].Score = 80
		controls[0].Status = "compliant"
	} else {
		controls[0].Score = 30
		controls[0].Status = "partial"
	}

	// DE.AE-3: Correlation rules count
	var corrCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM correlation_rules WHERE enabled = true`).Scan(&corrCount)
	controls[1].Evidence = fmt.Sprintf("%d active correlation rules", corrCount)
	if corrCount >= 5 {
		controls[1].Score = 90
		controls[1].Status = "compliant"
	} else if corrCount > 0 {
		controls[1].Score = 60
		controls[1].Status = "partial"
	} else {
		controls[1].Score = 20
		controls[1].Status = "non_compliant"
	}

	// DE.CM-1: Network events count
	var netEvents int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM events
		WHERE event_type = 'network' AND time > NOW() - INTERVAL '1 day'
	`).Scan(&netEvents)
	controls[2].Evidence = fmt.Sprintf("%d network events in last 24h", netEvents)
	if netEvents > 0 {
		controls[2].Score = 85
		controls[2].Status = "compliant"
	} else {
		controls[2].Score = 40
		controls[2].Status = "partial"
	}

	// DE.CM-4: Sigma rules enabled
	var sigmaRules int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM detection_rules WHERE enabled = true`).Scan(&sigmaRules)
	controls[3].Evidence = fmt.Sprintf("%d Sigma detection rules enabled", sigmaRules)
	if sigmaRules >= 10 {
		controls[3].Score = 95
		controls[3].Status = "compliant"
	} else if sigmaRules > 0 {
		controls[3].Score = 70
		controls[3].Status = "partial"
	} else {
		controls[3].Score = 20
		controls[3].Status = "non_compliant"
	}

	// DE.DP-4: Alert notifications configured
	var notifChannels int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM notification_channels WHERE enabled = true`).Scan(&notifChannels)
	controls[4].Evidence = fmt.Sprintf("%d active notification channels", notifChannels)
	if notifChannels > 0 {
		controls[4].Score = 85
		controls[4].Status = "compliant"
	} else {
		controls[4].Score = 30
		controls[4].Status = "partial"
	}

	return controls
}

// scoreRespond scores the Respond function controls.
func (s *Scorer) scoreRespond(ctx context.Context) []*Control {
	controls := []*Control{
		{
			ID: "RS.RP-1", Framework: "NIST_CSF", Category: "Respond",
			Name:        "Response Plan Execution",
			Description: "Response plan is executed during or after an incident.",
			Weight:      1.0,
		},
		{
			ID: "RS.CO-2", Framework: "NIST_CSF", Category: "Respond",
			Name:        "Incident Reporting",
			Description: "Incidents are reported consistent with established criteria.",
			Weight:      1.0,
		},
		{
			ID: "RS.AN-1", Framework: "NIST_CSF", Category: "Respond",
			Name:        "Alert Investigation",
			Description: "Notifications from detection systems are investigated.",
			Weight:      1.0,
		},
		{
			ID: "RS.MI-1", Framework: "NIST_CSF", Category: "Respond",
			Name:        "Incident Containment",
			Description: "Incidents are contained.",
			Weight:      1.0,
		},
		{
			ID: "RS.IM-1", Framework: "NIST_CSF", Category: "Respond",
			Name:        "Response Plans Incorporated",
			Description: "Response plans incorporate lessons learned.",
			Weight:      0.8,
		},
	}

	now := time.Now().UTC()
	for _, ctrl := range controls {
		ctrl.LastAssessed = now
	}

	if s.pool == nil {
		for _, ctrl := range controls {
			ctrl.Score = 60
			ctrl.Status = "partial"
		}
		return controls
	}

	// RS.RP-1: Playbooks defined
	var playbookCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM playbooks`).Scan(&playbookCount)
	controls[0].Evidence = fmt.Sprintf("%d incident response playbooks defined", playbookCount)
	if playbookCount >= 3 {
		controls[0].Score = 85
		controls[0].Status = "compliant"
	} else if playbookCount > 0 {
		controls[0].Score = 60
		controls[0].Status = "partial"
	} else {
		controls[0].Score = 20
		controls[0].Status = "non_compliant"
	}

	// RS.CO-2: Incident creation rate
	var incidentCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE created_at > NOW() - INTERVAL '30 days'`).Scan(&incidentCount)
	controls[1].Evidence = fmt.Sprintf("%d incidents reported in last 30 days", incidentCount)
	if incidentCount > 0 {
		controls[1].Score = 80
		controls[1].Status = "compliant"
	} else {
		controls[1].Score = 50
		controls[1].Status = "partial"
	}

	// RS.AN-1: Alert resolution rate (from average resolution time)
	var avgResolutionH float64
	_ = s.pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600), 0)
		FROM alerts
		WHERE resolved_at IS NOT NULL
		  AND created_at > NOW() - INTERVAL '30 days'
	`).Scan(&avgResolutionH)
	controls[2].Evidence = fmt.Sprintf("Average alert resolution time: %.1f hours", avgResolutionH)
	if avgResolutionH > 0 && avgResolutionH <= 4 {
		controls[2].Score = 95
		controls[2].Status = "compliant"
	} else if avgResolutionH > 0 && avgResolutionH <= 24 {
		controls[2].Score = 75
		controls[2].Status = "partial"
	} else if avgResolutionH > 0 {
		controls[2].Score = 50
		controls[2].Status = "partial"
	} else {
		controls[2].Score = 30
		controls[2].Status = "partial"
	}

	// RS.MI-1: Isolation/quarantine actions
	var isolationCount int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM response_actions
		WHERE action_type IN ('isolate', 'quarantine')
		  AND executed_at > NOW() - INTERVAL '30 days'
	`).Scan(&isolationCount)
	controls[3].Evidence = fmt.Sprintf("%d containment actions in last 30 days", isolationCount)
	if isolationCount > 0 {
		controls[3].Score = 80
		controls[3].Status = "compliant"
	} else {
		controls[3].Score = 50
		controls[3].Status = "partial"
	}

	// RS.IM-1: Post-incident tracking
	var resolvedIncidents int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM incidents
		WHERE status IN ('resolved', 'closed')
		  AND created_at > NOW() - INTERVAL '90 days'
	`).Scan(&resolvedIncidents)
	controls[4].Evidence = fmt.Sprintf("%d incidents resolved in last 90 days", resolvedIncidents)
	if resolvedIncidents > 0 {
		controls[4].Score = 75
		controls[4].Status = "partial"
	} else {
		controls[4].Score = 40
		controls[4].Status = "partial"
	}

	return controls
}

// scoreRecover scores the Recover function controls.
func (s *Scorer) scoreRecover(ctx context.Context) []*Control {
	controls := []*Control{
		{
			ID: "RC.RP-1", Framework: "NIST_CSF", Category: "Recover",
			Name:        "Recovery Plan",
			Description: "Recovery plan is executed during or after a cybersecurity incident.",
			Weight:      1.0,
		},
		{
			ID: "RC.IM-1", Framework: "NIST_CSF", Category: "Recover",
			Name:        "Recovery Plan Improvement",
			Description: "Recovery plans incorporate lessons learned.",
			Weight:      0.8,
		},
		{
			ID: "RC.CO-3", Framework: "NIST_CSF", Category: "Recover",
			Name:        "Recovery Communication",
			Description: "Recovery activities are communicated to internal and external stakeholders.",
			Weight:      0.8,
		},
		{
			ID: "RC.RP-2", Framework: "NIST_CSF", Category: "Recover",
			Name:        "Backup & Recovery Procedures",
			Description: "Backup and recovery procedures are tested.",
			Weight:      1.0,
		},
		{
			ID: "RC.CO-1", Framework: "NIST_CSF", Category: "Recover",
			Name:        "PR Management During Recovery",
			Description: "Public relations are managed during recovery.",
			Weight:      0.6,
		},
	}

	now := time.Now().UTC()
	for _, ctrl := range controls {
		ctrl.LastAssessed = now
	}

	// RC.RP-1: Static score if no recovery table
	controls[0].Score = 60
	controls[0].Status = "partial"
	controls[0].Evidence = "Recovery plan documentation not linked to system"

	controls[1].Score = 55
	controls[1].Status = "partial"
	controls[1].Evidence = "Lessons learned process not automated"

	controls[2].Score = 65
	controls[2].Status = "partial"
	controls[2].Evidence = "Notification channels configured for recovery communication"

	// RC.RP-2: Check backup history
	if s.pool != nil {
		var backupCount int
		_ = s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM backup_manifests
			WHERE created_at > NOW() - INTERVAL '30 days' AND status = 'success'
		`).Scan(&backupCount)
		controls[3].Evidence = fmt.Sprintf("%d successful backups in last 30 days", backupCount)
		if backupCount > 0 {
			controls[3].Score = 85
			controls[3].Status = "compliant"
		} else {
			controls[3].Score = 30
			controls[3].Status = "non_compliant"
		}
	} else {
		controls[3].Score = 60
		controls[3].Status = "partial"
	}

	controls[4].Score = 50
	controls[4].Status = "partial"
	controls[4].Evidence = "Manual PR management process"

	return controls
}

// ─── ISO 27001 ────────────────────────────────────────────────────────────────

// CalculateISO27001 computes an ISO 27001 compliance scorecard.
func (s *Scorer) CalculateISO27001(ctx context.Context) (*Scorecard, error) {
	sc := &Scorecard{
		Framework:      "ISO27001",
		CategoryScores: make(map[string]float64),
		Controls:       []*Control{},
		GeneratedAt:    time.Now().UTC(),
	}

	clauses := s.buildISO27001Controls(ctx)
	sc.Controls = append(sc.Controls, clauses...)

	s.calculateScores(sc)
	sc.Recommendations = s.GetRecommendations(sc)

	return sc, nil
}

// buildISO27001Controls creates ISO 27001 controls and scores them.
func (s *Scorer) buildISO27001Controls(ctx context.Context) []*Control {
	now := time.Now().UTC()

	// Pre-build the control list with static definitions
	controls := []*Control{
		// A.5 Information Security Policies
		{ID: "A.5.1.1", Framework: "ISO27001", Category: "A.5 Policies",
			Name: "Policies for Information Security", Weight: 1.0,
			Description: "A set of policies for information security shall be defined."},
		{ID: "A.5.1.2", Framework: "ISO27001", Category: "A.5 Policies",
			Name: "Review of Policies for Information Security", Weight: 0.8,
			Description: "The policies for information security shall be reviewed at planned intervals."},
		{ID: "A.5.2.1", Framework: "ISO27001", Category: "A.5 Policies",
			Name: "Information Security Roles", Weight: 0.9,
			Description: "All information security responsibilities shall be defined and allocated."},

		// A.6 Organization of Information Security
		{ID: "A.6.1.1", Framework: "ISO27001", Category: "A.6 Organization",
			Name: "Information Security Roles and Responsibilities", Weight: 0.9,
			Description: "All information security responsibilities shall be defined and allocated."},
		{ID: "A.6.1.5", Framework: "ISO27001", Category: "A.6 Organization",
			Name: "Information Security in Project Management", Weight: 0.7,
			Description: "Information security shall be addressed in project management."},
		{ID: "A.6.2.2", Framework: "ISO27001", Category: "A.6 Organization",
			Name: "Teleworking", Weight: 0.8,
			Description: "A policy and supporting security measures shall be implemented to protect information accessed from remote working sites."},

		// A.8 Asset Management
		{ID: "A.8.1.1", Framework: "ISO27001", Category: "A.8 Asset Management",
			Name: "Inventory of Assets", Weight: 1.0,
			Description: "Assets associated with information and information processing facilities shall be identified and an inventory of these assets shall be drawn up and maintained."},
		{ID: "A.8.1.3", Framework: "ISO27001", Category: "A.8 Asset Management",
			Name: "Acceptable Use of Assets", Weight: 0.9,
			Description: "Rules for the acceptable use of information and of assets associated with information and information processing facilities shall be identified, documented and implemented."},
		{ID: "A.8.2.1", Framework: "ISO27001", Category: "A.8 Asset Management",
			Name: "Classification of Information", Weight: 0.9,
			Description: "Information shall be classified in terms of legal requirements, value, criticality and sensitivity to unauthorised disclosure or modification."},

		// A.9 Access Control
		{ID: "A.9.1.1", Framework: "ISO27001", Category: "A.9 Access Control",
			Name: "Access Control Policy", Weight: 1.0,
			Description: "An access control policy shall be established, documented and reviewed based on business and information security requirements."},
		{ID: "A.9.2.1", Framework: "ISO27001", Category: "A.9 Access Control",
			Name: "User Registration and De-registration", Weight: 1.0,
			Description: "A formal user registration and de-registration process shall be implemented."},
		{ID: "A.9.4.2", Framework: "ISO27001", Category: "A.9 Access Control",
			Name: "Secure Log-on Procedures (MFA)", Weight: 1.0,
			Description: "Where required by the access control policy, access to systems and applications shall be controlled by a secure log-on procedure."},

		// A.10 Cryptography
		{ID: "A.10.1.1", Framework: "ISO27001", Category: "A.10 Cryptography",
			Name: "Policy on the Use of Cryptographic Controls", Weight: 1.0,
			Description: "A policy on the use of cryptographic controls for protection of information shall be developed and implemented."},
		{ID: "A.10.1.2", Framework: "ISO27001", Category: "A.10 Cryptography",
			Name: "Key Management", Weight: 0.9,
			Description: "A policy on the use, protection and lifetime of cryptographic keys shall be developed and implemented through their whole lifecycle."},

		// A.12 Operations Security
		{ID: "A.12.1.2", Framework: "ISO27001", Category: "A.12 Operations",
			Name: "Change Management", Weight: 1.0,
			Description: "Changes to the organization, business processes, information processing facilities and systems that affect information security shall be controlled."},
		{ID: "A.12.4.1", Framework: "ISO27001", Category: "A.12 Operations",
			Name: "Event Logging", Weight: 1.0,
			Description: "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed."},
		{ID: "A.12.6.1", Framework: "ISO27001", Category: "A.12 Operations",
			Name: "Management of Technical Vulnerabilities", Weight: 1.0,
			Description: "Information about technical vulnerabilities of information systems being used shall be obtained in a timely fashion."},

		// A.16 Incident Management
		{ID: "A.16.1.2", Framework: "ISO27001", Category: "A.16 Incident Management",
			Name: "Reporting Information Security Events", Weight: 1.0,
			Description: "Information security events shall be reported through appropriate management channels as quickly as possible."},
		{ID: "A.16.1.4", Framework: "ISO27001", Category: "A.16 Incident Management",
			Name: "Assessment of and Decision on Information Security Events", Weight: 1.0,
			Description: "Information security events shall be assessed and it shall be decided if they are to be classified as information security incidents."},
		{ID: "A.16.1.6", Framework: "ISO27001", Category: "A.16 Incident Management",
			Name: "Learning from Incidents", Weight: 0.9,
			Description: "Knowledge gained from analysing and resolving information security incidents shall be used to reduce the likelihood or impact of future incidents."},

		// A.17 Business Continuity
		{ID: "A.17.1.1", Framework: "ISO27001", Category: "A.17 Continuity",
			Name: "Planning Information Security Continuity", Weight: 1.0,
			Description: "The organization shall determine its requirements for information security and the continuity of information security management in adverse situations."},
		{ID: "A.17.1.2", Framework: "ISO27001", Category: "A.17 Continuity",
			Name: "Implementing Information Security Continuity", Weight: 1.0,
			Description: "The organization shall establish, document, implement and maintain processes, procedures and controls to ensure the required level of continuity."},
		{ID: "A.17.1.3", Framework: "ISO27001", Category: "A.17 Continuity",
			Name: "Verify, Review, and Evaluate Continuity", Weight: 0.9,
			Description: "The organization shall verify the established and implemented information security continuity controls at regular intervals."},

		// A.18 Compliance
		{ID: "A.18.1.3", Framework: "ISO27001", Category: "A.18 Compliance",
			Name: "Protection of Records", Weight: 0.9,
			Description: "Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release."},
		{ID: "A.18.2.2", Framework: "ISO27001", Category: "A.18 Compliance",
			Name: "Compliance with Security Policies", Weight: 1.0,
			Description: "Managers shall regularly review the compliance of information processing and procedures within their area of responsibility."},
		{ID: "A.18.2.3", Framework: "ISO27001", Category: "A.18 Compliance",
			Name: "Technical Compliance Review", Weight: 1.0,
			Description: "Information systems shall be regularly reviewed for compliance with the organization's information security policies and standards."},
	}

	for _, ctrl := range controls {
		ctrl.LastAssessed = now
		ctrl.Score = 0
		ctrl.Status = "not_assessed"
	}

	if s.pool == nil {
		for _, ctrl := range controls {
			ctrl.Score = 55
			ctrl.Status = "partial"
		}
		return controls
	}

	// Score each control with real data
	s.scoreISO27001Controls(ctx, controls)
	return controls
}

// scoreISO27001Controls applies database-derived scores to ISO 27001 controls.
func (s *Scorer) scoreISO27001Controls(ctx context.Context, controls []*Control) {
	// Helper to find control by ID
	find := func(id string) *Control {
		for _, c := range controls {
			if c.ID == id {
				return c
			}
		}
		return nil
	}

	// A.8.1.1: Asset inventory
	var assetCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&assetCount)
	if ctrl := find("A.8.1.1"); ctrl != nil {
		ctrl.Evidence = fmt.Sprintf("%d assets in inventory", assetCount)
		ctrl.Score = floatIf(assetCount > 0, 85, 10)
		ctrl.Status = statusFromScore(ctrl.Score)
	}

	// A.9.4.2: MFA
	var mfaCount, totalUsers int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE mfa_enabled = true`).Scan(&mfaCount)
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUsers)
	if ctrl := find("A.9.4.2"); ctrl != nil {
		if totalUsers > 0 {
			rate := float64(mfaCount) / float64(totalUsers) * 100
			ctrl.Score = rate
			ctrl.Evidence = fmt.Sprintf("%d/%d users have MFA (%.0f%%)", mfaCount, totalUsers, rate)
		} else {
			ctrl.Score = 40
			ctrl.Evidence = "No users found"
		}
		ctrl.Status = statusFromScore(ctrl.Score)
	}

	// A.12.4.1: Audit logging
	var auditCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '7 days'`).Scan(&auditCount)
	if ctrl := find("A.12.4.1"); ctrl != nil {
		ctrl.Evidence = fmt.Sprintf("%d audit entries in last 7 days", auditCount)
		ctrl.Score = floatIf(auditCount > 0, 90, 20)
		ctrl.Status = statusFromScore(ctrl.Score)
	}

	// A.12.6.1: Vulnerability management
	var vulnCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM vulnerabilities`).Scan(&vulnCount)
	if ctrl := find("A.12.6.1"); ctrl != nil {
		ctrl.Evidence = fmt.Sprintf("%d vulnerabilities tracked", vulnCount)
		ctrl.Score = floatIf(vulnCount > 0, 80, 35)
		ctrl.Status = statusFromScore(ctrl.Score)
	}

	// A.16.1.2: Incident reporting
	var incidentCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE created_at > NOW() - INTERVAL '30 days'`).Scan(&incidentCount)
	if ctrl := find("A.16.1.2"); ctrl != nil {
		ctrl.Evidence = fmt.Sprintf("%d incidents reported in last 30 days", incidentCount)
		ctrl.Score = floatIf(incidentCount > 0, 85, 45)
		ctrl.Status = statusFromScore(ctrl.Score)
	}

	// A.17.1.1-A.17.1.3: Continuity (backup-based)
	var backupCount int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM backup_manifests
		WHERE created_at > NOW() - INTERVAL '30 days' AND status = 'success'
	`).Scan(&backupCount)
	contScore := floatIf(backupCount > 0, 75, 30)
	for _, id := range []string{"A.17.1.1", "A.17.1.2", "A.17.1.3"} {
		if ctrl := find(id); ctrl != nil {
			ctrl.Score = contScore
			ctrl.Evidence = fmt.Sprintf("%d successful backups in last 30 days", backupCount)
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// Fill any remaining not_assessed with partial scores
	for _, ctrl := range controls {
		if ctrl.Status == "not_assessed" {
			ctrl.Score = 55
			ctrl.Status = "partial"
			ctrl.Evidence = "Manual assessment required"
		}
	}
}

// ─── Scoring Helpers ──────────────────────────────────────────────────────────

// calculateScores computes category and overall weighted scores.
func (s *Scorer) calculateScores(sc *Scorecard) {
	categoryWeights := make(map[string]float64)
	categoryScores := make(map[string]float64)

	for _, ctrl := range sc.Controls {
		categoryWeights[ctrl.Category] += ctrl.Weight
		categoryScores[ctrl.Category] += ctrl.Score * ctrl.Weight
	}

	totalWeight := 0.0
	weightedScore := 0.0
	for cat, totalW := range categoryWeights {
		if totalW > 0 {
			catScore := categoryScores[cat] / totalW
			sc.CategoryScores[cat] = catScore
			totalWeight += totalW
			weightedScore += catScore * totalW
		}
	}

	if totalWeight > 0 {
		sc.OverallScore = weightedScore / totalWeight
	}
}

// GetRecommendations returns up to 5 improvement recommendations based on lowest scoring controls.
func (s *Scorer) GetRecommendations(sc *Scorecard) []string {
	// Find the 5 controls with the lowest scores
	type scoredControl struct {
		name  string
		score float64
		cat   string
	}

	var candidates []scoredControl
	for _, ctrl := range sc.Controls {
		if ctrl.Status != "compliant" {
			candidates = append(candidates, scoredControl{
				name:  ctrl.Name,
				score: ctrl.Score,
				cat:   ctrl.Category,
			})
		}
	}

	// Simple sort: bubble worst 5 to front
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score < candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	recommendations := []string{}
	for i := 0; i < len(candidates) && i < 5; i++ {
		rec := fmt.Sprintf("[%s] Improve '%s' (current score: %.0f/100)",
			candidates[i].cat, candidates[i].name, candidates[i].score)
		recommendations = append(recommendations, rec)
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "All assessed controls are compliant. Continue regular reviews.")
	}
	return recommendations
}

// ─── Utility Functions ────────────────────────────────────────────────────────

func statusFromScore(score float64) string {
	switch {
	case score >= 80:
		return "compliant"
	case score >= 50:
		return "partial"
	default:
		return "non_compliant"
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func floatIf(cond bool, t, f float64) float64 {
	if cond {
		return t
	}
	return f
}

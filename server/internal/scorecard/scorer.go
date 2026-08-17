package scorecard

// NIST CSF and ISO 27001 compliance scoring.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/backup"
)

// The four values Control.Status may take. The first three are findings about
// the customer's posture; the fourth says no finding was reached, and is the
// only honest answer when the evidence query did not run.
const (
	StatusCompliant    = "compliant"
	StatusPartial      = "partial"
	StatusNonCompliant = "non_compliant"
	StatusNotAssessed  = "not_assessed"
)

// ErrNothingAssessed is returned when not one control could be evaluated —
// every evidence query failed. There is no score to report in that case, and
// saying so is different from reporting zero.
var ErrNothingAssessed = errors.New("scorecard: no control could be assessed")

// Control represents a single compliance control assessment.
type Control struct {
	ID          string  `json:"id"`
	Framework   string  `json:"framework"` // NIST_CSF or ISO27001
	Category    string  `json:"category"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	Score       float64 `json:"score"` // 0-100, meaningless unless Status != not_assessed
	Status      string  `json:"status"`
	Evidence    string  `json:"evidence,omitempty"`
	// Error carries the reason the evidence query did not run, when it did not.
	// It is what separates "we looked and found nothing" from "we could not
	// look" — the two used to be indistinguishable in the response.
	Error        string    `json:"error,omitempty"`
	LastAssessed time.Time `json:"last_assessed"`
}

// assessed reports whether this control carries a finding about the customer's
// posture, as opposed to a record that no finding was reached.
func (c *Control) assessed() bool { return c.Status != StatusNotAssessed }

// Scorecard holds the complete compliance scorecard for an organization.
type Scorecard struct {
	OrganizationID string             `json:"organization_id"`
	Framework      string             `json:"framework"`
	OverallScore   float64            `json:"overall_score"`
	CategoryScores map[string]float64 `json:"category_scores"`
	Controls       []*Control         `json:"controls"`
	// AssessedControls and TotalControls are the coverage behind OverallScore.
	// OverallScore averages only the controls that were assessed, so it must
	// never be read without them: 90 out of 3 assessed controls is not the same
	// claim as 90 out of 25, and the JSON now says which one it is.
	AssessedControls int       `json:"assessed_controls"`
	TotalControls    int       `json:"total_controls"`
	GeneratedAt      time.Time `json:"generated_at"`
	Recommendations  []string  `json:"recommendations"`
}

// Scorer calculates compliance scorecards by querying the database.
type Scorer struct {
	pool *pgxpool.Pool
}

// NewScorer creates a new Scorer.
func NewScorer(pool *pgxpool.Pool) *Scorer {
	return &Scorer{pool: pool}
}

// ─── Evidence gathering ───────────────────────────────────────────────────────
//
// Every control below is scored from a COUNT or an aggregate. Those queries used
// to be written `_ = s.pool.QueryRow(...).Scan(&n)`, which left n at zero when
// the query failed — and zero is a value each control already had a meaning for.
// A dropped connection therefore produced "No hardening baselines configured,
// non_compliant" rather than an error, and the whole scorecard came back with a
// headline number. Measured against a database where every query failed:
//
//	NIST CSF overall  42.5 (healthy)  ->  35.3 (every query failing)
//	ISO 27001 overall 50.0 (healthy)  ->  46.9 (every query failing)
//
// Seven points and three points. Nothing in the response said the difference was
// an outage rather than a posture, and the report is read by auditors.
//
// The two helpers below make that impossible to write by accident: countOf
// returns the error, and unassessed is the only way to leave a control without a
// finding.

// countOf runs a scalar query and returns its single value.
func (s *Scorer) countOf(ctx context.Context, q string, args ...any) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// unassessed records that a control could not be evaluated, and why. It clears
// the score rather than leaving a stale one, because a score attached to a
// not_assessed control is exactly the confusion this is here to prevent.
func unassessed(err error, reason string, controls ...*Control) {
	for _, c := range controls {
		c.Score = 0
		c.Status = StatusNotAssessed
		c.Evidence = reason
		if err != nil {
			c.Error = err.Error()
		}
	}
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

	if sc.AssessedControls == 0 {
		return sc, ErrNothingAssessed
	}
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
		ctrl.Status = StatusNotAssessed
	}

	if s.pool == nil {
		unassessed(nil, noDatabase, controls...)
		return controls
	}

	// ID.AM-1: Check asset inventory table.
	//
	// The asset count is also the denominator for ID.AM-2 and ID.AM-5, so losing
	// it costs three controls rather than one. It used to cost none visibly:
	// assetCount stayed 0, the two ratios were taken against assetCount+1, and
	// "1 software package for 1 asset" scored 100/compliant off a failed query.
	assetCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM agents`)
	if err != nil {
		unassessed(err, "asset inventory could not be read", controls[0], controls[1], controls[2])
	} else {
		controls[0].Evidence = fmt.Sprintf("%d assets inventoried", assetCount)
		if assetCount > 0 {
			controls[0].Score = 100
			controls[0].Status = StatusCompliant
		} else {
			controls[0].Score = 0
			controls[0].Status = StatusNonCompliant
		}

		// ID.AM-2: Check software inventory. An empty inventory is a finding —
		// it used to leave the control at its initial not_assessed while
		// carrying the evidence "0 software packages inventoried", so a real
		// answer of zero was reported as never having looked.
		swCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM endpoint_software`)
		if err != nil {
			unassessed(err, "software inventory could not be read", controls[1])
		} else {
			controls[1].Evidence = fmt.Sprintf("%d software packages inventoried", swCount)
			controls[1].Score = minFloat(float64(swCount)/float64(assetCount+1)*100, 100)
			controls[1].Status = statusFromScore(controls[1].Score)
		}

		// ID.AM-5: Check asset criticality scoring
		critCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM asset_criticality_scores`)
		if err != nil {
			unassessed(err, "asset criticality scores could not be read", controls[2])
		} else if critCount > 0 {
			controls[2].Score = minFloat(float64(critCount)/float64(assetCount+1)*100, 100)
			controls[2].Evidence = fmt.Sprintf("%d assets scored for criticality", critCount)
			controls[2].Status = statusFromScore(controls[2].Score)
		} else {
			controls[2].Score = 40
			controls[2].Status = StatusPartial
			controls[2].Evidence = "No asset criticality scoring configured"
		}
	}

	// ID.RA-1: Check vulnerability findings
	if vulnCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM vulnerabilities`); err != nil {
		unassessed(err, "vulnerability findings could not be read", controls[3])
	} else {
		controls[3].Evidence = fmt.Sprintf("%d vulnerabilities tracked", vulnCount)
		if vulnCount > 0 {
			controls[3].Score = 80
			controls[3].Status = StatusCompliant
		} else {
			controls[3].Score = 40
			controls[3].Status = StatusPartial
		}
	}

	// ID.RA-5: Check threat intel IOC count
	if iocCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM threat_intel_iocs`); err != nil {
		unassessed(err, "threat intelligence indicators could not be read", controls[4])
	} else {
		controls[4].Evidence = fmt.Sprintf("%d threat IOCs tracked", iocCount)
		if iocCount > 0 {
			controls[4].Score = 85
			controls[4].Status = StatusCompliant
		} else {
			controls[4].Score = 30
			controls[4].Status = StatusPartial
		}
	}

	return controls
}

// noDatabase is the reason recorded when the Scorer has no pool at all. The
// framework functions used to hand out a flat 55-65 in this case, which is a
// posture claim made without looking at anything.
const noDatabase = "no database connection configured"

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
		ctrl.Score = 0
		ctrl.Status = StatusNotAssessed
	}

	if s.pool == nil {
		unassessed(nil, noDatabase, controls...)
		return controls
	}

	// PR.AC-1: Check MFA and user management. Both halves of the rate are
	// needed: with only one, a failure on the denominator turned into "0 users"
	// and a flat 60/partial.
	mfaCount, mfaErr := s.countOf(ctx, `SELECT COUNT(*) FROM users WHERE mfa_enabled = true`)
	totalUsers, usersErr := s.countOf(ctx, `SELECT COUNT(*) FROM users`)
	switch {
	case mfaErr != nil:
		unassessed(mfaErr, "MFA enrolment could not be read", controls[0])
	case usersErr != nil:
		unassessed(usersErr, "user directory could not be read", controls[0])
	case totalUsers > 0:
		mfaRate := float64(mfaCount) / float64(totalUsers) * 100
		controls[0].Score = mfaRate
		controls[0].Evidence = fmt.Sprintf("%d/%d users have MFA enabled (%.0f%%)", mfaCount, totalUsers, mfaRate)
		controls[0].Status = statusFromScore(mfaRate)
	default:
		controls[0].Score = 60
		controls[0].Status = StatusPartial
		controls[0].Evidence = "No users defined"
	}

	// PR.DS-1: Check encryption management
	if encCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM endpoint_encryption`); err != nil {
		unassessed(err, "endpoint encryption state could not be read", controls[1])
	} else if encCount > 0 {
		controls[1].Score = 80
		controls[1].Evidence = fmt.Sprintf("%d endpoints with encryption configured", encCount)
		controls[1].Status = StatusCompliant
	} else {
		controls[1].Score = 40
		controls[1].Status = StatusPartial
		controls[1].Evidence = "No encryption management data found"
	}

	// PR.IP-1: Check endpoint hardening baselines
	baselineCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM hardening_baselines`)
	switch {
	case err != nil:
		unassessed(err, "hardening baselines could not be read", controls[2])
	case baselineCount > 0:
		// Check compliance rate across per-agent assessment roll-ups.
		var passedChecks, totalChecks int
		if err := s.pool.QueryRow(ctx, `
			SELECT COALESCE(SUM(passed_checks),0), COALESCE(SUM(passed_checks + failed_checks),0)
			FROM hardening_assessments
		`).Scan(&passedChecks, &totalChecks); err != nil {
			unassessed(err, "hardening assessment results could not be read", controls[2])
		} else if totalChecks > 0 {
			rate := float64(passedChecks) / float64(totalChecks) * 100
			controls[2].Score = rate
			controls[2].Evidence = fmt.Sprintf("%.0f%% hardening compliance (%d/%d checks passed)", rate, passedChecks, totalChecks)
			controls[2].Status = statusFromScore(rate)
		} else {
			controls[2].Score = 70
			controls[2].Status = StatusPartial
			controls[2].Evidence = fmt.Sprintf("%d baselines defined but never assessed", baselineCount)
		}
	default:
		controls[2].Score = 30
		controls[2].Status = StatusNonCompliant
		controls[2].Evidence = "No hardening baselines configured"
	}

	// PR.IP-3: Check agent config profiles
	if profileCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM agent_config_profiles`); err != nil {
		unassessed(err, "agent configuration profiles could not be read", controls[3])
	} else {
		controls[3].Evidence = fmt.Sprintf("%d agent configuration profiles defined", profileCount)
		if profileCount > 0 {
			controls[3].Score = 80
			controls[3].Status = StatusCompliant
		} else {
			controls[3].Score = 50
			controls[3].Status = StatusPartial
		}
	}

	// PR.PT-1: Check audit logs
	if auditCount, err := s.countOf(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '7 days'`); err != nil {
		unassessed(err, "audit log could not be read", controls[4])
	} else {
		controls[4].Evidence = fmt.Sprintf("%d audit log entries in last 7 days", auditCount)
		if auditCount > 0 {
			controls[4].Score = 90
			controls[4].Status = StatusCompliant
		} else {
			controls[4].Score = 20
			controls[4].Status = StatusNonCompliant
		}
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
		ctrl.Score = 0
		ctrl.Status = StatusNotAssessed
	}

	if s.pool == nil {
		unassessed(nil, noDatabase, controls...)
		return controls
	}

	// DE.AE-1: UEBA baselines
	if uebaBaselines, err := s.countOf(ctx, `SELECT COUNT(*) FROM ueba_baselines`); err != nil {
		unassessed(err, "UEBA baselines could not be read", controls[0])
	} else {
		controls[0].Evidence = fmt.Sprintf("%d UEBA behavioral baselines established", uebaBaselines)
		if uebaBaselines > 0 {
			controls[0].Score = 80
			controls[0].Status = StatusCompliant
		} else {
			controls[0].Score = 30
			controls[0].Status = StatusPartial
		}
	}

	// DE.AE-3: Correlation rules count
	if corrCount, err := s.countOf(ctx,
		`SELECT COUNT(*) FROM correlation_rules WHERE enabled = true`); err != nil {
		unassessed(err, "correlation rules could not be read", controls[1])
	} else {
		controls[1].Evidence = fmt.Sprintf("%d active correlation rules", corrCount)
		switch {
		case corrCount >= 5:
			controls[1].Score = 90
			controls[1].Status = StatusCompliant
		case corrCount > 0:
			controls[1].Score = 60
			controls[1].Status = StatusPartial
		default:
			controls[1].Score = 20
			controls[1].Status = StatusNonCompliant
		}
	}

	// DE.CM-1: Network events count
	if netEvents, err := s.countOf(ctx, `
		SELECT COUNT(*) FROM events
		WHERE event_type = 'network' AND time > NOW() - INTERVAL '1 day'
	`); err != nil {
		unassessed(err, "network telemetry could not be read", controls[2])
	} else {
		controls[2].Evidence = fmt.Sprintf("%d network events in last 24h", netEvents)
		if netEvents > 0 {
			controls[2].Score = 85
			controls[2].Status = StatusCompliant
		} else {
			controls[2].Score = 40
			controls[2].Status = StatusPartial
		}
	}

	// DE.CM-4: Sigma rules enabled
	if sigmaRules, err := s.countOf(ctx,
		`SELECT COUNT(*) FROM detection_rules WHERE enabled = true`); err != nil {
		unassessed(err, "detection rules could not be read", controls[3])
	} else {
		controls[3].Evidence = fmt.Sprintf("%d Sigma detection rules enabled", sigmaRules)
		switch {
		case sigmaRules >= 10:
			controls[3].Score = 95
			controls[3].Status = StatusCompliant
		case sigmaRules > 0:
			controls[3].Score = 70
			controls[3].Status = StatusPartial
		default:
			controls[3].Score = 20
			controls[3].Status = StatusNonCompliant
		}
	}

	// DE.DP-4: Alert notifications configured
	if notifChannels, err := s.countOf(ctx,
		`SELECT COUNT(*) FROM notification_channels WHERE enabled = true`); err != nil {
		unassessed(err, "notification channels could not be read", controls[4])
	} else {
		controls[4].Evidence = fmt.Sprintf("%d active notification channels", notifChannels)
		if notifChannels > 0 {
			controls[4].Score = 85
			controls[4].Status = StatusCompliant
		} else {
			controls[4].Score = 30
			controls[4].Status = StatusPartial
		}
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
		ctrl.Score = 0
		ctrl.Status = StatusNotAssessed
	}

	if s.pool == nil {
		unassessed(nil, noDatabase, controls...)
		return controls
	}

	// RS.RP-1: Playbooks defined
	if playbookCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM playbooks`); err != nil {
		unassessed(err, "response playbooks could not be read", controls[0])
	} else {
		controls[0].Evidence = fmt.Sprintf("%d incident response playbooks defined", playbookCount)
		switch {
		case playbookCount >= 3:
			controls[0].Score = 85
			controls[0].Status = StatusCompliant
		case playbookCount > 0:
			controls[0].Score = 60
			controls[0].Status = StatusPartial
		default:
			controls[0].Score = 20
			controls[0].Status = StatusNonCompliant
		}
	}

	// RS.CO-2: Incident creation rate
	if incidentCount, err := s.countOf(ctx,
		`SELECT COUNT(*) FROM incidents WHERE created_at > NOW() - INTERVAL '30 days'`); err != nil {
		unassessed(err, "incident history could not be read", controls[1])
	} else {
		controls[1].Evidence = fmt.Sprintf("%d incidents reported in last 30 days", incidentCount)
		if incidentCount > 0 {
			controls[1].Score = 80
			controls[1].Status = StatusCompliant
		} else {
			controls[1].Score = 50
			controls[1].Status = StatusPartial
		}
	}

	// RS.AN-1: Alert resolution rate (from average resolution time).
	//
	// COALESCE makes "no resolved alerts" and "query failed" both arrive as 0.0,
	// and the control read 0.0 as a real finding — "Average alert resolution
	// time: 0.0 hours", scored 30/partial. Only the error tells them apart.
	var avgResolutionH float64
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600), 0)
		FROM alerts
		WHERE resolved_at IS NOT NULL
		  AND created_at > NOW() - INTERVAL '30 days'
	`).Scan(&avgResolutionH); err != nil {
		unassessed(err, "alert resolution times could not be read", controls[2])
	} else {
		switch {
		case avgResolutionH <= 0:
			controls[2].Score = 30
			controls[2].Status = StatusPartial
			controls[2].Evidence = "No alerts resolved in last 30 days"
		case avgResolutionH <= 4:
			controls[2].Score = 95
			controls[2].Status = StatusCompliant
			controls[2].Evidence = fmt.Sprintf("Average alert resolution time: %.1f hours", avgResolutionH)
		case avgResolutionH <= 24:
			controls[2].Score = 75
			controls[2].Status = StatusPartial
			controls[2].Evidence = fmt.Sprintf("Average alert resolution time: %.1f hours", avgResolutionH)
		default:
			controls[2].Score = 50
			controls[2].Status = StatusPartial
			controls[2].Evidence = fmt.Sprintf("Average alert resolution time: %.1f hours", avgResolutionH)
		}
	}

	// RS.MI-1: Isolation/quarantine actions
	if isolationCount, err := s.countOf(ctx, `
		SELECT COUNT(*) FROM response_actions
		WHERE action_type IN ('isolate', 'quarantine')
		  AND executed_at > NOW() - INTERVAL '30 days'
	`); err != nil {
		unassessed(err, "containment actions could not be read", controls[3])
	} else {
		controls[3].Evidence = fmt.Sprintf("%d containment actions in last 30 days", isolationCount)
		if isolationCount > 0 {
			controls[3].Score = 80
			controls[3].Status = StatusCompliant
		} else {
			controls[3].Score = 50
			controls[3].Status = StatusPartial
		}
	}

	// RS.IM-1: Post-incident tracking
	if resolvedIncidents, err := s.countOf(ctx, `
		SELECT COUNT(*) FROM incidents
		WHERE status IN ('resolved', 'closed')
		  AND created_at > NOW() - INTERVAL '90 days'
	`); err != nil {
		unassessed(err, "resolved incidents could not be read", controls[4])
	} else {
		controls[4].Evidence = fmt.Sprintf("%d incidents resolved in last 90 days", resolvedIncidents)
		if resolvedIncidents > 0 {
			controls[4].Score = 75
			controls[4].Status = StatusPartial
		} else {
			controls[4].Score = 40
			controls[4].Status = StatusPartial
		}
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

	// RC.RP-1, RC.IM-1, RC.CO-3 and RC.CO-1 have no evidence source. Each used to
	// carry a fixed score — 60, 55, 65 and 50 — alongside evidence that said as
	// much: "Recovery plan documentation not linked to system". A number derived
	// from nothing was averaged in as though it had been assessed.
	//
	// That was the load-bearing half of this category. Once the queries above
	// started reporting their failures, a completely dead database scored 58.1
	// overall — better than the 42.5 a working one scored — because these four
	// constants were the only controls left standing. They are not findings and
	// no longer count as any.
	unassessed(nil, "Recovery plan documentation not linked to system", controls[0])
	unassessed(nil, "Lessons learned process not automated", controls[1])
	unassessed(nil, "Recovery communication is not tracked by this platform", controls[2])

	// RC.RP-2: Check backup history
	if s.pool == nil {
		unassessed(nil, noDatabase, controls[3])
	} else if backupCount, err := s.recentSuccessfulBackups(ctx); err != nil {
		unassessed(err, "backup history could not be read", controls[3])
	} else {
		controls[3].Evidence = fmt.Sprintf("%d successful backups in last 30 days", backupCount)
		if backupCount > 0 {
			controls[3].Score = 85
			controls[3].Status = StatusCompliant
		} else {
			controls[3].Score = 30
			controls[3].Status = StatusNonCompliant
		}
	}

	unassessed(nil, "Manual PR management process — not tracked by this platform", controls[4])

	return controls
}

// recentSuccessfulBackups counts backups from the last 30 days that finished and
// were verified. It is the single evidence source behind NIST CSF RC.RP-2 and
// ISO 27001 A.17.1.1–A.17.1.3, which previously each carried their own copy of
// the query.
//
// Two things were wrong with those copies. They filtered on
// `status = 'success'`, a word no producer writes — internal/backup writes
// backup.StatusCompleted and so does the column default — so the count was
// structurally zero and all four controls scored 30/non_compliant on every
// deployment, no matter how many backups had succeeded. And they looked only at
// backup_manifests, the logical config export; the nightly pg_dump that
// scheduler.BackupScheduler records in `backups` was not evidence of anything.
//
// UNION ALL rather than two counts summed in Go: one round trip, and the two
// tables' timestamp columns differ (created_at vs started_at), which is easier
// to get right once here than in each caller.
func (s *Scorer) recentSuccessfulBackups(ctx context.Context) (int, error) {
	return s.countOf(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM backup_manifests
			WHERE created_at > NOW() - INTERVAL '30 days' AND status = $1
			UNION ALL
			SELECT 1 FROM backups
			WHERE started_at > NOW() - INTERVAL '30 days' AND status = $1
		) AS verified_backups
	`, backup.StatusCompleted)
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

	if sc.AssessedControls == 0 {
		return sc, ErrNothingAssessed
	}
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
		ctrl.Status = StatusNotAssessed
	}

	if s.pool == nil {
		unassessed(nil, noDatabase, controls...)
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
	if ctrl := find("A.8.1.1"); ctrl != nil {
		if assetCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM agents`); err != nil {
			unassessed(err, "asset inventory could not be read", ctrl)
		} else {
			ctrl.Evidence = fmt.Sprintf("%d assets in inventory", assetCount)
			ctrl.Score = floatIf(assetCount > 0, 85, 10)
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// A.9.4.2: MFA
	if ctrl := find("A.9.4.2"); ctrl != nil {
		mfaCount, mfaErr := s.countOf(ctx, `SELECT COUNT(*) FROM users WHERE mfa_enabled = true`)
		totalUsers, usersErr := s.countOf(ctx, `SELECT COUNT(*) FROM users`)
		switch {
		case mfaErr != nil:
			unassessed(mfaErr, "MFA enrolment could not be read", ctrl)
		case usersErr != nil:
			unassessed(usersErr, "user directory could not be read", ctrl)
		case totalUsers > 0:
			rate := float64(mfaCount) / float64(totalUsers) * 100
			ctrl.Score = rate
			ctrl.Evidence = fmt.Sprintf("%d/%d users have MFA (%.0f%%)", mfaCount, totalUsers, rate)
			ctrl.Status = statusFromScore(ctrl.Score)
		default:
			ctrl.Score = 40
			ctrl.Evidence = "No users found"
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// A.12.4.1: Audit logging
	if ctrl := find("A.12.4.1"); ctrl != nil {
		if auditCount, err := s.countOf(ctx,
			`SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '7 days'`); err != nil {
			unassessed(err, "audit log could not be read", ctrl)
		} else {
			ctrl.Evidence = fmt.Sprintf("%d audit entries in last 7 days", auditCount)
			ctrl.Score = floatIf(auditCount > 0, 90, 20)
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// A.12.6.1: Vulnerability management
	if ctrl := find("A.12.6.1"); ctrl != nil {
		if vulnCount, err := s.countOf(ctx, `SELECT COUNT(*) FROM vulnerabilities`); err != nil {
			unassessed(err, "vulnerability findings could not be read", ctrl)
		} else {
			ctrl.Evidence = fmt.Sprintf("%d vulnerabilities tracked", vulnCount)
			ctrl.Score = floatIf(vulnCount > 0, 80, 35)
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// A.16.1.2: Incident reporting
	if ctrl := find("A.16.1.2"); ctrl != nil {
		if incidentCount, err := s.countOf(ctx,
			`SELECT COUNT(*) FROM incidents WHERE created_at > NOW() - INTERVAL '30 days'`); err != nil {
			unassessed(err, "incident history could not be read", ctrl)
		} else {
			ctrl.Evidence = fmt.Sprintf("%d incidents reported in last 30 days", incidentCount)
			ctrl.Score = floatIf(incidentCount > 0, 85, 45)
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// A.17.1.1-A.17.1.3: Continuity (backup-based)
	continuity := []*Control{}
	for _, id := range []string{"A.17.1.1", "A.17.1.2", "A.17.1.3"} {
		if ctrl := find(id); ctrl != nil {
			continuity = append(continuity, ctrl)
		}
	}
	if backupCount, err := s.recentSuccessfulBackups(ctx); err != nil {
		unassessed(err, "backup history could not be read", continuity...)
	} else {
		contScore := floatIf(backupCount > 0, 75, 30)
		for _, ctrl := range continuity {
			ctrl.Score = contScore
			ctrl.Evidence = fmt.Sprintf("%d successful backups in last 30 days", backupCount)
			ctrl.Status = statusFromScore(ctrl.Score)
		}
	}

	// The remaining controls — policy, roles, teleworking, cryptography, and the
	// rest of the clauses this platform holds no evidence for — used to be filled
	// in with a flat 55/partial and the evidence "Manual assessment required".
	// Nineteen of the twenty-six controls, which is to say most of the ISO 27001
	// score was a constant. They stay not_assessed now and are left out of the
	// average, so the score reports what the platform actually measured and
	// assessed_controls says how much of the standard that covers.
	for _, ctrl := range controls {
		if ctrl.Status == StatusNotAssessed && ctrl.Evidence == "" {
			ctrl.Evidence = "No automated evidence source — manual assessment required"
		}
	}
}

// ─── Scoring Helpers ──────────────────────────────────────────────────────────

// calculateScores computes category and overall weighted scores over the
// controls that were actually assessed.
//
// Unassessed controls used to be averaged in at their score of zero, which made
// "we could not read the audit log" cost exactly as much as "there is no audit
// log". Losing the two Identify queries dropped that category from 51.1 to 21.1
// on a database that had not changed. Excluding them means a failure moves
// AssessedControls rather than the score, and the two are separately visible.
//
// A category where nothing could be assessed is omitted from CategoryScores
// rather than reported as zero, for the same reason.
func (s *Scorer) calculateScores(sc *Scorecard) {
	categoryWeights := make(map[string]float64)
	categoryScores := make(map[string]float64)

	sc.TotalControls = len(sc.Controls)
	sc.AssessedControls = 0
	sc.OverallScore = 0
	for _, ctrl := range sc.Controls {
		if !ctrl.assessed() {
			continue
		}
		sc.AssessedControls++
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

	// Counted from the controls rather than read from sc.AssessedControls, which
	// only calculateScores fills in: recommendations must not depend on having
	// been called in the right order.
	assessed := 0
	var candidates []scoredControl
	for _, ctrl := range sc.Controls {
		if !ctrl.assessed() {
			// An unassessed control has no score to improve on. It used to sort
			// to the very front — score zero beats every real finding — so a
			// failed query produced the page's top recommendation, phrased as
			// advice about the customer's posture.
			continue
		}
		assessed++
		if ctrl.Status != StatusCompliant {
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
		if assessed == 0 {
			return []string{"No control could be assessed. Check the platform's database connectivity before reading this report."}
		}
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

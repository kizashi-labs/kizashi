package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/tick"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Framework identifies a compliance framework.
type Framework string

const (
	FrameworkCIS  Framework = "cis"
	FrameworkNIST Framework = "nist"
	FrameworkSOC2 Framework = "soc2"
)

// CheckResult holds the outcome of a single control check.
type CheckResult struct {
	Status      string `json:"status"` // pass / fail / unknown
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

// AgentComplianceData holds the agent data used by control check functions.
type AgentComplianceData struct {
	AgentID       string
	Hostname      string
	OSType        string
	OSVersion     string
	AgentVersion  string
	Status        string
	LastSeen      time.Time
	EnrolledAt    time.Time
	RecentEvents  int // event count in last 24h
	RecentAlerts  int // alert count in last 24h
	NetworkEvents int // network event count in last 24h
}

// Control represents a single compliance control with a check function.
type Control struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Check       func(agentData AgentComplianceData) CheckResult
}

// ControlReport is the evaluated result of a single control for an agent.
type ControlReport struct {
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

// ComplianceReport is the full compliance evaluation result for one agent.
type ComplianceReport struct {
	ID          string          `json:"id"`
	AgentID     string          `json:"agent_id"`
	Hostname    string          `json:"hostname"`
	Framework   Framework       `json:"framework"`
	Score       float64         `json:"score"`
	Passed      int             `json:"passed"`
	Failed      int             `json:"failed"`
	Unknown     int             `json:"unknown"`
	Controls    []ControlReport `json:"controls"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
}

// Evaluator runs compliance evaluations against enrolled agents.
type Evaluator struct {
	db *pgxpool.Pool
}

// NewEvaluator creates a new Evaluator.
func NewEvaluator(db *pgxpool.Pool) *Evaluator {
	return &Evaluator{db: db}
}

// frameworkControls returns the control set for the given framework.
func frameworkControls(fw Framework) []Control {
	switch fw {
	case FrameworkCIS:
		return CISControls()
	case FrameworkNIST:
		return NISTControls()
	case FrameworkSOC2:
		return SOC2Controls()
	default:
		return nil
	}
}

// loadAgentData fetches the AgentComplianceData for a single agent.
func (e *Evaluator) loadAgentData(ctx context.Context, agentID string) (*AgentComplianceData, error) {
	data := &AgentComplianceData{AgentID: agentID}

	err := e.db.QueryRow(ctx, `
		SELECT
			COALESCE(hostname, ''),
			COALESCE(os_type, 'unknown'),
			COALESCE(os_version, ''),
			COALESCE(agent_version, ''),
			COALESCE(status, 'unknown'),
			COALESCE(last_seen, enrolled_at),
			enrolled_at
		FROM agents
		WHERE id = $1::uuid`,
		agentID,
	).Scan(
		&data.Hostname,
		&data.OSType,
		&data.OSVersion,
		&data.AgentVersion,
		&data.Status,
		&data.LastSeen,
		&data.EnrolledAt,
	)
	if err != nil {
		return nil, fmt.Errorf("load agent %s: %w", agentID, err)
	}

	// Count recent events (last 24h).
	if err := e.db.QueryRow(ctx, `
			SELECT COUNT(*) FROM events
			WHERE agent_id = $1::uuid
			  AND time >= NOW() - INTERVAL '24 hours'`,
		agentID,
	).Scan(&data.RecentEvents); err != nil {
		return nil, fmt.Errorf("数えられないため報告を作りません: %w", err)
	}

	// Count recent alerts (last 24h).
	if err := e.db.QueryRow(ctx, `
			SELECT COUNT(*) FROM alerts
			WHERE agent_id = $1::uuid
			  AND created_at >= NOW() - INTERVAL '24 hours'`,
		agentID,
	).Scan(&data.RecentAlerts); err != nil {
		return nil, fmt.Errorf("数えられないため報告を作りません: %w", err)
	}

	// Count recent network events (last 24h).
	if err := e.db.QueryRow(ctx, `
			SELECT COUNT(*) FROM events
			WHERE agent_id = $1::uuid
			  AND event_type = 'network'
			  AND time >= NOW() - INTERVAL '24 hours'`,
		agentID,
	).Scan(&data.NetworkEvents); err != nil {
		return nil, fmt.Errorf("数えられないため報告を作りません: %w", err)
	}

	return data, nil
}

// EvaluateAgent runs all controls for the given framework against a single agent
// and persists the report to the compliance_reports table.
func (e *Evaluator) EvaluateAgent(ctx context.Context, agentID string, framework Framework) (*ComplianceReport, error) {
	if e.db == nil {
		return nil, fmt.Errorf("evaluator: database not configured")
	}

	controls := frameworkControls(framework)
	if controls == nil {
		return nil, fmt.Errorf("evaluator: unknown framework %q", framework)
	}

	agentData, err := e.loadAgentData(ctx, agentID)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		AgentID:     agentID,
		Hostname:    agentData.Hostname,
		Framework:   framework,
		EvaluatedAt: time.Now().UTC(),
	}

	for _, ctrl := range controls {
		result := ctrl.Check(*agentData)
		cr := ControlReport{
			ControlID:   ctrl.ID,
			Title:       ctrl.Title,
			Description: ctrl.Description,
			Severity:    ctrl.Severity,
			Status:      result.Status,
			Evidence:    result.Evidence,
			Remediation: result.Remediation,
		}
		report.Controls = append(report.Controls, cr)

		switch result.Status {
		case "pass":
			report.Passed++
		case "fail":
			report.Failed++
		default:
			report.Unknown++
		}
	}

	total := report.Passed + report.Failed
	if total > 0 {
		report.Score = float64(report.Passed) * 100.0 / float64(total)
	}

	if err := e.persistReport(ctx, report); err != nil {
		tick.Fail(ctx, err, "evaluator: failed to persist compliance report",
			"agent_id", agentID, "framework", framework)
	}

	return report, nil
}

// EvaluateAll runs the given framework evaluation against all enrolled agents.
func (e *Evaluator) EvaluateAll(ctx context.Context, framework Framework) ([]ComplianceReport, error) {
	if e.db == nil {
		return nil, fmt.Errorf("evaluator: database not configured")
	}

	rows, err := e.db.Query(ctx, `
		SELECT id::text FROM agents
		WHERE last_seen > NOW() - INTERVAL '48 hours'
		ORDER BY hostname
		LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("evaluator: list agents: %w", err)
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr == nil {
			agentIDs = append(agentIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var reports []ComplianceReport
	for _, id := range agentIDs {
		report, evalErr := e.EvaluateAgent(ctx, id, framework)
		if evalErr != nil {
			tick.FailComponent(ctx, "compliance_evaluator", evalErr, "evaluator: skipping agent", "agent_id", id)
			continue
		}
		reports = append(reports, *report)
	}

	if reports == nil {
		reports = []ComplianceReport{}
	}
	return reports, nil
}

// persistReport saves or updates a compliance report in the database.
func (e *Evaluator) persistReport(ctx context.Context, r *ComplianceReport) error {
	detailsJSON, err := json.Marshal(r.Controls)
	if err != nil {
		return fmt.Errorf("marshal details: %w", err)
	}

	_, err = e.db.Exec(ctx, `
		INSERT INTO compliance_reports
			(agent_id, framework, score, passed, failed, unknown, details, evaluated_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`,
		r.AgentID,
		string(r.Framework),
		r.Score,
		r.Passed,
		r.Failed,
		r.Unknown,
		detailsJSON,
		r.EvaluatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert compliance_report: %w", err)
	}
	return nil
}

// GetLatestReport retrieves the most recent stored report for an agent+framework.
func (e *Evaluator) GetLatestReport(ctx context.Context, agentID string, framework Framework) (*ComplianceReport, error) {
	if e.db == nil {
		return nil, fmt.Errorf("evaluator: database not configured")
	}

	r := &ComplianceReport{AgentID: agentID, Framework: framework}
	var detailsJSON []byte
	err := e.db.QueryRow(ctx, `
		SELECT id::text, score, passed, failed, unknown, details, evaluated_at
		FROM compliance_reports
		WHERE agent_id = $1::uuid
		  AND framework = $2
		ORDER BY evaluated_at DESC
		LIMIT 1`,
		agentID, string(framework),
	).Scan(&r.ID, &r.Score, &r.Passed, &r.Failed, &r.Unknown, &detailsJSON, &r.EvaluatedAt)
	if err != nil {
		return nil, fmt.Errorf("get latest report: %w", err)
	}

	if len(detailsJSON) > 0 {
		if jsonErr := json.Unmarshal(detailsJSON, &r.Controls); jsonErr != nil {
			slog.Warn("evaluator: failed to unmarshal control details", "error", jsonErr)
		}
	}

	// Populate hostname from agents table.
	if err := e.db.QueryRow(ctx, `SELECT COALESCE(hostname,'') FROM agents WHERE id = $1::uuid`, agentID).
		Scan(&r.Hostname); err != nil {
		return nil, fmt.Errorf("数えられないため報告を作りません: %w", err)
	}

	return r, nil
}

// OrgSummary holds the average compliance score per framework across all agents.
type OrgSummary struct {
	Framework   Framework `json:"framework"`
	AvgScore    float64   `json:"avg_score"`
	AgentCount  int       `json:"agent_count"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// GetOrgSummary returns the org-wide average score per framework from the latest reports.
func (e *Evaluator) GetOrgSummary(ctx context.Context) ([]OrgSummary, error) {
	if e.db == nil {
		return nil, fmt.Errorf("evaluator: database not configured")
	}

	rows, err := e.db.Query(ctx, `
		SELECT framework, AVG(score), COUNT(DISTINCT agent_id), MAX(evaluated_at)
		FROM compliance_reports cr
		WHERE evaluated_at = (
			SELECT MAX(cr2.evaluated_at)
			FROM compliance_reports cr2
			WHERE cr2.agent_id = cr.agent_id
			  AND cr2.framework = cr.framework
		)
		GROUP BY framework
		ORDER BY framework`)
	if err != nil {
		return nil, fmt.Errorf("get org summary: %w", err)
	}
	defer rows.Close()

	var summaries []OrgSummary
	for rows.Next() {
		var s OrgSummary
		var fw string
		if scanErr := rows.Scan(&fw, &s.AvgScore, &s.AgentCount, &s.EvaluatedAt); scanErr == nil {
			s.Framework = Framework(fw)
			summaries = append(summaries, s)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if summaries == nil {
		summaries = []OrgSummary{}
	}
	return summaries, nil
}

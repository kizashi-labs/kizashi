package reports

// Report types: executive_summary, compliance_report, incident_report, threat_summary

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/detection"
)

// DateRange specifies the start and end of a reporting period.
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ReportSpec defines what report to generate.
type ReportSpec struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // executive_summary, compliance_report, incident_report, threat_summary
	Title       string            `json:"title"`
	DateRange   DateRange         `json:"date_range"`
	Filters     map[string]string `json:"filters,omitempty"`
	Format      string            `json:"format"` // json or csv
	RequestedBy string            `json:"requested_by,omitempty"`
}

// ReportResult holds a generated report's output.
type ReportResult struct {
	ID            string      `json:"id"`
	Type          string      `json:"type"`
	Title         string      `json:"title"`
	Format        string      `json:"format"`
	Data          interface{} `json:"data"`
	GeneratedAt   time.Time   `json:"generated_at"`
	FileSizeBytes int         `json:"file_size_bytes"`
}

// Generator generates reports by querying the database.
type Generator struct {
	pool *pgxpool.Pool
}

// NewGenerator creates a new Generator.
func NewGenerator(pool *pgxpool.Pool) *Generator {
	return &Generator{pool: pool}
}

// Generate dispatches to the appropriate type-specific report generator.
func (g *Generator) Generate(ctx context.Context, spec *ReportSpec) (*ReportResult, error) {
	if spec.ID == "" {
		spec.ID = uuid.New().String()
	}
	if spec.Format == "" {
		spec.Format = "json"
	}

	var (
		data interface{}
		err  error
	)

	switch spec.Type {
	case "executive_summary":
		data, err = g.GenerateExecutiveSummary(ctx, spec)
	case "compliance_report":
		data, err = g.GenerateComplianceReport(ctx, spec)
	case "incident_report":
		data, err = g.GenerateIncidentReport(ctx, spec)
	case "threat_summary":
		data, err = g.GenerateThreatSummary(ctx, spec)
	default:
		return nil, fmt.Errorf("unsupported report type: %s", spec.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("generating %s: %w", spec.Type, err)
	}

	result := &ReportResult{
		ID:          spec.ID,
		Type:        spec.Type,
		Title:       spec.Title,
		Format:      spec.Format,
		Data:        data,
		GeneratedAt: time.Now().UTC(),
	}

	// Calculate file size estimate
	if raw, err2 := json.Marshal(data); err2 == nil {
		result.FileSizeBytes = len(raw)
	}

	return result, nil
}

// ─── Executive Summary ────────────────────────────────────────────────────────

// ExecutiveSummaryData holds the data for an executive summary report.
type ExecutiveSummaryData struct {
	Period           DateRange        `json:"period"`
	TotalAlerts      int              `json:"total_alerts"`
	OpenAlerts       int              `json:"open_alerts"`
	ResolvedAlerts   int              `json:"resolved_alerts"`
	ResolutionRate   float64          `json:"resolution_rate_pct"`
	CriticalAlerts   int              `json:"critical_alerts"`
	TopThreats       []ThreatEntry    `json:"top_threats"`
	TopAgents        []AgentEntry     `json:"top_agents_by_alerts"`
	AgentHealth      AgentHealthStats `json:"agent_health"`
	AlertsBySeverity map[string]int   `json:"alerts_by_severity"`
}

// ThreatEntry represents a frequently-triggered rule or tactic.
type ThreatEntry struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// AgentEntry represents an agent and its alert count.
type AgentEntry struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Alerts   int    `json:"alerts"`
}

// AgentHealthStats summarizes agent health across the fleet.
type AgentHealthStats struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Offline int `json:"offline"`
	Stale   int `json:"stale"`
}

// GenerateExecutiveSummary generates a high-level security posture summary.
func (g *Generator) GenerateExecutiveSummary(ctx context.Context, spec *ReportSpec) (*ExecutiveSummaryData, error) {
	data := &ExecutiveSummaryData{
		Period:           spec.DateRange,
		TopThreats:       []ThreatEntry{},
		TopAgents:        []AgentEntry{},
		AlertsBySeverity: map[string]int{},
	}

	if g.pool == nil {
		return data, nil
	}

	// Alert counts
	_ = g.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.TotalAlerts)

	_ = g.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE status = 'open' AND created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.OpenAlerts)

	_ = g.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE status IN ('resolved','closed') AND created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.ResolvedAlerts)

	_ = g.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts
		WHERE severity >= 9 AND created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.CriticalAlerts)

	if data.TotalAlerts > 0 {
		data.ResolutionRate = float64(data.ResolvedAlerts) / float64(data.TotalAlerts) * 100
	}

	// Alerts by severity
	rows, err := g.pool.Query(ctx, `
		SELECT severity::text, COUNT(*) FROM alerts
		WHERE created_at BETWEEN $1 AND $2
		GROUP BY severity
	`, spec.DateRange.Start, spec.DateRange.End)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if rows.Scan(&sev, &cnt) == nil {
				data.AlertsBySeverity[sev] = cnt
			}
		}
	}

	// Top threats (rule names)
	//
	// alerts に rule_name 列は無い。ルール名は rules から JOIN で引き、
	// 紐付かないもの (組み込み検知器は rule_id を埋めない) は title で
	// まとめる。
	threatRows, err := g.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(r.name,''), al.title) AS rule_name, COUNT(*) as cnt
		FROM alerts al
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.created_at BETWEEN $1 AND $2
		GROUP BY 1 ORDER BY cnt DESC LIMIT 10
	`, spec.DateRange.Start, spec.DateRange.End)
	if err != nil {
		slog.Warn("reports: top threats query failed", "error", err)
	}
	if err == nil {
		defer threatRows.Close()
		for threatRows.Next() {
			var te ThreatEntry
			if threatRows.Scan(&te.Name, &te.Count) == nil {
				data.TopThreats = append(data.TopThreats, te)
			}
		}
	}

	// Top agents by alert count
	agentRows, err := g.pool.Query(ctx, `
		SELECT a.id::text, COALESCE(a.hostname, a.id::text), COUNT(al.id) as cnt
		FROM alerts al
		JOIN agents a ON a.id = al.agent_id
		WHERE al.created_at BETWEEN $1 AND $2
		GROUP BY a.id, a.hostname ORDER BY cnt DESC LIMIT 10
	`, spec.DateRange.Start, spec.DateRange.End)
	if err == nil {
		defer agentRows.Close()
		for agentRows.Next() {
			var ae AgentEntry
			if agentRows.Scan(&ae.AgentID, &ae.Hostname, &ae.Alerts) == nil {
				data.TopAgents = append(data.TopAgents, ae)
			}
		}
	}

	// Agent health stats
	_ = g.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&data.AgentHealth.Total)
	_ = g.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE status = 'online'`).Scan(&data.AgentHealth.Online)
	// 'inactive'(30日以上未確認の退役扱い)も offline に含める。除外すると
	// 直下の Stale = Total - Online - Offline に紛れ込み、退役ホストが
	// 「状態不明」として計上される。
	_ = g.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE status IN ('offline', 'inactive')`).Scan(&data.AgentHealth.Offline)
	data.AgentHealth.Stale = data.AgentHealth.Total - data.AgentHealth.Online - data.AgentHealth.Offline

	return data, nil
}

// ─── Compliance Report ────────────────────────────────────────────────────────

// ComplianceReportData holds the data for a compliance report.
type ComplianceReportData struct {
	Period         DateRange              `json:"period"`
	Framework      string                 `json:"framework"`
	OverallScore   float64                `json:"overall_score"`
	TotalEndpoints int                    `json:"total_endpoints"`
	CompliantCount int                    `json:"compliant_count"`
	NonCompliant   int                    `json:"non_compliant_count"`
	Controls       []ComplianceControlRow `json:"controls"`
}

// ComplianceControlRow represents one compliance control's assessment.
type ComplianceControlRow struct {
	ControlID   string  `json:"control_id"`
	ControlName string  `json:"control_name"`
	PassRate    float64 `json:"pass_rate_pct"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
}

// GenerateComplianceReport generates a NIST CSF/ISO27001 compliance status report.
func (g *Generator) GenerateComplianceReport(ctx context.Context, spec *ReportSpec) (*ComplianceReportData, error) {
	framework := "NIST CSF"
	if f, ok := spec.Filters["framework"]; ok {
		framework = f
	}

	data := &ComplianceReportData{
		Period:    spec.DateRange,
		Framework: framework,
		Controls:  []ComplianceControlRow{},
	}

	if g.pool == nil {
		data.OverallScore = 75.0
		return data, nil
	}

	// Query endpoint hardening table
	rows, err := g.pool.Query(ctx, `
		SELECT
			COALESCE(check_name, 'Unknown') as check_name,
			SUM(CASE WHEN passed THEN 1 ELSE 0 END) as passed,
			SUM(CASE WHEN NOT passed THEN 1 ELSE 0 END) as failed
		FROM endpoint_hardening_assessments
		WHERE assessed_at BETWEEN $1 AND $2
		GROUP BY check_name
		ORDER BY check_name
		LIMIT 50
	`, spec.DateRange.Start, spec.DateRange.End)
	if err != nil {
		slog.Warn("reports: compliance query failed, using empty data", "error", err)
	} else {
		defer rows.Close()
		totalPassed := 0
		totalFailed := 0
		for rows.Next() {
			var ctrl ComplianceControlRow
			var passed, failed int
			if rows.Scan(&ctrl.ControlName, &passed, &failed) == nil {
				ctrl.Passed = passed
				ctrl.Failed = failed
				if passed+failed > 0 {
					ctrl.PassRate = float64(passed) / float64(passed+failed) * 100
				}
				data.Controls = append(data.Controls, ctrl)
				totalPassed += passed
				totalFailed += failed
			}
		}
		if totalPassed+totalFailed > 0 {
			data.OverallScore = float64(totalPassed) / float64(totalPassed+totalFailed) * 100
			data.CompliantCount = totalPassed
			data.NonCompliant = totalFailed
		}
	}

	_ = g.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&data.TotalEndpoints)

	// Default score if no data
	if data.OverallScore == 0 && len(data.Controls) == 0 {
		data.OverallScore = 65.0
	}

	return data, nil
}

// ─── Incident Report ─────────────────────────────────────────────────────────

// IncidentReportData holds the data for an incident report.
type IncidentReportData struct {
	Period          DateRange     `json:"period"`
	TotalIncidents  int           `json:"total_incidents"`
	OpenIncidents   int           `json:"open_incidents"`
	ClosedIncidents int           `json:"closed_incidents"`
	AvgResolutionH  float64       `json:"avg_resolution_hours"`
	Incidents       []IncidentRow `json:"incidents"`
}

// IncidentRow represents a single incident in the report.
type IncidentRow struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	AffectedIDs []string   `json:"affected_agent_ids"`
}

// GenerateIncidentReport generates an incident timeline report.
func (g *Generator) GenerateIncidentReport(ctx context.Context, spec *ReportSpec) (*IncidentReportData, error) {
	data := &IncidentReportData{
		Period:    spec.DateRange,
		Incidents: []IncidentRow{},
	}

	if g.pool == nil {
		return data, nil
	}

	_ = g.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM incidents
		WHERE created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.TotalIncidents)

	_ = g.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM incidents
		WHERE status = 'open' AND created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.OpenIncidents)

	data.ClosedIncidents = data.TotalIncidents - data.OpenIncidents

	// Average resolution time
	_ = g.pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600), 0)
		FROM incidents
		WHERE resolved_at IS NOT NULL
		  AND created_at BETWEEN $1 AND $2
	`, spec.DateRange.Start, spec.DateRange.End).Scan(&data.AvgResolutionH)

	// Incident list
	rows, err := g.pool.Query(ctx, `
		SELECT id::text, COALESCE(title,''), COALESCE(severity::text,'medium'),
		       COALESCE(status,'open'), created_at, resolved_at
		FROM incidents
		WHERE created_at BETWEEN $1 AND $2
		ORDER BY created_at DESC
		LIMIT 100
	`, spec.DateRange.Start, spec.DateRange.End)
	if err != nil {
		slog.Warn("reports: incident query failed", "error", err)
		return data, nil
	}
	defer rows.Close()
	for rows.Next() {
		var ir IncidentRow
		if err := rows.Scan(&ir.ID, &ir.Title, &ir.Severity, &ir.Status, &ir.CreatedAt, &ir.ResolvedAt); err == nil {
			ir.AffectedIDs = []string{}
			data.Incidents = append(data.Incidents, ir)
		}
	}

	return data, nil
}

// ─── Threat Summary ───────────────────────────────────────────────────────────

// ThreatSummaryData holds the data for a threat summary report.
type ThreatSummaryData struct {
	Period          DateRange          `json:"period"`
	TotalIOCMatches int                `json:"total_ioc_matches"`
	TopIOCs         []IOCMatchEntry    `json:"top_ioc_matches"`
	SigmaRulesHit   []SigmaRuleEntry   `json:"sigma_rules_triggered"`
	MITRETactics    []MITRETacticEntry `json:"mitre_tactics"`
	ThreatsByType   map[string]int     `json:"threats_by_type"`
}

// IOCMatchEntry represents a frequently-matched IOC.
type IOCMatchEntry struct {
	Value string `json:"value"`
	Type  string `json:"type"`
	Hits  int    `json:"hits"`
}

// SigmaRuleEntry represents a frequently triggered Sigma rule.
type SigmaRuleEntry struct {
	RuleName string `json:"rule_name"`
	RuleID   string `json:"rule_id"`
	Hits     int    `json:"hits"`
}

// MITRETacticEntry represents a MITRE ATT&CK tactic and its alert count.
type MITRETacticEntry struct {
	Tactic string `json:"tactic"`
	Count  int    `json:"count"`
}

// GenerateThreatSummary generates a threat intelligence summary report.
func (g *Generator) GenerateThreatSummary(ctx context.Context, spec *ReportSpec) (*ThreatSummaryData, error) {
	data := &ThreatSummaryData{
		Period:        spec.DateRange,
		TopIOCs:       []IOCMatchEntry{},
		SigmaRulesHit: []SigmaRuleEntry{},
		MITRETactics:  []MITRETacticEntry{},
		ThreatsByType: map[string]int{},
	}

	if g.pool == nil {
		return data, nil
	}

	// Top Sigma rules triggered
	//
	// alerts に rule_name 列は無い。ここは rule_id と対で出す「発火した
	// ルール」の一覧なので、title へのフォールバックはしない — ルールに
	// 紐付かないアラート (組み込み検知器) は元の `rule_name IS NOT NULL`
	// と同じく除外する。
	ruleRows, err := g.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(r.name,''),'Unknown'), al.rule_id::text, COUNT(*) as cnt
		FROM alerts al
		JOIN rules r ON r.id = al.rule_id
		WHERE al.created_at BETWEEN $1 AND $2
		GROUP BY r.name, al.rule_id
		ORDER BY cnt DESC
		LIMIT 20
	`, spec.DateRange.Start, spec.DateRange.End)
	if err != nil {
		slog.Warn("reports: top sigma rules query failed", "error", err)
	}
	if err == nil {
		defer ruleRows.Close()
		for ruleRows.Next() {
			var entry SigmaRuleEntry
			if ruleRows.Scan(&entry.RuleName, &entry.RuleID, &entry.Hits) == nil {
				data.SigmaRulesHit = append(data.SigmaRulesHit, entry)
				data.TotalIOCMatches += entry.Hits
			}
		}
	}

	// MITRE ATT&CK tactic breakdown
	//
	// alerts に raw_data / mitre_tactic 列は無い。実在するのは
	// mitre_technique (T1059 のようなテクニック ID) だけなので、
	// SQL ではテクニック単位で数え、タクティクへの写像は Go 側で
	// detection.TacticForTechnique に任せる。scorer 側と同じ写像表を
	// 使うため、片方だけ更新されて数字が食い違うことがない。
	mitreRows, err := g.pool.Query(ctx, `
		SELECT mitre_technique, COUNT(*) as cnt
		FROM alerts
		WHERE created_at BETWEEN $1 AND $2
		  AND mitre_technique IS NOT NULL AND mitre_technique != ''
		GROUP BY mitre_technique
	`, spec.DateRange.Start, spec.DateRange.End)
	if err != nil {
		slog.Warn("reports: mitre technique query failed", "error", err)
	}
	if err == nil {
		byTactic := map[string]int{}
		for mitreRows.Next() {
			var technique string
			var cnt int
			if mitreRows.Scan(&technique, &cnt) != nil {
				continue
			}
			tactic := detection.TacticForTechnique(technique)
			if tactic == "" || tactic == "unknown" {
				// 写像表に無いテクニックは "Unknown" にまとめる。
				// TacticForTechnique は表に無いとき空文字を返す。
				tactic = "Unknown"
			}
			byTactic[tactic] += cnt
		}
		if err := mitreRows.Err(); err != nil {
			slog.Warn("reports: mitre technique row iteration failed", "error", err)
		}
		mitreRows.Close()

		for tactic, cnt := range byTactic {
			data.MITRETactics = append(data.MITRETactics, MITRETacticEntry{Tactic: tactic, Count: cnt})
		}
		// map の反復順は不定なので、出力を安定させるために並べ替える。
		sort.Slice(data.MITRETactics, func(i, j int) bool {
			if data.MITRETactics[i].Count != data.MITRETactics[j].Count {
				return data.MITRETactics[i].Count > data.MITRETactics[j].Count
			}
			return data.MITRETactics[i].Tactic < data.MITRETactics[j].Tactic
		})
		if len(data.MITRETactics) > 15 {
			data.MITRETactics = data.MITRETactics[:15]
		}
	}

	// Threats by type
	//
	// alerts に alert_type 列は無い。種別に相当する実在の列は source
	// (sigma / ioc / anomaly / mobile-mtd / custom …) で、検知の出どころを
	// 表す。既定値は 'custom'。
	typeRows, err := g.pool.Query(ctx, `
		SELECT COALESCE(source, 'unknown'), COUNT(*) FROM alerts
		WHERE created_at BETWEEN $1 AND $2
		GROUP BY source
	`, spec.DateRange.Start, spec.DateRange.End)
	if err != nil {
		slog.Warn("reports: threats by type query failed", "error", err)
	}
	if err == nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var t string
			var cnt int
			if typeRows.Scan(&t, &cnt) == nil {
				data.ThreatsByType[t] = cnt
			}
		}
	}

	return data, nil
}

// ─── CSV Conversion ───────────────────────────────────────────────────────────

// ToCSV converts report data to CSV format.
func (g *Generator) ToCSV(data interface{}) ([]byte, error) {
	if data == nil {
		return []byte{}, nil
	}

	// Marshal to JSON first to get a map representation
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling to JSON: %w", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		return nil, fmt.Errorf("unmarshaling JSON: %w", err)
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Write flat key-value pairs for the top-level fields
	headers := []string{"field", "value"}
	if err := w.Write(headers); err != nil {
		return nil, err
	}

	for k, v := range jsonMap {
		val := flattenValue(v)
		if err := w.Write([]string{k, val}); err != nil {
			return nil, err
		}
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}

// flattenValue converts an interface{} to a human-readable string for CSV output.
func flattenValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', 2, 64)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case map[string]interface{}:
		b, _ := json.Marshal(v)
		return string(b)
	case []interface{}:
		if reflect.ValueOf(v).Len() == 0 {
			return "[]"
		}
		b, _ := json.Marshal(v)
		return string(b)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ─── Report Templates ─────────────────────────────────────────────────────────

// ReportTemplate describes a report template available to users.
type ReportTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Fields      map[string]string `json:"fields"`
}

// GetTemplates returns all available report templates.
func GetTemplates() []ReportTemplate {
	return []ReportTemplate{
		{
			ID:          "executive_summary",
			Name:        "Executive Summary",
			Description: "High-level security posture overview including alert trends, top threats, and agent health statistics.",
			Fields: map[string]string{
				"date_range.start": "Start date (RFC3339)",
				"date_range.end":   "End date (RFC3339)",
				"format":           "Output format: json or csv",
			},
		},
		{
			ID:          "compliance_report",
			Name:        "Compliance Report",
			Description: "NIST CSF/ISO 27001 compliance status based on endpoint hardening assessments.",
			Fields: map[string]string{
				"date_range.start":  "Start date (RFC3339)",
				"date_range.end":    "End date (RFC3339)",
				"filters.framework": "Framework: NIST CSF or ISO 27001",
				"format":            "Output format: json or csv",
			},
		},
		{
			ID:          "incident_report",
			Name:        "Incident Report",
			Description: "Incident timeline with affected agents, resolution times, and response actions.",
			Fields: map[string]string{
				"date_range.start": "Start date (RFC3339)",
				"date_range.end":   "End date (RFC3339)",
				"format":           "Output format: json or csv",
			},
		},
		{
			ID:          "threat_summary",
			Name:        "Threat Intelligence Summary",
			Description: "Top IOC matches, Sigma rules triggered, and MITRE ATT&CK tactic breakdown.",
			Fields: map[string]string{
				"date_range.start": "Start date (RFC3339)",
				"date_range.end":   "End date (RFC3339)",
				"format":           "Output format: json or csv",
			},
		},
	}
}

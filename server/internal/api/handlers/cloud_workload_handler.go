package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CloudWorkloadHandler serves cloud workload security data.
// GET /api/v1/cloud-workload?provider=...
// GET /api/v1/cloud-workload/threats
// GET /api/v1/cloud-workload/misconfigs
type CloudWorkloadHandler struct {
	pool *pgxpool.Pool
}

func NewCloudWorkloadHandler(pool *pgxpool.Pool) *CloudWorkloadHandler {
	return &CloudWorkloadHandler{pool: pool}
}

func (h *CloudWorkloadHandler) tableExists(c *gin.Context, name string) bool {
	return tableIsThere(c.Request.Context(), h.pool, name)
}

// ── Types ─────────────────────────────────────────────────────────────────────

type cloudWorkload struct {
	ID               string          `json:"id"`
	WorkloadName     string          `json:"workload_name"`
	Type             string          `json:"type"`
	Provider         string          `json:"provider"`
	Region           string          `json:"region"`
	ProtectionStatus string          `json:"protection_status"`
	AgentVersion     *string         `json:"agent_version"`
	LastSeen         string          `json:"last_seen"`
	ThreatsCount     int             `json:"threats_count"`
	Tags             json.RawMessage `json:"tags"`
	RuntimeEvents    json.RawMessage `json:"runtime_events"`
	Vulnerabilities  json.RawMessage `json:"vulnerabilities"`
	ConfigIssues     json.RawMessage `json:"config_issues"`
	AccountID        string          `json:"account_id"`
	InstanceID       string          `json:"instance_id"`
}

type cloudThreat struct {
	ID                  string          `json:"id"`
	Timestamp           string          `json:"timestamp"`
	WorkloadID          string          `json:"workload_id"`
	WorkloadName        string          `json:"workload_name"`
	Provider            string          `json:"provider"`
	ThreatType          string          `json:"threat_type"`
	Severity            string          `json:"severity"`
	Process             string          `json:"process"`
	Cmdline             string          `json:"cmdline"`
	AutoBlocked         bool            `json:"auto_blocked"`
	ProcessTree         json.RawMessage `json:"process_tree"`
	NetworkConnections  json.RawMessage `json:"network_connections"`
	RecommendedResponse json.RawMessage `json:"recommended_response"`
}

type cloudMisconfig struct {
	ID           string  `json:"id"`
	WorkloadID   string  `json:"workload_id"`
	WorkloadName string  `json:"workload_name"`
	Provider     string  `json:"provider"`
	IssueType    string  `json:"issue_type"`
	Severity     string  `json:"severity"`
	Description  string  `json:"description"`
	Remediation  string  `json:"remediation"`
	Status       string  `json:"status"`
	QuickFixable bool    `json:"quick_fixable"`
	Region       *string `json:"region"`
}

// ListWorkloads returns cloud workloads, optionally filtered by provider.
// GET /api/v1/cloud-workload?provider=aws|azure|gcp
func (h *CloudWorkloadHandler) ListWorkloads(c *gin.Context) {
	ctx := c.Request.Context()
	provider := c.Query("provider")

	if !h.tableExists(c, "cloud_workloads") {
		c.JSON(http.StatusOK, []cloudWorkload{})
		return
	}

	const baseQuery = `
		SELECT id::text, workload_name, type, provider, region,
		       protection_status, agent_version, last_seen, threats_count,
		       COALESCE(tags,'[]'::jsonb), COALESCE(runtime_events,'[]'::jsonb),
		       COALESCE(vulnerabilities,'[]'::jsonb), COALESCE(config_issues,'[]'::jsonb),
		       account_id, instance_id
		FROM cloud_workloads`

	var (
		rows pgx.Rows
		err  error
	)
	if provider == "aws" || provider == "azure" || provider == "gcp" {
		rows, err = h.pool.Query(ctx, baseQuery+` WHERE provider=$1 ORDER BY threats_count DESC, last_seen DESC`, provider)
	} else {
		rows, err = h.pool.Query(ctx, baseQuery+` ORDER BY threats_count DESC, last_seen DESC LIMIT 200`)
	}
	if err != nil {
		ReadFailure(c, err, []cloudWorkload{})
		return
	}
	defer rows.Close()

	var workloads []cloudWorkload
	for rows.Next() {
		var w cloudWorkload
		var lastSeen time.Time
		if rows.Scan(
			&w.ID, &w.WorkloadName, &w.Type, &w.Provider, &w.Region,
			&w.ProtectionStatus, &w.AgentVersion, &lastSeen, &w.ThreatsCount,
			&w.Tags, &w.RuntimeEvents, &w.Vulnerabilities, &w.ConfigIssues,
			&w.AccountID, &w.InstanceID,
		) != nil {
			continue
		}
		w.LastSeen = lastSeen.Format(time.RFC3339)
		workloads = append(workloads, w)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListWorkloads: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []cloudWorkload{})
		return
	}
	if workloads == nil {
		workloads = []cloudWorkload{}
	}
	c.JSON(http.StatusOK, workloads)
}

// ListThreats returns runtime threats across cloud workloads.
// GET /api/v1/cloud-workload/threats
func (h *CloudWorkloadHandler) ListThreats(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "cloud_runtime_threats") {
		c.JSON(http.StatusOK, []cloudThreat{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, timestamp, workload_id, workload_name, provider,
		       threat_type, severity, process, cmdline, auto_blocked,
		       COALESCE(process_tree,'[]'::jsonb),
		       COALESCE(network_connections,'[]'::jsonb),
		       COALESCE(recommended_response,'[]'::jsonb)
		FROM cloud_runtime_threats ORDER BY timestamp DESC LIMIT 200
	`)
	if err != nil {
		ReadFailure(c, err, []cloudThreat{})
		return
	}
	defer rows.Close()

	var threats []cloudThreat
	for rows.Next() {
		var t cloudThreat
		var ts time.Time
		if rows.Scan(
			&t.ID, &ts, &t.WorkloadID, &t.WorkloadName, &t.Provider,
			&t.ThreatType, &t.Severity, &t.Process, &t.Cmdline, &t.AutoBlocked,
			&t.ProcessTree, &t.NetworkConnections, &t.RecommendedResponse,
		) != nil {
			continue
		}
		t.Timestamp = ts.Format(time.RFC3339)
		threats = append(threats, t)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListThreats: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []cloudThreat{})
		return
	}
	if threats == nil {
		threats = []cloudThreat{}
	}
	c.JSON(http.StatusOK, threats)
}

// ListMisconfigs returns cloud misconfiguration findings.
// GET /api/v1/cloud-workload/misconfigs
func (h *CloudWorkloadHandler) ListMisconfigs(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "cloud_misconfigurations") {
		c.JSON(http.StatusOK, []cloudMisconfig{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, workload_id, workload_name, provider, issue_type,
		       severity, description, remediation, status, quick_fixable, region
		FROM cloud_misconfigurations WHERE status='open' ORDER BY severity, created_at DESC LIMIT 200
	`)
	if err != nil {
		ReadFailure(c, err, []cloudMisconfig{})
		return
	}
	defer rows.Close()

	var misconfigs []cloudMisconfig
	for rows.Next() {
		var m cloudMisconfig
		if rows.Scan(
			&m.ID, &m.WorkloadID, &m.WorkloadName, &m.Provider, &m.IssueType,
			&m.Severity, &m.Description, &m.Remediation, &m.Status, &m.QuickFixable, &m.Region,
		) != nil {
			continue
		}
		misconfigs = append(misconfigs, m)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListMisconfigs: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []cloudMisconfig{})
		return
	}
	if misconfigs == nil {
		misconfigs = []cloudMisconfig{}
	}
	c.JSON(http.StatusOK, misconfigs)
}

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ChaosHandler serves the /admin/chaos-engineering page: a catalog of security
// chaos experiments plus their execution runs and approval requests.
type ChaosHandler struct {
	pool *pgxpool.Pool
}

func NewChaosHandler(pool *pgxpool.Pool) *ChaosHandler {
	return &ChaosHandler{pool: pool}
}

// displayName resolves a user_id to a human label (full name, else email, else
// the id) for stamping executed_by / requested_by.
func (h *ChaosHandler) displayName(c *gin.Context) string {
	uid := c.GetString("user_id")
	if uid == "" {
		return "unknown"
	}
	var name string
	if err := h.pool.QueryRow(c.Request.Context(),
		`SELECT COALESCE(NULLIF(full_name,''), email) FROM users WHERE id = $1::uuid`, uid).Scan(&name); err != nil || name == "" {
		return uid
	}
	return name
}

// captureMetrics samples real steady-state metrics: host CPU/memory/disk %
// (via the shared hostResources helper) plus a couple of DB-derived counts.
// Used to record before/after snapshots for a (dry-run) experiment.
func (h *ChaosHandler) captureMetrics(ctx context.Context) map[string]float64 {
	m := map[string]float64{}
	for k, v := range hostResources(ctx) {
		if f, ok := v.(float64); ok {
			m[k] = f
		}
	}
	var onlineAgents, openAlerts int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE status='online'`).Scan(&onlineAgents)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE status='open'`).Scan(&openAlerts)
	m["online_agents"] = float64(onlineAgents)
	m["open_alerts"] = float64(openAlerts)
	return m
}

// ListExperiments handles GET /api/v1/admin/chaos/experiments
func (h *ChaosHandler) ListExperiments(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	rows, err := h.pool.Query(ctx, `
		SELECT id, name, category, description, severity_impact, target_type,
		       estimated_duration_min, is_safe, hypothesis, blast_radius,
		       rollback_procedure, steady_state_metrics, execution_steps
		FROM chaos_experiments
		WHERE tenant_id = $1::uuid
		ORDER BY created_at ASC`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	out := []gin.H{}
	for rows.Next() {
		var (
			id, name, category, description, severity, targetType, isSafe, hypothesis, blastRadius string
			durationMin                                                                            int
			rollback, steady, steps                                                                json.RawMessage
		)
		if err := rows.Scan(&id, &name, &category, &description, &severity, &targetType,
			&durationMin, &isSafe, &hypothesis, &blastRadius, &rollback, &steady, &steps); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "name": name, "category": category, "description": description,
			"severity_impact": severity, "target_type": targetType,
			"estimated_duration_min": durationMin, "is_safe": isSafe,
			"hypothesis": hypothesis, "blast_radius": blastRadius,
			"rollback_procedure": rollback, "steady_state_metrics": steady, "execution_steps": steps,
		})
	}
	c.JSON(http.StatusOK, out)
}

// ListRuns handles GET /api/v1/admin/chaos/runs
func (h *ChaosHandler) ListRuns(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	rows, err := h.pool.Query(ctx, `
		SELECT id, experiment_id, experiment_name, executed_by, started_at, duration_min,
		       scope, result, findings_summary, hypothesis_actual,
		       metrics_before, metrics_after, rollback_taken, lessons_learned
		FROM chaos_runs
		WHERE tenant_id = $1::uuid
		ORDER BY started_at DESC`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	out := []gin.H{}
	for rows.Next() {
		var (
			id, expID, expName, executedBy, scope, result, findings, hypothesisActual, lessons string
			startedAt                                                                          time.Time
			durationMin                                                                        int
			rollbackTaken                                                                      bool
			metricsBefore, metricsAfter                                                        json.RawMessage
		)
		if err := rows.Scan(&id, &expID, &expName, &executedBy, &startedAt, &durationMin,
			&scope, &result, &findings, &hypothesisActual, &metricsBefore, &metricsAfter,
			&rollbackTaken, &lessons); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "experiment_id": expID, "experiment_name": expName,
			"executed_by": executedBy, "started_at": startedAt, "duration_min": durationMin,
			"scope": scope, "result": result, "findings_summary": findings,
			"hypothesis_actual": hypothesisActual, "metrics_before": metricsBefore,
			"metrics_after": metricsAfter, "rollback_taken": rollbackTaken,
			"lessons_learned": lessons,
		})
	}
	c.JSON(http.StatusOK, out)
}

// ListApprovals handles GET /api/v1/admin/chaos/approvals
func (h *ChaosHandler) ListApprovals(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	rows, err := h.pool.Query(ctx, `
		SELECT id, experiment_id, experiment_name, requested_by, justification,
		       approvers, status, requested_at
		FROM chaos_approvals
		WHERE tenant_id = $1::uuid
		ORDER BY requested_at DESC`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	out := []gin.H{}
	for rows.Next() {
		var (
			id, expID, expName, requestedBy, justification, status string
			approvers                                              json.RawMessage
			requestedAt                                            time.Time
		)
		if err := rows.Scan(&id, &expID, &expName, &requestedBy, &justification,
			&approvers, &status, &requestedAt); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "experiment_id": expID, "experiment_name": expName,
			"requested_by": requestedBy, "justification": justification,
			"approvers": approvers, "status": status, "requested_at": requestedAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

// CreateRun handles POST /api/v1/admin/chaos/runs — records a new execution.
// A run starts with result 'inconclusive' (no automated outcome engine).
func (h *ChaosHandler) CreateRun(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	var req struct {
		ExperimentID string `json:"experiment_id"`
		Scope        string `json:"scope"`
		RunNow       bool   `json:"run_now"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ExperimentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "experiment_id は必須です"})
		return
	}

	var expName string
	var duration int
	if err := h.pool.QueryRow(ctx,
		`SELECT name, estimated_duration_min FROM chaos_experiments WHERE id = $1::uuid AND tenant_id = $2::uuid`,
		req.ExperimentID, tenantID).Scan(&expName, &duration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "実験が見つかりません"})
		return
	}

	executedBy := h.displayName(c)
	startedAt := time.Now()

	// Dry-run execution: capture real steady-state metrics before and after.
	// No fault is actually injected (safe mode), so the run is honestly recorded
	// as 'inconclusive' — it rehearses the experiment and snapshots live metrics
	// rather than testing the hypothesis. Two back-to-back samples (each does a
	// short CPU sampling window) give a realistic before/after pair.
	metricsBefore := h.captureMetrics(ctx)
	metricsAfter := h.captureMetrics(ctx)
	beforeJSON, _ := json.Marshal(metricsBefore)
	afterJSON, _ := json.Marshal(metricsAfter)

	const findings = "ドライラン実行: 実障害注入は安全のため行わず、実環境の定常状態メトリクスを記録しました。"
	const lessons = "実障害注入を有効化するには承認フローと安全装置(自動停止・自動ロールバック)の整備が前提です。"

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO chaos_runs
		    (tenant_id, experiment_id, experiment_name, executed_by, started_at,
		     duration_min, scope, result, findings_summary, lessons_learned,
		     metrics_before, metrics_after, rollback_taken)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, 'inconclusive', $8, $9,
		        $10::jsonb, $11::jsonb, FALSE)
		RETURNING id`,
		tenantID, req.ExperimentID, expName, executedBy, startedAt, duration, req.Scope,
		findings, lessons, beforeJSON, afterJSON).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "experiment_id": req.ExperimentID, "experiment_name": expName,
		"executed_by": executedBy, "started_at": startedAt, "duration_min": duration,
		"scope": req.Scope, "result": "inconclusive", "findings_summary": findings,
		"hypothesis_actual": "", "metrics_before": metricsBefore, "metrics_after": metricsAfter,
		"rollback_taken": false, "lessons_learned": lessons,
	})
}

// CreateApproval handles POST /api/v1/admin/chaos/approvals
func (h *ChaosHandler) CreateApproval(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")

	var req struct {
		ExperimentID  string   `json:"experiment_id"`
		Justification string   `json:"justification"`
		Approvers     []string `json:"approvers"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ExperimentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "experiment_id は必須です"})
		return
	}
	if req.Approvers == nil {
		req.Approvers = []string{}
	}

	var expName string
	_ = h.pool.QueryRow(ctx,
		`SELECT name FROM chaos_experiments WHERE id = $1::uuid AND tenant_id = $2::uuid`,
		req.ExperimentID, tenantID).Scan(&expName)

	requestedBy := h.displayName(c)
	approversJSON, _ := json.Marshal(req.Approvers)
	requestedAt := time.Now()

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO chaos_approvals
		    (tenant_id, experiment_id, experiment_name, requested_by, justification, approvers, status, requested_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, 'pending', $7)
		RETURNING id`,
		tenantID, req.ExperimentID, expName, requestedBy, req.Justification, approversJSON, requestedAt).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "experiment_id": req.ExperimentID, "experiment_name": expName,
		"requested_by": requestedBy, "justification": req.Justification,
		"approvers": req.Approvers, "status": "pending", "requested_at": requestedAt,
	})
}

// UpdateApproval handles PUT /api/v1/admin/chaos/approvals/:id
func (h *ChaosHandler) UpdateApproval(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.GetString("tenant_id")
	id := c.Param("id")

	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Status != "approved" && req.Status != "rejected" && req.Status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status が不正です"})
		return
	}

	ct, err := h.pool.Exec(ctx,
		`UPDATE chaos_approvals SET status = $3 WHERE id = $1::uuid AND tenant_id = $2::uuid`,
		id, tenantID, req.Status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "承認申請が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

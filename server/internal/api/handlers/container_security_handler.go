package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContainerSecurityHandler manages Kubernetes security policies and violations.
type ContainerSecurityHandler struct {
	pool *pgxpool.Pool
}

func NewContainerSecurityHandler(pool *pgxpool.Pool) *ContainerSecurityHandler {
	return &ContainerSecurityHandler{pool: pool}
}

// ListPolicies GET /policies
func (h *ContainerSecurityHandler) ListPolicies(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, namespace, policy_type, rules, enforcement, violation_count, is_active, created_at, updated_at
		 FROM k8s_security_policies ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Policy struct {
		ID             string      `json:"id"`
		Name           string      `json:"name"`
		Namespace      string      `json:"namespace"`
		PolicyType     string      `json:"policy_type"`
		Rules          interface{} `json:"rules"`
		Enforcement    string      `json:"enforcement"`
		ViolationCount int         `json:"violation_count"`
		IsActive       bool        `json:"is_active"`
		CreatedAt      time.Time   `json:"created_at"`
		UpdatedAt      time.Time   `json:"updated_at"`
	}
	policies := []Policy{}
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Namespace, &p.PolicyType, &p.Rules,
			&p.Enforcement, &p.ViolationCount, &p.IsActive, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, policies)
}

// CreatePolicy POST /policies
func (h *ContainerSecurityHandler) CreatePolicy(c *gin.Context) {
	var req struct {
		Name        string      `json:"name" binding:"required"`
		Namespace   string      `json:"namespace"`
		PolicyType  string      `json:"policy_type" binding:"required"`
		Rules       interface{} `json:"rules"`
		Enforcement string      `json:"enforcement"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Namespace == "" {
		req.Namespace = "*"
	}
	if req.Enforcement == "" {
		req.Enforcement = "audit"
	}
	if req.Rules == nil {
		req.Rules = map[string]interface{}{}
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO k8s_security_policies (name, namespace, policy_type, rules, enforcement)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.Name, req.Namespace, req.PolicyType, req.Rules, req.Enforcement,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// UpdatePolicy PUT /policies/:id
func (h *ContainerSecurityHandler) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        string      `json:"name"`
		Namespace   string      `json:"namespace"`
		PolicyType  string      `json:"policy_type"`
		Rules       interface{} `json:"rules"`
		Enforcement string      `json:"enforcement"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE k8s_security_policies
		 SET name=COALESCE(NULLIF($1,''), name),
		     namespace=COALESCE(NULLIF($2,''), namespace),
		     policy_type=COALESCE(NULLIF($3,''), policy_type),
		     rules=COALESCE($4::jsonb, rules),
		     enforcement=COALESCE(NULLIF($5,''), enforcement),
		     updated_at=NOW()
		 WHERE id=$6`,
		req.Name, req.Namespace, req.PolicyType, req.Rules, req.Enforcement, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeletePolicy DELETE /policies/:id
func (h *ContainerSecurityHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(), `DELETE FROM k8s_security_policies WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// TogglePolicy POST /policies/:id/toggle
func (h *ContainerSecurityHandler) TogglePolicy(c *gin.Context) {
	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE k8s_security_policies SET is_active = NOT is_active, updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "toggled"})
}

// ListViolations GET /violations — filter by policy_id, severity, status
func (h *ContainerSecurityHandler) ListViolations(c *gin.Context) {
	policyID := c.Query("policy_id")
	severity := c.Query("severity")
	status := c.Query("status")

	query := `SELECT id, policy_id, namespace, resource_type, resource_name, violation_msg, severity, status, created_at
	          FROM k8s_policy_violations WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if policyID != "" {
		query += ` AND policy_id=$` + itoa(argIdx)
		args = append(args, policyID)
		argIdx++
	}
	if severity != "" {
		query += ` AND severity=$` + itoa(argIdx)
		args = append(args, severity)
		argIdx++
	}
	if status != "" {
		query += ` AND status=$` + itoa(argIdx)
		args = append(args, status)
		argIdx++
	}
	query += ` ORDER BY created_at DESC LIMIT 200`

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Violation struct {
		ID           string    `json:"id"`
		PolicyID     string    `json:"policy_id"`
		Namespace    string    `json:"namespace"`
		ResourceType string    `json:"resource_type"`
		ResourceName string    `json:"resource_name"`
		ViolationMsg string    `json:"violation_msg"`
		Severity     string    `json:"severity"`
		Status       string    `json:"status"`
		CreatedAt    time.Time `json:"created_at"`
	}
	violations := []Violation{}
	for rows.Next() {
		var v Violation
		if err := rows.Scan(&v.ID, &v.PolicyID, &v.Namespace, &v.ResourceType, &v.ResourceName,
			&v.ViolationMsg, &v.Severity, &v.Status, &v.CreatedAt); err != nil {
			continue
		}
		violations = append(violations, v)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, violations)
}

// ResolveViolation POST /violations/:id/resolve
func (h *ContainerSecurityHandler) ResolveViolation(c *gin.Context) {
	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE k8s_policy_violations SET status='resolved' WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "resolved"})
}

// GetStats GET /stats — violation counts by severity, top violating policies, namespace breakdown
func (h *ContainerSecurityHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Violation counts by severity
	type SeverityCount struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	severityCounts := []SeverityCount{}
	rows, err := h.pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM k8s_policy_violations WHERE status='open' GROUP BY severity ORDER BY COUNT(*) DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sc SeverityCount
			if err := rows.Scan(&sc.Severity, &sc.Count); err == nil {
				severityCounts = append(severityCounts, sc)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("container severity counts iteration failed", "error", err)
		}
	}

	// Top violating policies
	type PolicyStat struct {
		PolicyID   string `json:"policy_id"`
		PolicyName string `json:"policy_name"`
		Count      int    `json:"count"`
	}
	topPolicies := []PolicyStat{}
	rows2, err := h.pool.Query(ctx,
		`SELECT v.policy_id, p.name, COUNT(*) as cnt
		 FROM k8s_policy_violations v
		 JOIN k8s_security_policies p ON p.id = v.policy_id
		 WHERE v.status='open'
		 GROUP BY v.policy_id, p.name
		 ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var ps PolicyStat
			if err := rows2.Scan(&ps.PolicyID, &ps.PolicyName, &ps.Count); err == nil {
				topPolicies = append(topPolicies, ps)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("container topPolicies iteration failed", "error", err)
		}
	}

	// Namespace breakdown
	type NSCount struct {
		Namespace string `json:"namespace"`
		Count     int    `json:"count"`
	}
	nsCounts := []NSCount{}
	rows3, err := h.pool.Query(ctx,
		`SELECT namespace, COUNT(*) FROM k8s_policy_violations WHERE status='open' GROUP BY namespace ORDER BY COUNT(*) DESC LIMIT 10`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var ns NSCount
			if err := rows3.Scan(&ns.Namespace, &ns.Count); err == nil {
				nsCounts = append(nsCounts, ns)
			}
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("container nsCounts iteration failed", "error", err)
		}
	}

	var totalPolicies, activePolicies, totalViolations int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) FROM k8s_security_policies`).
		Scan(&totalPolicies, &activePolicies)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM k8s_policy_violations WHERE status='open'`).
		Scan(&totalViolations)

	c.JSON(http.StatusOK, gin.H{
		"total_policies":      totalPolicies,
		"active_policies":     activePolicies,
		"open_violations":     totalViolations,
		"by_severity":         severityCounts,
		"top_policies":        topPolicies,
		"namespace_breakdown": nsCounts,
	})
}

// ListImages GET /admin/container-security/images — migration 169
func (h *ContainerSecurityHandler) ListImages(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, registry, repository, tag, COALESCE(digest,''),
		       COALESCE(size_bytes,0), vulnerability_count, critical_vulns, high_vulns,
		       scan_status, last_scanned_at, created_at
		FROM container_images ORDER BY critical_vulns DESC, vulnerability_count DESC
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"images": []any{}})
		return
	}
	defer rows.Close()

	type Image struct {
		ID                 string  `json:"id"`
		Registry           string  `json:"registry"`
		Repository         string  `json:"repository"`
		Tag                string  `json:"tag"`
		Digest             string  `json:"digest"`
		SizeBytes          int64   `json:"size_bytes"`
		VulnerabilityCount int     `json:"vulnerability_count"`
		CriticalVulns      int     `json:"critical_vulns"`
		HighVulns          int     `json:"high_vulns"`
		ScanStatus         string  `json:"scan_status"`
		LastScannedAt      *string `json:"last_scanned_at"`
		CreatedAt          string  `json:"created_at"`
	}

	var list []Image
	for rows.Next() {
		var img Image
		var lastScanned *time.Time
		var createdAt time.Time
		if err := rows.Scan(&img.ID, &img.Registry, &img.Repository, &img.Tag, &img.Digest,
			&img.SizeBytes, &img.VulnerabilityCount, &img.CriticalVulns, &img.HighVulns,
			&img.ScanStatus, &lastScanned, &createdAt); err != nil {
			continue
		}
		img.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if lastScanned != nil {
			s := lastScanned.UTC().Format(time.RFC3339)
			img.LastScannedAt = &s
		}
		list = append(list, img)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if list == nil {
		list = []Image{}
	}
	c.JSON(http.StatusOK, gin.H{"images": list})
}

// ListRuntimeEvents GET /admin/container-security/events — migration 169
func (h *ContainerSecurityHandler) ListRuntimeEvents(c *gin.Context) {
	severity := c.Query("severity")
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, container_id, COALESCE(container_name,''), image,
		       COALESCE(namespace,'default'), COALESCE(pod_name,''), COALESCE(node_name,''),
		       event_type, severity, COALESCE(description,''), created_at
		FROM container_runtime_events
		WHERE ($1 = '' OR severity = $1)
		ORDER BY created_at DESC LIMIT 100
	`, severity)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"events": []any{}})
		return
	}
	defer rows.Close()

	type Event struct {
		ID            string `json:"id"`
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		Image         string `json:"image"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name"`
		NodeName      string `json:"node_name"`
		EventType     string `json:"event_type"`
		Severity      string `json:"severity"`
		Description   string `json:"description"`
		CreatedAt     string `json:"created_at"`
	}
	var list []Event
	for rows.Next() {
		var e Event
		var createdAt time.Time
		if err := rows.Scan(&e.ID, &e.ContainerID, &e.ContainerName, &e.Image,
			&e.Namespace, &e.PodName, &e.NodeName, &e.EventType, &e.Severity,
			&e.Description, &createdAt); err != nil {
			continue
		}
		e.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, e)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if list == nil {
		list = []Event{}
	}
	c.JSON(http.StatusOK, gin.H{"events": list})
}

// ImageStats GET /admin/container-security/image-stats — migration 169
func (h *ContainerSecurityHandler) ImageStats(c *gin.Context) {
	var totalImages, criticalImages, scanned int
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE critical_vulns > 0),
		       COUNT(*) FILTER (WHERE scan_status='scanned')
		FROM container_images
	`).Scan(&totalImages, &criticalImages, &scanned)

	var totalEvents, criticalEvents int
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE severity='critical')
		FROM container_runtime_events
		WHERE created_at >= NOW() - INTERVAL '24 hours'
	`).Scan(&totalEvents, &criticalEvents)

	c.JSON(http.StatusOK, gin.H{
		"total_images":    totalImages,
		"critical_images": criticalImages,
		"scanned":         scanned,
		"events_24h":      totalEvents,
		"critical_events": criticalEvents,
	})
}

// TriggerImageScan POST /admin/container-security/images/:id/scan — migration 169
func (h *ContainerSecurityHandler) TriggerImageScan(c *gin.Context) {
	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE container_images SET scan_status='scanning', updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "scanning", "message": "Scan initiated"})
}

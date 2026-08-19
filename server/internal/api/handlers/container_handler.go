package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContainerHandler manages container/Kubernetes workload monitoring.
type ContainerHandler struct {
	pool *pgxpool.Pool
}

// NewContainerHandler creates a new ContainerHandler.
func NewContainerHandler(pool *pgxpool.Pool) *ContainerHandler {
	return &ContainerHandler{pool: pool}
}

func (h *ContainerHandler) workloadTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "container_workloads")
}

func (h *ContainerHandler) eventTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "container_events")
}

type containerWorkload struct {
	ID              string      `json:"id"`
	ClusterName     string      `json:"cluster_name"`
	Namespace       string      `json:"namespace"`
	WorkloadType    string      `json:"workload_type"`
	WorkloadName    string      `json:"workload_name"`
	Image           string      `json:"image"`
	ImageDigest     string      `json:"image_digest"`
	Replicas        int         `json:"replicas"`
	ReadyReplicas   int         `json:"ready_replicas"`
	Status          string      `json:"status"`
	RiskScore       int         `json:"risk_score"`
	Vulnerabilities interface{} `json:"vulnerabilities"`
	Labels          interface{} `json:"labels"`
	LastSeenAt      string      `json:"last_seen_at"`
	CreatedAt       string      `json:"created_at"`
	UpdatedAt       string      `json:"updated_at"`
}

// ListWorkloads returns container workloads with optional filters.
// GET /api/v1/containers/workloads
func (h *ContainerHandler) ListWorkloads(c *gin.Context) {
	if !h.workloadTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"workloads": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	cluster := c.Query("cluster")
	namespace := c.Query("namespace")
	status := c.Query("status")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	query := `SELECT id, cluster_name, namespace, workload_type, workload_name, image, image_digest,
	                 replicas, ready_replicas, status, risk_score, vulnerabilities, labels,
	                 last_seen_at, created_at, updated_at
	          FROM container_workloads WHERE 1=1`
	args := []interface{}{}
	i := 1
	if cluster != "" {
		query += ` AND cluster_name=$` + strconv.Itoa(i)
		args = append(args, cluster)
		i++
	}
	if namespace != "" {
		query += ` AND namespace=$` + strconv.Itoa(i)
		args = append(args, namespace)
		i++
	}
	if status != "" {
		query += ` AND status=$` + strconv.Itoa(i)
		args = append(args, status)
		i++
	}
	query += ` ORDER BY risk_score DESC, created_at DESC LIMIT $` + strconv.Itoa(i) + ` OFFSET $` + strconv.Itoa(i+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ワークロード一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var result []containerWorkload
	for rows.Next() {
		var wl containerWorkload
		var vulnsRaw, labelsRaw []byte
		var lastSeen, createdAt, updatedAt time.Time
		if err := rows.Scan(
			&wl.ID, &wl.ClusterName, &wl.Namespace, &wl.WorkloadType, &wl.WorkloadName,
			&wl.Image, &wl.ImageDigest, &wl.Replicas, &wl.ReadyReplicas, &wl.Status,
			&wl.RiskScore, &vulnsRaw, &labelsRaw, &lastSeen, &createdAt, &updatedAt,
		); err != nil {
			continue
		}
		if vulnsRaw != nil {
			_ = json.Unmarshal(vulnsRaw, &wl.Vulnerabilities)
		}
		if wl.Vulnerabilities == nil {
			wl.Vulnerabilities = []interface{}{}
		}
		if labelsRaw != nil {
			_ = json.Unmarshal(labelsRaw, &wl.Labels)
		}
		if wl.Labels == nil {
			wl.Labels = map[string]interface{}{}
		}
		wl.LastSeenAt = lastSeen.Format(time.RFC3339)
		wl.CreatedAt = createdAt.Format(time.RFC3339)
		wl.UpdatedAt = updatedAt.Format(time.RFC3339)
		result = append(result, wl)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []containerWorkload{}
	}
	c.JSON(http.StatusOK, gin.H{"workloads": result, "total": len(result)})
}

// GetWorkload returns a single workload.
// GET /api/v1/containers/workloads/:id
func (h *ContainerHandler) GetWorkload(c *gin.Context) {
	if !h.workloadTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	var wl containerWorkload
	var vulnsRaw, labelsRaw []byte
	var lastSeen, createdAt, updatedAt time.Time
	err := h.pool.QueryRow(ctx,
		`SELECT id, cluster_name, namespace, workload_type, workload_name, image, image_digest,
		        replicas, ready_replicas, status, risk_score, vulnerabilities, labels,
		        last_seen_at, created_at, updated_at
		 FROM container_workloads WHERE id=$1`, id,
	).Scan(
		&wl.ID, &wl.ClusterName, &wl.Namespace, &wl.WorkloadType, &wl.WorkloadName,
		&wl.Image, &wl.ImageDigest, &wl.Replicas, &wl.ReadyReplicas, &wl.Status,
		&wl.RiskScore, &vulnsRaw, &labelsRaw, &lastSeen, &createdAt, &updatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ワークロードが見つかりません"})
		return
	}
	if vulnsRaw != nil {
		_ = json.Unmarshal(vulnsRaw, &wl.Vulnerabilities)
	}
	if wl.Vulnerabilities == nil {
		wl.Vulnerabilities = []interface{}{}
	}
	if labelsRaw != nil {
		_ = json.Unmarshal(labelsRaw, &wl.Labels)
	}
	if wl.Labels == nil {
		wl.Labels = map[string]interface{}{}
	}
	wl.LastSeenAt = lastSeen.Format(time.RFC3339)
	wl.CreatedAt = createdAt.Format(time.RFC3339)
	wl.UpdatedAt = updatedAt.Format(time.RFC3339)
	c.JSON(http.StatusOK, wl)
}

// UpsertWorkload batch-upserts workloads from a sync payload.
// POST /api/v1/containers/workloads/sync
func (h *ContainerHandler) UpsertWorkload(c *gin.Context) {
	if !h.workloadTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var body struct {
		Workloads []struct {
			ClusterName     string      `json:"cluster_name" binding:"required"`
			Namespace       string      `json:"namespace" binding:"required"`
			WorkloadType    string      `json:"workload_type" binding:"required"`
			WorkloadName    string      `json:"workload_name" binding:"required"`
			Image           string      `json:"image" binding:"required"`
			ImageDigest     string      `json:"image_digest"`
			Replicas        int         `json:"replicas"`
			ReadyReplicas   int         `json:"ready_replicas"`
			Status          string      `json:"status"`
			RiskScore       int         `json:"risk_score"`
			Vulnerabilities interface{} `json:"vulnerabilities"`
			Labels          interface{} `json:"labels"`
		} `json:"workloads"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}

	ctx := c.Request.Context()
	upserted := 0
	for _, wl := range body.Workloads {
		vulnsJSON, _ := json.Marshal(wl.Vulnerabilities)
		labelsJSON, _ := json.Marshal(wl.Labels)
		if vulnsJSON == nil {
			vulnsJSON = []byte("[]")
		}
		if labelsJSON == nil {
			labelsJSON = []byte("{}")
		}
		_, err := h.pool.Exec(ctx,
			`INSERT INTO container_workloads
			   (cluster_name, namespace, workload_type, workload_name, image, image_digest,
			    replicas, ready_replicas, status, risk_score, vulnerabilities, labels, last_seen_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW())
			 ON CONFLICT (cluster_name, namespace, workload_name)
			 DO UPDATE SET image=$5, image_digest=$6, replicas=$7, ready_replicas=$8, status=$9,
			               risk_score=$10, vulnerabilities=$11, labels=$12, last_seen_at=NOW(), updated_at=NOW()`,
			wl.ClusterName, wl.Namespace, wl.WorkloadType, wl.WorkloadName, wl.Image, wl.ImageDigest,
			wl.Replicas, wl.ReadyReplicas, wl.Status, wl.RiskScore, vulnsJSON, labelsJSON,
		)
		if err == nil {
			upserted++
		}
	}
	c.JSON(http.StatusOK, gin.H{"upserted": upserted, "message": "ワークロードを同期しました"})
}

// GetWorkloadEvents returns events for a workload.
// GET /api/v1/containers/workloads/:id/events
func (h *ContainerHandler) GetWorkloadEvents(c *gin.Context) {
	if !h.eventTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0})
		return
	}
	id := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, workload_id, event_type, severity, message, details, occurred_at
		 FROM container_events WHERE workload_id=$1
		 ORDER BY occurred_at DESC LIMIT $2 OFFSET $3`,
		id, limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "イベントの取得に失敗しました"})
		return
	}
	defer rows.Close()

	type containerEvent struct {
		ID         string      `json:"id"`
		WorkloadID string      `json:"workload_id"`
		EventType  string      `json:"event_type"`
		Severity   string      `json:"severity"`
		Message    string      `json:"message"`
		Details    interface{} `json:"details"`
		OccurredAt string      `json:"occurred_at"`
	}

	var result []containerEvent
	for rows.Next() {
		var ev containerEvent
		var detailsRaw []byte
		var occurredAt time.Time
		if err := rows.Scan(
			&ev.ID, &ev.WorkloadID, &ev.EventType, &ev.Severity,
			&ev.Message, &detailsRaw, &occurredAt,
		); err != nil {
			continue
		}
		if detailsRaw != nil {
			_ = json.Unmarshal(detailsRaw, &ev.Details)
		}
		if ev.Details == nil {
			ev.Details = map[string]interface{}{}
		}
		ev.OccurredAt = occurredAt.Format(time.RFC3339)
		result = append(result, ev)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []containerEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": result, "total": len(result)})
}

// GetStats returns container workload statistics.
// GET /api/v1/containers/stats
func (h *ContainerHandler) GetStats(c *gin.Context) {
	if !h.workloadTableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"total":        0,
			"by_cluster":   []interface{}{},
			"by_status":    []interface{}{},
			"risk_buckets": gin.H{},
			"total_vulns":  0,
		})
		return
	}
	ctx := c.Request.Context()

	// By cluster
	clusterRows, err := h.pool.Query(ctx,
		`SELECT cluster_name, COUNT(*) FROM container_workloads GROUP BY cluster_name ORDER BY COUNT(*) DESC`)
	if !ReadOK(c, err) {
		return
	}
	type clusterCount struct {
		ClusterName string `json:"cluster_name"`
		Count       int    `json:"count"`
	}
	var byClusters []clusterCount
	if clusterRows != nil {
		defer clusterRows.Close()
		for clusterRows.Next() {
			var cc clusterCount
			if err := clusterRows.Scan(&cc.ClusterName, &cc.Count); err == nil {
				byClusters = append(byClusters, cc)
			}
		}
		if err := clusterRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if byClusters == nil {
		byClusters = []clusterCount{}
	}

	// By status
	statusRows, err := h.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM container_workloads GROUP BY status`)
	if !ReadOK(c, err) {
		return
	}
	type statusCount struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	var byStatus []statusCount
	if statusRows != nil {
		defer statusRows.Close()
		for statusRows.Next() {
			var sc statusCount
			if err := statusRows.Scan(&sc.Status, &sc.Count); err == nil {
				byStatus = append(byStatus, sc)
			}
		}
		if err := statusRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if byStatus == nil {
		byStatus = []statusCount{}
	}

	// Risk buckets
	var low, medium, high, critical int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT
			  COUNT(*) FILTER (WHERE risk_score < 25),
			  COUNT(*) FILTER (WHERE risk_score >= 25 AND risk_score < 50),
			  COUNT(*) FILTER (WHERE risk_score >= 50 AND risk_score < 75),
			  COUNT(*) FILTER (WHERE risk_score >= 75)
			 FROM container_workloads`).Scan(&low, &medium, &high, &critical)) {
		return
	}

	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM container_workloads`).Scan(&total)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":      total,
		"by_cluster": byClusters,
		"by_status":  byStatus,
		"risk_buckets": gin.H{
			"low":      low,
			"medium":   medium,
			"high":     high,
			"critical": critical,
		},
	})
}

// ListClusters returns distinct cluster names with workload counts.
// GET /api/v1/containers/clusters
func (h *ContainerHandler) ListClusters(c *gin.Context) {
	if !h.workloadTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"clusters": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT cluster_name, COUNT(*) as workload_count,
		        COUNT(*) FILTER (WHERE status='running') as running_count
		 FROM container_workloads GROUP BY cluster_name ORDER BY cluster_name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "クラスター一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type cluster struct {
		ClusterName   string `json:"cluster_name"`
		WorkloadCount int    `json:"workload_count"`
		RunningCount  int    `json:"running_count"`
	}
	var result []cluster
	for rows.Next() {
		var cl cluster
		if err := rows.Scan(&cl.ClusterName, &cl.WorkloadCount, &cl.RunningCount); err == nil {
			result = append(result, cl)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []cluster{}
	}
	c.JSON(http.StatusOK, gin.H{"clusters": result})
}

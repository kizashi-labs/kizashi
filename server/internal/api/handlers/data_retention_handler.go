package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DataRetentionHandler exposes admin-editable retention policies with live
// record counts, purge preview and manual purge per data type.
type DataRetentionHandler struct{ pool *pgxpool.Pool }

func NewDataRetentionHandler(pool *pgxpool.Pool) *DataRetentionHandler {
	return &DataRetentionHandler{pool: pool}
}

// retentionSpec maps a policy type to its table, time column and an optional
// extra WHERE condition that keeps purges safe (e.g. only closed alerts).
type retentionSpec struct {
	table   string
	timeCol string
	extra   string // appended with AND if non-empty
}

var retentionSpecs = map[string]retentionSpec{
	"alerts":           {table: "alerts", timeCol: "updated_at", extra: "status IN ('resolved','false_positive','closed')"},
	"events":           {table: "events", timeCol: "time"},
	"audit_logs":       {table: "audit_logs", timeCol: "created_at"},
	"playbook_runs":    {table: "playbook_runs", timeCol: "ran_at"},
	"darkweb_findings": {table: "darkweb_findings", timeCol: "found_at"},
}

// relationSizeBytes returns the total on-disk size of a table. TimescaleDB
// hypertables (e.g. events) store data in chunk tables, so the plain
// pg_total_relation_size of the parent is near zero — try hypertable_size
// first and fall back for regular tables (or when timescaledb is absent).
func (h *DataRetentionHandler) relationSizeBytes(c *gin.Context, table string) int64 {
	ctx := c.Request.Context()
	var size int64
	if err := h.pool.QueryRow(ctx, `SELECT hypertable_size($1::regclass)`, table).Scan(&size); err == nil && size > 0 {
		return size
	}
	_ = h.pool.QueryRow(ctx, `SELECT COALESCE(pg_total_relation_size($1::regclass), 0)`, table).Scan(&size)
	return size
}

// purgeWhere builds the WHERE clause for records older than the cutoff.
func (sp retentionSpec) purgeWhere() string {
	w := fmt.Sprintf("%s < $1", sp.timeCol)
	if sp.extra != "" {
		w += " AND " + sp.extra
	}
	return w
}

// ListPolicies returns all retention policies with live counts and sizes.
// GET /api/v1/admin/data-retention
func (h *DataRetentionHandler) ListPolicies(c *gin.Context) {
	ctx := c.Request.Context()
	policies := []gin.H{}

	rows, err := h.pool.Query(ctx, `
		SELECT type, retention_days, auto_purge, purge_schedule, last_purge
		FROM data_retention_policies ORDER BY type`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type policyRow struct {
		typ           string
		retentionDays *int
		autoPurge     bool
		schedule      string
		lastPurge     *time.Time
	}
	var prs []policyRow
	for rows.Next() {
		var p policyRow
		if err := rows.Scan(&p.typ, &p.retentionDays, &p.autoPurge, &p.schedule, &p.lastPurge); err != nil {
			continue
		}
		prs = append(prs, p)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	rows.Close()

	for _, p := range prs {
		spec, ok := retentionSpecs[p.typ]
		if !ok {
			continue
		}
		var count int64
		if !ReadOK(c, h.pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, spec.table)).Scan(&count)) {
			return
		}
		sizeBytes := h.relationSizeBytes(c, spec.table)

		entry := gin.H{
			"type":           p.typ,
			"retention_days": p.retentionDays,
			"records_count":  count,
			"size_mb":        sizeBytes / (1024 * 1024),
			"auto_purge":     p.autoPurge,
			"purge_schedule": p.schedule,
			"last_purge":     nil,
		}
		if p.lastPurge != nil {
			entry["last_purge"] = p.lastPurge.UTC().Format(time.RFC3339)
		}
		policies = append(policies, entry)
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// UpdatePolicy updates one retention policy.
// PUT /api/v1/admin/data-retention/:type
func (h *DataRetentionHandler) UpdatePolicy(c *gin.Context) {
	typ := c.Param("type")
	if _, ok := retentionSpecs[typ]; !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "未知のデータ種別です"})
		return
	}
	var req struct {
		RetentionDays *int   `json:"retention_days"`
		AutoPurge     bool   `json:"auto_purge"`
		PurgeSchedule string `json:"purge_schedule"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	switch req.PurgeSchedule {
	case "daily", "weekly", "monthly":
	default:
		req.PurgeSchedule = "daily"
	}
	if req.RetentionDays != nil && *req.RetentionDays <= 0 {
		req.RetentionDays = nil // 0/negative = forever
	}
	ct, err := h.pool.Exec(c.Request.Context(), `
		UPDATE data_retention_policies
		SET retention_days=$2, auto_purge=$3, purge_schedule=$4, updated_at=NOW()
		WHERE type=$1`, typ, req.RetentionDays, req.AutoPurge, req.PurgeSchedule)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ポリシーを更新しました"})
}

// loadPolicyCutoff returns the cutoff time for a type, or an error when the
// policy is unknown or set to keep data forever.
func (h *DataRetentionHandler) loadPolicyCutoff(c *gin.Context, typ string) (retentionSpec, time.Time, bool) {
	spec, ok := retentionSpecs[typ]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "未知のデータ種別です"})
		return spec, time.Time{}, false
	}
	var days *int
	if err := h.pool.QueryRow(c.Request.Context(),
		`SELECT retention_days FROM data_retention_policies WHERE type=$1`, typ).Scan(&days); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return spec, time.Time{}, false
	}
	if days == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "保持期間が無期限のため削除対象がありません"})
		return spec, time.Time{}, false
	}
	return spec, time.Now().UTC().AddDate(0, 0, -*days), true
}

// PurgePreview returns how many records a purge would delete.
// POST /api/v1/admin/data-retention/purge-preview  {"type": "..."}
func (h *DataRetentionHandler) PurgePreview(c *gin.Context) {
	var req struct {
		Type string `json:"type" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type is required"})
		return
	}
	spec, cutoff, ok := h.loadPolicyCutoff(c, req.Type)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var count, total int64
	if err := h.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s`, spec.table, spec.purgeWhere()), cutoff).Scan(&count); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, spec.table)).Scan(&total)) {
		return
	}
	sizeBytes := h.relationSizeBytes(c, spec.table)

	sizeMB := int64(0)
	if total > 0 {
		sizeMB = sizeBytes * count / total / (1024 * 1024)
	}
	c.JSON(http.StatusOK, gin.H{"count": count, "size_mb": sizeMB})
}

// Purge deletes records older than the configured retention for the type.
// POST /api/v1/admin/data-retention/purge  {"type": "..."}
func (h *DataRetentionHandler) Purge(c *gin.Context) {
	var req struct {
		Type string `json:"type" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type is required"})
		return
	}
	spec, cutoff, ok := h.loadPolicyCutoff(c, req.Type)
	if !ok {
		return
	}
	ct, err := h.pool.Exec(c.Request.Context(),
		fmt.Sprintf(`DELETE FROM %s WHERE %s`, spec.table, spec.purgeWhere()), cutoff)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if _, err := h.pool.Exec(c.Request.Context(),
		`UPDATE data_retention_policies SET last_purge=NOW(), updated_at=NOW() WHERE type=$1`, req.Type); !WriteOK(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": ct.RowsAffected(), "type": req.Type})
}

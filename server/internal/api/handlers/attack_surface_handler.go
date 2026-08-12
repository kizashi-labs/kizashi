package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AttackSurfaceHandler manages attack surface assets and scans.
type AttackSurfaceHandler struct {
	pool *pgxpool.Pool
}

func NewAttackSurfaceHandler(pool *pgxpool.Pool) *AttackSurfaceHandler {
	return &AttackSurfaceHandler{pool: pool}
}

// ListAssets GET /assets
func (h *AttackSurfaceHandler) ListAssets(c *gin.Context) {
	ctx := c.Request.Context()
	assetType := c.Query("asset_type")
	isKnown := c.Query("is_known")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	query := `SELECT id, asset_type, value, COALESCE(parent_id::text,''), source,
		risk_score, is_known, is_monitored, tags, metadata, first_seen, last_seen, created_at
		FROM attack_surface_assets WHERE 1=1`
	args := []interface{}{}
	argN := 1

	if assetType != "" {
		query += " AND asset_type = $" + strconv.Itoa(argN)
		args = append(args, assetType)
		argN++
	}
	if isKnown == "true" {
		query += " AND is_known = true"
	} else if isKnown == "false" {
		query += " AND is_known = false"
	}

	query += " ORDER BY risk_score DESC, created_at DESC LIMIT $" + strconv.Itoa(argN) + " OFFSET $" + strconv.Itoa(argN+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Asset struct {
		ID          string      `json:"id"`
		AssetType   string      `json:"asset_type"`
		Value       string      `json:"value"`
		ParentID    string      `json:"parent_id,omitempty"`
		Source      string      `json:"source"`
		RiskScore   int         `json:"risk_score"`
		IsKnown     bool        `json:"is_known"`
		IsMonitored bool        `json:"is_monitored"`
		Tags        interface{} `json:"tags"`
		Metadata    interface{} `json:"metadata"`
		FirstSeen   time.Time   `json:"first_seen"`
		LastSeen    time.Time   `json:"last_seen"`
		CreatedAt   time.Time   `json:"created_at"`
	}

	assets := []Asset{}
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.AssetType, &a.Value, &a.ParentID, &a.Source,
			&a.RiskScore, &a.IsKnown, &a.IsMonitored, &a.Tags, &a.Metadata,
			&a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
			continue
		}
		assets = append(assets, a)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"assets": assets, "limit": limit, "offset": offset})
}

// CreateAsset POST /assets
func (h *AttackSurfaceHandler) CreateAsset(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		AssetType   string      `json:"asset_type" binding:"required"`
		Value       string      `json:"value" binding:"required"`
		ParentID    *string     `json:"parent_id"`
		Source      string      `json:"source"`
		RiskScore   int         `json:"risk_score"`
		IsKnown     bool        `json:"is_known"`
		IsMonitored *bool       `json:"is_monitored"`
		Tags        interface{} `json:"tags"`
		Metadata    interface{} `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Source == "" {
		req.Source = "manual"
	}
	isMonitored := true
	if req.IsMonitored != nil {
		isMonitored = *req.IsMonitored
	}
	if req.Tags == nil {
		req.Tags = []interface{}{}
	}
	if req.Metadata == nil {
		req.Metadata = map[string]interface{}{}
	}

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO attack_surface_assets
			(asset_type, value, parent_id, source, risk_score, is_known, is_monitored, tags, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		req.AssetType, req.Value, req.ParentID, req.Source, req.RiskScore,
		req.IsKnown, isMonitored, req.Tags, req.Metadata,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// UpdateAsset PUT /assets/:id
func (h *AttackSurfaceHandler) UpdateAsset(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")
	var req struct {
		IsKnown     *bool       `json:"is_known"`
		IsMonitored *bool       `json:"is_monitored"`
		Tags        interface{} `json:"tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `UPDATE attack_surface_assets SET last_seen = NOW()`
	args := []interface{}{}
	argN := 1

	if req.IsKnown != nil {
		query += ", is_known = $" + strconv.Itoa(argN)
		args = append(args, *req.IsKnown)
		argN++
	}
	if req.IsMonitored != nil {
		query += ", is_monitored = $" + strconv.Itoa(argN)
		args = append(args, *req.IsMonitored)
		argN++
	}
	if req.Tags != nil {
		query += ", tags = $" + strconv.Itoa(argN)
		args = append(args, req.Tags)
		argN++
	}
	query += " WHERE id = $" + strconv.Itoa(argN)
	args = append(args, id)

	tag, err := h.pool.Exec(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteAsset DELETE /assets/:id
func (h *AttackSurfaceHandler) DeleteAsset(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")
	tag, err := h.pool.Exec(ctx, `DELETE FROM attack_surface_assets WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

// GetStats GET /stats
func (h *AttackSurfaceHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	type TypeCount struct {
		AssetType string `json:"asset_type"`
		Count     int    `json:"count"`
	}
	type TopRisk struct {
		ID        string `json:"id"`
		AssetType string `json:"asset_type"`
		Value     string `json:"value"`
		RiskScore int    `json:"risk_score"`
	}

	countsByType := []TypeCount{}
	rows, err := h.pool.Query(ctx, `SELECT asset_type, COUNT(*) FROM attack_surface_assets GROUP BY asset_type ORDER BY COUNT(*) DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t TypeCount
			if rows.Scan(&t.AssetType, &t.Count) == nil {
				countsByType = append(countsByType, t)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("attack surface countsByType iteration failed", "error", err)
		}
	}

	topRisk := []TopRisk{}
	rows2, err := h.pool.Query(ctx, `SELECT id, asset_type, value, risk_score FROM attack_surface_assets ORDER BY risk_score DESC LIMIT 10`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var t TopRisk
			if rows2.Scan(&t.ID, &t.AssetType, &t.Value, &t.RiskScore) == nil {
				topRisk = append(topRisk, t)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("attack surface topRisk iteration failed", "error", err)
		}
	}

	var newAssets int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM attack_surface_assets WHERE first_seen >= NOW() - INTERVAL '7 days'`).Scan(&newAssets)

	var total int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM attack_surface_assets`).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"total":           total,
		"counts_by_type":  countsByType,
		"top_risk_assets": topRisk,
		"new_last_7_days": newAssets,
	})
}

// ListScans GET /scans
func (h *AttackSurfaceHandler) ListScans(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `SELECT id, scan_type, target, status, assets_found, new_assets,
		COALESCE(started_at::text,''), COALESCE(completed_at::text,''), created_at
		FROM attack_surface_scans ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Scan struct {
		ID          string    `json:"id"`
		ScanType    string    `json:"scan_type"`
		Target      string    `json:"target"`
		Status      string    `json:"status"`
		AssetsFound int       `json:"assets_found"`
		NewAssets   int       `json:"new_assets"`
		StartedAt   string    `json:"started_at"`
		CompletedAt string    `json:"completed_at"`
		CreatedAt   time.Time `json:"created_at"`
	}
	scans := []Scan{}
	for rows.Next() {
		var s Scan
		if rows.Scan(&s.ID, &s.ScanType, &s.Target, &s.Status, &s.AssetsFound, &s.NewAssets,
			&s.StartedAt, &s.CompletedAt, &s.CreatedAt) == nil {
			scans = append(scans, s)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

// StartScan POST /scans
func (h *AttackSurfaceHandler) StartScan(c *gin.Context) {
	ctx := c.Request.Context()
	var req struct {
		ScanType string `json:"scan_type" binding:"required"`
		Target   string `json:"target" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO attack_surface_scans (scan_type, target, status, started_at)
		VALUES ($1, $2, 'running', NOW()) RETURNING id`,
		req.ScanType, req.Target,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	_, _ = h.pool.Exec(ctx, `
		UPDATE attack_surface_scans
		SET status = 'completed', assets_found = 0, new_assets = 0, completed_at = NOW()
		WHERE id = $1`,
		id)

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "running"})
}

// GetScan GET /scans/:id
func (h *AttackSurfaceHandler) GetScan(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")

	type Scan struct {
		ID          string    `json:"id"`
		ScanType    string    `json:"scan_type"`
		Target      string    `json:"target"`
		Status      string    `json:"status"`
		AssetsFound int       `json:"assets_found"`
		NewAssets   int       `json:"new_assets"`
		StartedAt   string    `json:"started_at"`
		CompletedAt string    `json:"completed_at"`
		CreatedAt   time.Time `json:"created_at"`
	}
	var s Scan
	err := h.pool.QueryRow(ctx, `SELECT id, scan_type, target, status, assets_found, new_assets,
		COALESCE(started_at::text,''), COALESCE(completed_at::text,''), created_at
		FROM attack_surface_scans WHERE id = $1`, id).
		Scan(&s.ID, &s.ScanType, &s.Target, &s.Status, &s.AssetsFound, &s.NewAssets,
			&s.StartedAt, &s.CompletedAt, &s.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	c.JSON(http.StatusOK, s)
}

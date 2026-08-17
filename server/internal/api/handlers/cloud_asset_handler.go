package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CloudAssetHandler manages cloud asset inventory.
type CloudAssetHandler struct {
	pool *pgxpool.Pool
}

// NewCloudAssetHandler creates a new CloudAssetHandler.
func NewCloudAssetHandler(pool *pgxpool.Pool) *CloudAssetHandler {
	return &CloudAssetHandler{pool: pool}
}

type cloudAsset struct {
	ID         string      `json:"id"`
	Provider   string      `json:"provider"`
	AssetType  string      `json:"asset_type"`
	AssetID    string      `json:"asset_id"`
	Name       string      `json:"name"`
	Region     string      `json:"region"`
	AccountID  string      `json:"account_id"`
	Status     string      `json:"status"`
	Tags       interface{} `json:"tags"`
	Config     interface{} `json:"config"`
	RiskScore  int         `json:"risk_score"`
	LastSeenAt string      `json:"last_seen_at"`
	CreatedAt  string      `json:"created_at"`
	UpdatedAt  string      `json:"updated_at"`
}

const caCols = `id, provider, asset_type, asset_id, name, region, account_id, status,
	tags, config, risk_score, last_seen_at, created_at, updated_at`

func scanCloudAsset(row interface{ Scan(...any) error }) (*cloudAsset, error) {
	var a cloudAsset
	var lastSeenAt, createdAt, updatedAt time.Time
	var tagsRaw, configRaw []byte
	err := row.Scan(
		&a.ID, &a.Provider, &a.AssetType, &a.AssetID, &a.Name,
		&a.Region, &a.AccountID, &a.Status,
		&tagsRaw, &configRaw, &a.RiskScore,
		&lastSeenAt, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.LastSeenAt = lastSeenAt.Format(time.RFC3339)
	a.CreatedAt = createdAt.Format(time.RFC3339)
	a.UpdatedAt = updatedAt.Format(time.RFC3339)
	if tagsRaw != nil {
		_ = json.Unmarshal(tagsRaw, &a.Tags)
	}
	if a.Tags == nil {
		a.Tags = map[string]interface{}{}
	}
	if configRaw != nil {
		_ = json.Unmarshal(configRaw, &a.Config)
	}
	if a.Config == nil {
		a.Config = map[string]interface{}{}
	}
	return &a, nil
}

// List returns cloud assets with optional filters.
// GET /api/v1/cloud-assets
func (h *CloudAssetHandler) List(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "cloud_assets")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "total": 0})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	provider := c.Query("provider")
	assetType := c.Query("asset_type")
	region := c.Query("region")

	query := `SELECT ` + caCols + ` FROM cloud_assets WHERE 1=1`
	args := []interface{}{}
	n := 1

	if provider != "" {
		query += ` AND provider = $` + strconv.Itoa(n)
		args = append(args, provider)
		n++
	}
	if assetType != "" {
		query += ` AND asset_type = $` + strconv.Itoa(n)
		args = append(args, assetType)
		n++
	}
	if region != "" {
		query += ` AND region = $` + strconv.Itoa(n)
		args = append(args, region)
		n++
	}

	countQuery := `SELECT COUNT(*) FROM cloud_assets WHERE 1=1`
	if provider != "" {
		countQuery += ` AND provider = '` + strings.ReplaceAll(provider, "'", "''") + `'`
	}
	if assetType != "" {
		countQuery += ` AND asset_type = '` + strings.ReplaceAll(assetType, "'", "''") + `'`
	}
	if region != "" {
		countQuery += ` AND region = '` + strings.ReplaceAll(region, "'", "''") + `'`
	}

	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, countQuery).Scan(&total)) {
		return
	}

	query += ` ORDER BY risk_score DESC, created_at DESC LIMIT $` + strconv.Itoa(n) + ` OFFSET $` + strconv.Itoa(n+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list cloud assets"})
		return
	}
	defer rows.Close()

	assets := []*cloudAsset{}
	for rows.Next() {
		a, err := scanCloudAsset(rows)
		if err == nil {
			assets = append(assets, a)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list cloud assets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     assets,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// Get returns a single cloud asset by ID.
// GET /api/v1/cloud-assets/:id
func (h *CloudAssetHandler) Get(c *gin.Context) {
	id := c.Param("id")
	row := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+caCols+` FROM cloud_assets WHERE id = $1`, id,
	)
	a, err := scanCloudAsset(row)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cloud asset not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get cloud asset"})
		return
	}
	c.JSON(http.StatusOK, a)
}

// Upsert batch-upserts cloud assets from a sync payload.
// POST /api/v1/cloud-assets/sync
func (h *CloudAssetHandler) Upsert(c *gin.Context) {
	var req struct {
		Assets []struct {
			Provider  string                 `json:"provider"    binding:"required"`
			AssetType string                 `json:"asset_type"  binding:"required"`
			AssetID   string                 `json:"asset_id"    binding:"required"`
			Name      string                 `json:"name"`
			Region    string                 `json:"region"`
			AccountID string                 `json:"account_id"`
			Status    string                 `json:"status"`
			Tags      map[string]interface{} `json:"tags"`
			Config    map[string]interface{} `json:"config"`
			RiskScore int                    `json:"risk_score"`
		} `json:"assets"   binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	upserted := 0
	for _, a := range req.Assets {
		if a.Provider == "" || a.AssetID == "" {
			continue
		}
		if a.Status == "" {
			a.Status = "active"
		}
		tagsJSON, _ := json.Marshal(a.Tags)
		configJSON, _ := json.Marshal(a.Config)

		_, err := h.pool.Exec(ctx,
			`INSERT INTO cloud_assets
			  (provider, asset_type, asset_id, name, region, account_id, status, tags, config, risk_score, last_seen_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
			 ON CONFLICT (provider, asset_id) DO UPDATE SET
			   asset_type   = EXCLUDED.asset_type,
			   name         = EXCLUDED.name,
			   region       = EXCLUDED.region,
			   account_id   = EXCLUDED.account_id,
			   status       = EXCLUDED.status,
			   tags         = EXCLUDED.tags,
			   config       = EXCLUDED.config,
			   risk_score   = EXCLUDED.risk_score,
			   last_seen_at = NOW(),
			   updated_at   = NOW()`,
			a.Provider, a.AssetType, a.AssetID, a.Name, a.Region,
			a.AccountID, a.Status, tagsJSON, configJSON, a.RiskScore,
		)
		if err == nil {
			upserted++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Sync complete",
		"upserted": upserted,
		"total":    len(req.Assets),
	})
}

// Delete removes a cloud asset by ID.
// DELETE /api/v1/cloud-assets/:id
func (h *CloudAssetHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM cloud_assets WHERE id = $1`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete cloud asset"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud asset not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Cloud asset deleted"})
}

// GetStats returns aggregate statistics for cloud assets.
// GET /api/v1/cloud-assets/stats
func (h *CloudAssetHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "cloud_assets")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"providers": []interface{}{}, "asset_types": []interface{}{}, "risk_buckets": gin.H{}})
		return
	}

	type providerStat struct {
		Provider string `json:"provider"`
		Count    int    `json:"count"`
	}
	type typeStat struct {
		AssetType string `json:"asset_type"`
		Count     int    `json:"count"`
	}

	var providers []providerStat
	rows, err := h.pool.Query(ctx,
		`SELECT provider, COUNT(*) FROM cloud_assets GROUP BY provider ORDER BY COUNT(*) DESC`,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s providerStat
			if rows.Scan(&s.Provider, &s.Count) == nil {
				providers = append(providers, s)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var assetTypes []typeStat
	rows2, err := h.pool.Query(ctx,
		`SELECT asset_type, COUNT(*) FROM cloud_assets GROUP BY asset_type ORDER BY COUNT(*) DESC`,
	)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var s typeStat
			if rows2.Scan(&s.AssetType, &s.Count) == nil {
				assetTypes = append(assetTypes, s)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var lowCount, medCount, highCount int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cloud_assets WHERE risk_score < 30`).Scan(&lowCount)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cloud_assets WHERE risk_score >= 30 AND risk_score < 70`).Scan(&medCount)) {
		return
	}
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cloud_assets WHERE risk_score >= 70`).Scan(&highCount)) {
		return
	}

	if providers == nil {
		providers = []providerStat{}
	}
	if assetTypes == nil {
		assetTypes = []typeStat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"providers":   providers,
		"asset_types": assetTypes,
		"risk_buckets": gin.H{
			"low":    lowCount,
			"medium": medCount,
			"high":   highCount,
		},
	})
}

// UpdateRisk updates the risk score for a cloud asset.
// POST /api/v1/cloud-assets/:id/risk
func (h *CloudAssetHandler) UpdateRisk(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		RiskScore int    `json:"risk_score"`
		Reason    string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`UPDATE cloud_assets SET risk_score = $2, updated_at = NOW() WHERE id = $1`,
		id, req.RiskScore,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update risk score"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud asset not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         id,
		"risk_score": req.RiskScore,
		"reason":     req.Reason,
	})
}

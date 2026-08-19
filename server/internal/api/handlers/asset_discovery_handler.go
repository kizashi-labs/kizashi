package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AssetDiscoveryHandler manages network asset discovery endpoints.
type AssetDiscoveryHandler struct {
	pool *pgxpool.Pool
}

// NewAssetDiscoveryHandler creates a new AssetDiscoveryHandler.
func NewAssetDiscoveryHandler(pool *pgxpool.Pool) *AssetDiscoveryHandler {
	return &AssetDiscoveryHandler{pool: pool}
}

func (h *AssetDiscoveryHandler) tableExists(ctx context.Context, tableName string) bool {
	return tableIsThere(ctx, h.pool, tableName)
}

// ListAssets — GET /discovery/assets
func (h *AssetDiscoveryHandler) ListAssets(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovered_assets") {
		c.JSON(http.StatusOK, gin.H{"assets": []interface{}{}, "total": 0})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	query := `SELECT id, ip_address, mac_address, hostname, vendor, os_guess,
	                 open_ports, services, device_type, is_managed, agent_id,
	                 risk_score, first_seen_at, last_seen_at
	          FROM discovered_assets WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if v := c.Query("is_managed"); v != "" {
		managed, _ := strconv.ParseBool(v)
		query += fmt.Sprintf(" AND is_managed=$%d", argIdx)
		args = append(args, managed)
		argIdx++
	}
	if v := c.Query("device_type"); v != "" {
		query += fmt.Sprintf(" AND device_type=$%d", argIdx)
		args = append(args, v)
		argIdx++
	}
	if v := c.Query("risk_score_min"); v != "" {
		min, err := strconv.Atoi(v)
		if err == nil {
			query += fmt.Sprintf(" AND risk_score>=$%d", argIdx)
			args = append(args, min)
			argIdx++
		}
	}

	countQuery := "SELECT COUNT(*) FROM (" + query + ") sub"
	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, countQuery, args...).Scan(&total)) {
		return
	}

	query += fmt.Sprintf(" ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アセット一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type asset struct {
		ID          string  `json:"id"`
		IPAddress   string  `json:"ip_address"`
		MACAddress  string  `json:"mac_address"`
		Hostname    string  `json:"hostname"`
		Vendor      string  `json:"vendor"`
		OSGuess     string  `json:"os_guess"`
		OpenPorts   []byte  `json:"open_ports"`
		Services    []byte  `json:"services"`
		DeviceType  string  `json:"device_type"`
		IsManaged   bool    `json:"is_managed"`
		AgentID     *string `json:"agent_id"`
		RiskScore   int     `json:"risk_score"`
		FirstSeenAt string  `json:"first_seen_at"`
		LastSeenAt  string  `json:"last_seen_at"`
	}

	var result []asset
	for rows.Next() {
		var a asset
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&a.ID, &a.IPAddress, &a.MACAddress, &a.Hostname, &a.Vendor,
			&a.OSGuess, &a.OpenPorts, &a.Services, &a.DeviceType, &a.IsManaged,
			&a.AgentID, &a.RiskScore, &firstSeen, &lastSeen); err != nil {
			continue
		}
		a.FirstSeenAt = firstSeen.Format(time.RFC3339)
		a.LastSeenAt = lastSeen.Format(time.RFC3339)
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アセット一覧の取得に失敗しました"})
		return
	}
	if result == nil {
		result = []asset{}
	}
	c.JSON(http.StatusOK, gin.H{"assets": result, "total": total, "page": page})
}

// GetAsset — GET /discovery/assets/:id
func (h *AssetDiscoveryHandler) GetAsset(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovered_assets") {
		c.JSON(http.StatusNotFound, gin.H{"error": "アセットが見つかりません"})
		return
	}

	id := c.Param("id")
	row := h.pool.QueryRow(ctx,
		`SELECT id, ip_address, mac_address, hostname, vendor, os_guess,
		        open_ports, services, device_type, is_managed, agent_id,
		        risk_score, first_seen_at, last_seen_at
		 FROM discovered_assets WHERE id=$1`, id)

	var (
		assetID, ipAddr, mac, hostname, vendor, osGuess, deviceType string
		openPorts, services                                         []byte
		isManaged                                                   bool
		agentID                                                     *string
		riskScore                                                   int
		firstSeen, lastSeen                                         time.Time
	)
	if err := row.Scan(&assetID, &ipAddr, &mac, &hostname, &vendor, &osGuess,
		&openPorts, &services, &deviceType, &isManaged, &agentID,
		&riskScore, &firstSeen, &lastSeen); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アセットが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":            assetID,
		"ip_address":    ipAddr,
		"mac_address":   mac,
		"hostname":      hostname,
		"vendor":        vendor,
		"os_guess":      osGuess,
		"open_ports":    openPorts,
		"services":      services,
		"device_type":   deviceType,
		"is_managed":    isManaged,
		"agent_id":      agentID,
		"risk_score":    riskScore,
		"first_seen_at": firstSeen.Format(time.RFC3339),
		"last_seen_at":  lastSeen.Format(time.RFC3339),
	})
}

// StartScan — POST /discovery/scan
func (h *AssetDiscoveryHandler) StartScan(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovery_scans") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "スキャンテーブルが存在しません"})
		return
	}

	var body struct {
		Subnet   string `json:"subnet" binding:"required"`
		ScanType string `json:"scan_type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストボディが無効です"})
		return
	}
	if body.Subnet == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subnetは必須です"})
		return
	}
	if body.ScanType == "" {
		body.ScanType = "ping"
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var scanID string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO discovery_scans (subnet, scan_type, status, started_by)
		 VALUES ($1, $2, 'running', $3) RETURNING id`,
		body.Subnet, body.ScanType, userIDStr).Scan(&scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スキャンの開始に失敗しました"})
		return
	}

	// Background scan: upsert agents whose IPs match the subnet, then count results.
	pool := h.pool
	subnet := body.Subnet
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		newAssets := 0

		// Upsert agents in the subnet into discovered_assets (inet << cidr).
		agentsTableExists := tableIsThere(bgCtx, pool, "agents")

		if agentsTableExists && h.tableExists(bgCtx, "discovered_assets") {
			// agents の OS 列は `os_type` (migration 001)。`os` は存在せず、
			// このクエリは毎回失敗して既存エージェントを資産として拾えていなかった。
			rows, err := pool.Query(bgCtx,
				`SELECT hostname, os_type, ip_addresses[1]::text
				 FROM agents
				 WHERE ip_addresses[1] IS NOT NULL
				   AND ip_addresses[1]::inet << $1::cidr`,
				subnet)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var hostname, osName string
					var ip *string
					if scanErr := rows.Scan(&hostname, &osName, &ip); scanErr != nil || ip == nil {
						continue
					}
					deviceType := "workstation"
					if osName == "linux" || osName == "darwin" {
						deviceType = "server"
					}
					var id string
					err := pool.QueryRow(bgCtx,
						`INSERT INTO discovered_assets
						   (ip_address, hostname, os_guess, device_type, risk_score, last_seen_at)
						 VALUES ($1, $2, $3, $4, 0, NOW())
						 ON CONFLICT (ip_address) DO UPDATE SET
						   last_seen_at=NOW(), hostname=EXCLUDED.hostname
						 RETURNING id`,
						*ip, hostname, osName, deviceType,
					).Scan(&id)
					if err == nil {
						newAssets++
					}
				}
				if err := rows.Err(); err != nil {
					slog.Warn("row iteration error", "error", err)
				}
			}
		}

		// Count total assets seen in this subnet.
		var totalAssets int
		if h.tableExists(bgCtx, "discovered_assets") {
			if err := pool.QueryRow(bgCtx,
				`SELECT COUNT(*) FROM discovered_assets WHERE ip_address::inet << $1::cidr`,
				subnet).Scan(&totalAssets); err != nil {
				slog.Warn("asset_discovery: アセット数の取得に失敗しました", "error", err)
			}
		}

		// Use a fresh context for the final status update so it succeeds even if bgCtx timed out.
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer updateCancel()
		if _, err := pool.Exec(updateCtx,
			`UPDATE discovery_scans SET status='completed', assets_found=$1, new_assets=$2, completed_at=NOW() WHERE id=$3`,
			totalAssets, newAssets, scanID); err != nil {
			slog.Warn("asset discovery: スキャン結果の更新に失敗しました", "scan_id", scanID, "error", err)
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"scan_id": scanID, "status": "running"})
}

// GetScanStatus — GET /discovery/scans/:id
func (h *AssetDiscoveryHandler) GetScanStatus(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovery_scans") {
		c.JSON(http.StatusNotFound, gin.H{"error": "スキャンが見つかりません"})
		return
	}

	id := c.Param("id")
	row := h.pool.QueryRow(ctx,
		`SELECT id, subnet, scan_type, status, assets_found, new_assets,
		        started_by, started_at, completed_at
		 FROM discovery_scans WHERE id=$1`, id)

	var (
		scanID, subnet, scanType, status string
		assetsFound, newAssets           int
		startedBy                        *string
		startedAt                        time.Time
		completedAt                      *time.Time
	)
	if err := row.Scan(&scanID, &subnet, &scanType, &status, &assetsFound, &newAssets,
		&startedBy, &startedAt, &completedAt); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "スキャンが見つかりません"})
		return
	}

	resp := gin.H{
		"id":           scanID,
		"subnet":       subnet,
		"scan_type":    scanType,
		"status":       status,
		"assets_found": assetsFound,
		"new_assets":   newAssets,
		"started_by":   startedBy,
		"started_at":   startedAt.Format(time.RFC3339),
		"completed_at": nil,
	}
	if completedAt != nil {
		resp["completed_at"] = completedAt.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, resp)
}

// ListScans — GET /discovery/scans
func (h *AssetDiscoveryHandler) ListScans(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovery_scans") {
		c.JSON(http.StatusOK, gin.H{"scans": []interface{}{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, subnet, scan_type, status, assets_found, new_assets,
		        started_by, started_at, completed_at
		 FROM discovery_scans ORDER BY started_at DESC LIMIT 20`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スキャン一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type scan struct {
		ID          string  `json:"id"`
		Subnet      string  `json:"subnet"`
		ScanType    string  `json:"scan_type"`
		Status      string  `json:"status"`
		AssetsFound int     `json:"assets_found"`
		NewAssets   int     `json:"new_assets"`
		StartedBy   *string `json:"started_by"`
		StartedAt   string  `json:"started_at"`
		CompletedAt *string `json:"completed_at"`
	}

	var result []scan
	for rows.Next() {
		var s scan
		var startedAt time.Time
		var completedAt *time.Time
		if err := rows.Scan(&s.ID, &s.Subnet, &s.ScanType, &s.Status,
			&s.AssetsFound, &s.NewAssets, &s.StartedBy, &startedAt, &completedAt); err != nil {
			continue
		}
		s.StartedAt = startedAt.Format(time.RFC3339)
		if completedAt != nil {
			t := completedAt.Format(time.RFC3339)
			s.CompletedAt = &t
		}
		result = append(result, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スキャン一覧の取得に失敗しました"})
		return
	}
	if result == nil {
		result = []scan{}
	}
	c.JSON(http.StatusOK, gin.H{"scans": result, "total": len(result)})
}

// MarkManaged — POST /discovery/assets/:id/mark-managed
func (h *AssetDiscoveryHandler) MarkManaged(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovered_assets") {
		c.JSON(http.StatusNotFound, gin.H{"error": "アセットが見つかりません"})
		return
	}

	id := c.Param("id")
	var body struct {
		AgentID *string `json:"agent_id"`
	}
	_ = c.ShouldBindJSON(&body)

	_, err := h.pool.Exec(ctx,
		`UPDATE discovered_assets SET is_managed=true, agent_id=$1 WHERE id=$2`,
		body.AgentID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "マネージド設定に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "アセットをマネージドとしてマークしました"})
}

// GetStats — GET /discovery/stats
func (h *AssetDiscoveryHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	if !h.tableExists(ctx, "discovered_assets") {
		c.JSON(http.StatusOK, gin.H{
			"total":           0,
			"managed":         0,
			"unmanaged":       0,
			"managed_percent": 0,
			"by_device_type":  gin.H{},
		})
		return
	}

	var total, managed int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_managed) FROM discovered_assets`).
		Scan(&total, &managed)) {
		return
	}
	unmanaged := total - managed
	managedPct := 0.0
	if total > 0 {
		managedPct = float64(managed) / float64(total) * 100
	}

	rows, err := h.pool.Query(ctx,
		`SELECT device_type, COUNT(*) FROM discovered_assets GROUP BY device_type`)
	byType := gin.H{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dt string
			var cnt int
			if rows.Scan(&dt, &cnt) == nil {
				byType[dt] = cnt
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":           total,
		"managed":         managed,
		"unmanaged":       unmanaged,
		"managed_percent": managedPct,
		"by_device_type":  byType,
	})
}

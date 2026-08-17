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

// RansomwareHandler manages ransomware protection configuration and events.
type RansomwareHandler struct {
	pool *pgxpool.Pool
}

// NewRansomwareHandler creates a new RansomwareHandler.
func NewRansomwareHandler(pool *pgxpool.Pool) *RansomwareHandler {
	return &RansomwareHandler{pool: pool}
}

func (h *RansomwareHandler) checkConfigTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "ransomware_protection_config")
}

func (h *RansomwareHandler) checkEventsTable(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "ransomware_events")
}

type ransomwareConfig struct {
	ID                  string          `json:"id"`
	Enabled             bool            `json:"enabled"`
	ProtectedFolders    json.RawMessage `json:"protected_folders"`
	AllowedApps         json.RawMessage `json:"allowed_apps"`
	BackupEnabled       bool            `json:"backup_enabled"`
	BackupIntervalHours int             `json:"backup_interval_hours"`
	CanaryFilesEnabled  bool            `json:"canary_files_enabled"`
	CanaryFilePaths     json.RawMessage `json:"canary_file_paths"`
	EntropyDetection    bool            `json:"entropy_detection"`
	EntropyThreshold    float64         `json:"entropy_threshold"`
	UpdatedAt           string          `json:"updated_at"`
}

type ransomwareEvent struct {
	ID            string          `json:"id"`
	EndpointID    *string         `json:"endpoint_id"`
	Hostname      *string         `json:"hostname"`
	EventType     string          `json:"event_type"`
	ProcessName   *string         `json:"process_name"`
	ProcessPID    *int            `json:"process_pid"`
	AffectedFiles *int            `json:"affected_files"`
	Details       json.RawMessage `json:"details"`
	AutoIsolated  bool            `json:"auto_isolated"`
	CreatedAt     string          `json:"created_at"`
}

// GetConfig returns the ransomware protection config, creating a default if none exists.
// GET /api/v1/admin/ransomware/config
func (h *RansomwareHandler) GetConfig(c *gin.Context) {
	if !h.checkConfigTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"enabled":               true,
			"protected_folders":     []string{},
			"allowed_apps":          []string{},
			"backup_enabled":        true,
			"backup_interval_hours": 4,
			"canary_files_enabled":  true,
			"canary_file_paths":     []string{},
			"entropy_detection":     true,
			"entropy_threshold":     7.5,
		})
		return
	}
	ctx := c.Request.Context()

	var cfg ransomwareConfig
	var updatedAt time.Time
	var protectedFolders, allowedApps, canaryFilePaths []byte

	err := h.pool.QueryRow(ctx,
		`SELECT id, enabled, protected_folders, allowed_apps, backup_enabled,
		        backup_interval_hours, canary_files_enabled, canary_file_paths,
		        entropy_detection, entropy_threshold, updated_at
		 FROM ransomware_protection_config LIMIT 1`,
	).Scan(
		&cfg.ID, &cfg.Enabled, &protectedFolders, &allowedApps,
		&cfg.BackupEnabled, &cfg.BackupIntervalHours,
		&cfg.CanaryFilesEnabled, &canaryFilePaths,
		&cfg.EntropyDetection, &cfg.EntropyThreshold, &updatedAt,
	)
	if err != nil {
		// No config exists — create default
		err2 := h.pool.QueryRow(ctx,
			`INSERT INTO ransomware_protection_config DEFAULT VALUES RETURNING
			 id, enabled, protected_folders, allowed_apps, backup_enabled,
			 backup_interval_hours, canary_files_enabled, canary_file_paths,
			 entropy_detection, entropy_threshold, updated_at`,
		).Scan(
			&cfg.ID, &cfg.Enabled, &protectedFolders, &allowedApps,
			&cfg.BackupEnabled, &cfg.BackupIntervalHours,
			&cfg.CanaryFilesEnabled, &canaryFilePaths,
			&cfg.EntropyDetection, &cfg.EntropyThreshold, &updatedAt,
		)
		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get or create config"})
			return
		}
	}

	if len(protectedFolders) > 0 {
		cfg.ProtectedFolders = json.RawMessage(protectedFolders)
	} else {
		cfg.ProtectedFolders = json.RawMessage(`[]`)
	}
	if len(allowedApps) > 0 {
		cfg.AllowedApps = json.RawMessage(allowedApps)
	} else {
		cfg.AllowedApps = json.RawMessage(`[]`)
	}
	if len(canaryFilePaths) > 0 {
		cfg.CanaryFilePaths = json.RawMessage(canaryFilePaths)
	} else {
		cfg.CanaryFilePaths = json.RawMessage(`[]`)
	}
	cfg.UpdatedAt = updatedAt.Format(time.RFC3339)
	c.JSON(http.StatusOK, cfg)
}

// UpdateConfig updates all ransomware protection config fields.
// PUT /api/v1/admin/ransomware/config
func (h *RansomwareHandler) UpdateConfig(c *gin.Context) {
	if !h.checkConfigTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Enabled             *bool    `json:"enabled"`
		ProtectedFolders    []string `json:"protected_folders"`
		AllowedApps         []string `json:"allowed_apps"`
		BackupEnabled       *bool    `json:"backup_enabled"`
		BackupIntervalHours *int     `json:"backup_interval_hours"`
		CanaryFilesEnabled  *bool    `json:"canary_files_enabled"`
		CanaryFilePaths     []string `json:"canary_file_paths"`
		EntropyDetection    *bool    `json:"entropy_detection"`
		EntropyThreshold    *float64 `json:"entropy_threshold"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	pfJSON, _ := json.Marshal(body.ProtectedFolders)
	appsJSON, _ := json.Marshal(body.AllowedApps)
	canaryJSON, _ := json.Marshal(body.CanaryFilePaths)

	ctx := c.Request.Context()

	// Upsert: update if exists, insert if not
	_, err := h.pool.Exec(ctx,
		`INSERT INTO ransomware_protection_config
		 (enabled, protected_folders, allowed_apps, backup_enabled,
		  backup_interval_hours, canary_files_enabled, canary_file_paths,
		  entropy_detection, entropy_threshold, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
		 ON CONFLICT DO NOTHING`,
		body.Enabled, pfJSON, appsJSON, body.BackupEnabled,
		body.BackupIntervalHours, body.CanaryFilesEnabled, canaryJSON,
		body.EntropyDetection, body.EntropyThreshold,
	)
	if err != nil {
		// Fallback to UPDATE the first row
		_, err2 := h.pool.Exec(ctx,
			`UPDATE ransomware_protection_config SET
			 enabled=COALESCE($1, enabled),
			 protected_folders=$2,
			 allowed_apps=$3,
			 backup_enabled=COALESCE($4, backup_enabled),
			 backup_interval_hours=COALESCE($5, backup_interval_hours),
			 canary_files_enabled=COALESCE($6, canary_files_enabled),
			 canary_file_paths=$7,
			 entropy_detection=COALESCE($8, entropy_detection),
			 entropy_threshold=COALESCE($9, entropy_threshold),
			 updated_at=NOW()
			 WHERE id=(SELECT id FROM ransomware_protection_config LIMIT 1)`,
			body.Enabled, pfJSON, appsJSON, body.BackupEnabled,
			body.BackupIntervalHours, body.CanaryFilesEnabled, canaryJSON,
			body.EntropyDetection, body.EntropyThreshold,
		)
		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config"})
			return
		}
	} else {
		// Row may not have been inserted (conflict) — update existing
		if _, err := h.pool.Exec(ctx,
			`UPDATE ransomware_protection_config SET
				 enabled=COALESCE($1, enabled),
				 protected_folders=$2,
				 allowed_apps=$3,
				 backup_enabled=COALESCE($4, backup_enabled),
				 backup_interval_hours=COALESCE($5, backup_interval_hours),
				 canary_files_enabled=COALESCE($6, canary_files_enabled),
				 canary_file_paths=$7,
				 entropy_detection=COALESCE($8, entropy_detection),
				 entropy_threshold=COALESCE($9, entropy_threshold),
				 updated_at=NOW()
				 WHERE id=(SELECT id FROM ransomware_protection_config LIMIT 1)`,
			body.Enabled, pfJSON, appsJSON, body.BackupEnabled,
			body.BackupIntervalHours, body.CanaryFilesEnabled, canaryJSON,
			body.EntropyDetection, body.EntropyThreshold,
		); !WriteOK(c, err) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Config updated"})
}

// AddProtectedFolder appends a path to the protected_folders JSONB array.
// POST /api/v1/admin/ransomware/config/folders
func (h *RansomwareHandler) AddProtectedFolder(c *gin.Context) {
	if !h.checkConfigTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE ransomware_protection_config
		 SET protected_folders = protected_folders || $1::jsonb, updated_at=NOW()
		 WHERE id=(SELECT id FROM ransomware_protection_config LIMIT 1)`,
		`["`+body.Path+`"]`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add protected folder"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Protected folder added"})
}

// RemoveProtectedFolder removes a path from the protected_folders JSONB array.
// DELETE /api/v1/admin/ransomware/config/folders
func (h *RansomwareHandler) RemoveProtectedFolder(c *gin.Context) {
	if !h.checkConfigTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE ransomware_protection_config
		 SET protected_folders = (
		   SELECT jsonb_agg(elem)
		   FROM jsonb_array_elements_text(protected_folders) AS elem
		   WHERE elem <> $1
		 ), updated_at=NOW()
		 WHERE id=(SELECT id FROM ransomware_protection_config LIMIT 1)`,
		body.Path,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove protected folder"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Protected folder removed"})
}

// AddAllowedApp appends an app to the allowed_apps JSONB array.
// POST /api/v1/admin/ransomware/config/apps
func (h *RansomwareHandler) AddAllowedApp(c *gin.Context) {
	if !h.checkConfigTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		App string `json:"app" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.App == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app is required"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE ransomware_protection_config
		 SET allowed_apps = allowed_apps || $1::jsonb, updated_at=NOW()
		 WHERE id=(SELECT id FROM ransomware_protection_config LIMIT 1)`,
		`["`+body.App+`"]`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add allowed app"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Allowed app added"})
}

// RemoveAllowedApp removes an app from the allowed_apps JSONB array.
// DELETE /api/v1/admin/ransomware/config/apps
func (h *RansomwareHandler) RemoveAllowedApp(c *gin.Context) {
	if !h.checkConfigTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		App string `json:"app" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.App == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app is required"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE ransomware_protection_config
		 SET allowed_apps = (
		   SELECT jsonb_agg(elem)
		   FROM jsonb_array_elements_text(allowed_apps) AS elem
		   WHERE elem <> $1
		 ), updated_at=NOW()
		 WHERE id=(SELECT id FROM ransomware_protection_config LIMIT 1)`,
		body.App,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove allowed app"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Allowed app removed"})
}

// ListEvents returns paginated ransomware events.
// GET /api/v1/admin/ransomware/events
func (h *RansomwareHandler) ListEvents(c *gin.Context) {
	if !h.checkEventsTable(c) {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, endpoint_id, hostname, event_type, process_name, process_pid,
		        affected_files, details, auto_isolated, created_at
		 FROM ransomware_events ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list events"})
		return
	}
	defer rows.Close()

	var result []ransomwareEvent
	for rows.Next() {
		var ev ransomwareEvent
		var createdAt time.Time
		var details []byte
		if err := rows.Scan(
			&ev.ID, &ev.EndpointID, &ev.Hostname, &ev.EventType,
			&ev.ProcessName, &ev.ProcessPID, &ev.AffectedFiles,
			&details, &ev.AutoIsolated, &createdAt,
		); err != nil {
			continue
		}
		if len(details) > 0 {
			ev.Details = json.RawMessage(details)
		}
		ev.CreatedAt = createdAt.Format(time.RFC3339)
		result = append(result, ev)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list events"})
		return
	}
	if result == nil {
		result = []ransomwareEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": result, "total": len(result)})
}

// GetStats returns ransomware event counts by type and a last-7-days trend.
// GET /api/v1/admin/ransomware/stats
func (h *RansomwareHandler) GetStats(c *gin.Context) {
	if !h.checkEventsTable(c) {
		c.JSON(http.StatusOK, gin.H{
			"counts_by_type": gin.H{},
			"trend":          []interface{}{},
			"total_7d":       0,
		})
		return
	}
	ctx := c.Request.Context()

	// Counts by event_type
	rows, err := h.pool.Query(ctx,
		`SELECT event_type, COUNT(*) FROM ransomware_events
		 WHERE created_at >= NOW() - INTERVAL '7 days'
		 GROUP BY event_type ORDER BY event_type`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stats"})
		return
	}
	defer rows.Close()

	countsByType := map[string]int{}
	total7d := 0
	for rows.Next() {
		var evType string
		var cnt int
		if err := rows.Scan(&evType, &cnt); err != nil {
			continue
		}
		countsByType[evType] = cnt
		total7d += cnt
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stats"})
		return
	}
	rows.Close()

	// Daily trend for last 7 days
	trendRows, err := h.pool.Query(ctx,
		`SELECT DATE(created_at) AS day, COUNT(*) AS cnt
		 FROM ransomware_events
		 WHERE created_at >= NOW() - INTERVAL '7 days'
		 GROUP BY day ORDER BY day`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"counts_by_type": countsByType,
			"trend":          []interface{}{},
			"total_7d":       total7d,
		})
		return
	}
	defer trendRows.Close()

	type trendPoint struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	var trend []trendPoint
	for trendRows.Next() {
		var tp trendPoint
		var day time.Time
		if err := trendRows.Scan(&day, &tp.Count); err != nil {
			continue
		}
		tp.Day = day.Format("2006-01-02")
		trend = append(trend, tp)
	}
	if err := trendRows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if trend == nil {
		trend = []trendPoint{}
	}

	c.JSON(http.StatusOK, gin.H{
		"counts_by_type": countsByType,
		"trend":          trend,
		"total_7d":       total7d,
	})
}

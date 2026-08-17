package handlers

import (
	"context"
	"encoding/json"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PlatformUpgradeHandler serves /api/v1/admin/platform/* endpoints.
//
// Version lifecycle:
//  1. At startup RecordStartup() inserts the current (version, build_date) into
//     platform_versions if it is not already present. This gives real upgrade history
//     that grows automatically with each deployment.
//  2. Available upgrade packages live in platform_upgrade_packages and are managed
//     by admins (or CI/CD pipelines) via POST /api/v1/admin/platform/upgrades.
//  3. Scheduled upgrades live in platform_upgrade_schedule.
type PlatformUpgradeHandler struct {
	pool         *pgxpool.Pool
	version      string // injected via -ldflags "-X main.Version=..."
	buildDate    string // injected via -ldflags "-X main.BuildDate=..."
	commit       string // injected via -ldflags "-X main.Commit=..."
	natsVer      string // NATS server version string (from nc.ConnectedServerVersion())
	agentVersion string // bundled agent version from AGENT_LATEST_VERSION env var
}

func NewPlatformUpgradeHandler(pool *pgxpool.Pool, version, buildDate, commit, natsVer, agentVersion string) *PlatformUpgradeHandler {
	if version == "" {
		version = "dev"
	}
	if buildDate == "" {
		buildDate = time.Now().UTC().Format("2006-01-02")
	}
	if natsVer == "" {
		natsVer = "—"
	}
	return &PlatformUpgradeHandler{
		pool:         pool,
		version:      version,
		buildDate:    buildDate,
		commit:       commit,
		natsVer:      natsVer,
		agentVersion: agentVersion,
	}
}

// RecordStartup inserts the current version into platform_versions (idempotent: once per version).
// Call this as a goroutine after the DB is ready.
func (h *PlatformUpgradeHandler) RecordStartup(ctx context.Context) {
	if h.pool == nil {
		return
	}
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Ensure the table exists before trying to insert (migrations may not have run yet).
	tableExists := tableIsThere(ctx2, h.pool, "platform_versions")
	if !tableExists {
		slog.Warn("platform_versions テーブルが存在しません — マイグレーションをまだ実行していない可能性があります")
		return
	}

	// Only insert if this exact version string hasn't been recorded before.
	var count int
	_ = h.pool.QueryRow(ctx2,
		`SELECT COUNT(*) FROM platform_versions WHERE version = $1`, h.version,
	).Scan(&count)
	if count > 0 {
		slog.Info("プラットフォームバージョン: 既にDBに記録済み", "version", h.version)
		return
	}

	_, err := h.pool.Exec(ctx2, `
		INSERT INTO platform_versions (version, build_date, deployed_by, status, notes)
		VALUES ($1, $2, 'system', 'active', '起動時に自動記録')
	`, h.version, h.buildDate)
	if err != nil {
		metrics.BackgroundFailed("platform_version_record", err, "プラットフォームバージョンの記録に失敗しました", "version", h.version)
		return
	}
	slog.Info("プラットフォームバージョンをDBに記録しました", "version", h.version, "build_date", h.buildDate)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// pgShortVersion extracts "15.4" from "PostgreSQL 15.4 on x86_64-...".
func pgShortVersion(full string) string {
	parts := strings.Fields(full)
	if len(parts) >= 2 {
		return parts[1]
	}
	return full
}

// latestAgentVersion returns the agent version to display.
// Priority: (1) bundled agent binary version from env var,
//
//	(2) latest version reported by a connected agent,
//	(3) "未設定" when neither is available.
func (h *PlatformUpgradeHandler) latestAgentVersion(ctx context.Context) string {
	// 1. Use bundled agent version from AGENT_LATEST_VERSION env var
	if h.agentVersion != "" {
		return h.agentVersion
	}
	// 2. Fallback: query the agents table for the most recent reported version
	var ver string
	_ = h.pool.QueryRow(ctx, `
		SELECT agent_version FROM agents
		WHERE agent_version IS NOT NULL AND agent_version != ''
		ORDER BY LENGTH(agent_version) DESC, agent_version DESC
		LIMIT 1
	`).Scan(&ver)
	if ver != "" {
		return ver
	}
	// 3. Nothing available yet
	return "未設定"
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// GetVersion handles GET /api/v1/admin/platform/version
// Returns real version info: app version from ldflags, PostgreSQL version from DB,
// NATS version from connection, agent version from agents table.
func (h *PlatformUpgradeHandler) GetVersion(c *gin.Context) {
	ctx := c.Request.Context()

	// PostgreSQL version (real query)
	var pgFull string
	pgStatus := "healthy"
	if err := h.pool.Ping(ctx); err != nil {
		pgStatus = "degraded"
	} else {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT version()`).Scan(&pgFull)) {
			return
		}
	}
	pgVer := pgShortVersion(pgFull)
	if pgVer == "" {
		pgVer = "—"
	}

	// Go runtime version
	goVer := strings.TrimPrefix(runtime.Version(), "go")

	components := []gin.H{
		{"name": "API Server", "version": h.version, "status": "healthy"},
		{"name": "Frontend", "version": h.version, "status": "healthy"},
		{"name": "PostgreSQL", "version": pgVer, "status": pgStatus},
		{"name": "NATS", "version": h.natsVer, "status": "healthy"},
		{"name": "EDR Agent", "version": h.latestAgentVersion(ctx), "status": "healthy"},
		{"name": "Go Runtime", "version": goVer, "status": "healthy"},
	}

	c.JSON(http.StatusOK, gin.H{
		"version":    h.version,
		"build_date": h.buildDate,
		"commit":     h.commit,
		"components": components,
	})
}

// GetUpgrades handles GET /api/v1/admin/platform/upgrades
// Returns packages from platform_upgrade_packages table.
func (h *PlatformUpgradeHandler) GetUpgrades(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, version, release_date, type, changelog_summary, changelog_details, size_mb
		FROM platform_upgrade_packages
		ORDER BY created_at DESC
	`)
	if err != nil {
		ReadFailure(c, err, []interface{}{})
		return
	}
	defer rows.Close()

	type pkg struct {
		ID               string          `json:"id"`
		Version          string          `json:"version"`
		ReleaseDate      string          `json:"release_date"`
		Type             string          `json:"type"`
		ChangelogSummary string          `json:"changelog_summary"`
		ChangelogDetails json.RawMessage `json:"changelog_details"`
		SizeMB           int             `json:"size_mb"`
	}

	var list []pkg
	for rows.Next() {
		var p pkg
		var rd *time.Time
		if rows.Scan(&p.ID, &p.Version, &rd, &p.Type, &p.ChangelogSummary, &p.ChangelogDetails, &p.SizeMB) != nil {
			continue
		}
		if rd != nil {
			p.ReleaseDate = rd.Format("2006-01-02")
		}
		if p.ChangelogDetails == nil {
			p.ChangelogDetails = json.RawMessage(`[]`)
		}
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("GetUpgrades: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	if list == nil {
		list = []pkg{}
	}
	c.JSON(http.StatusOK, list)
}

// CreateUpgradePackage handles POST /api/v1/admin/platform/upgrades
// Allows admins (or CI/CD) to register a new upgrade package.
func (h *PlatformUpgradeHandler) CreateUpgradePackage(c *gin.Context) {
	var body struct {
		Version          string   `json:"version"            binding:"required"`
		ReleaseDate      string   `json:"release_date"`
		Type             string   `json:"type"`
		ChangelogSummary string   `json:"changelog_summary"`
		ChangelogDetails []string `json:"changelog_details"`
		SizeMB           int      `json:"size_mb"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "version は必須です"})
		return
	}
	if body.Type == "" {
		body.Type = "patch"
	}
	if body.ChangelogDetails == nil {
		body.ChangelogDetails = []string{}
	}
	detailsJSON, _ := json.Marshal(body.ChangelogDetails)

	var rd interface{}
	if body.ReleaseDate != "" {
		t, err := time.Parse("2006-01-02", body.ReleaseDate)
		if err == nil {
			rd = t
		}
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO platform_upgrade_packages
		  (version, release_date, type, changelog_summary, changelog_details, size_mb)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (version) DO UPDATE
		  SET changelog_summary = EXCLUDED.changelog_summary,
		      changelog_details = EXCLUDED.changelog_details,
		      type               = EXCLUDED.type,
		      size_mb            = EXCLUDED.size_mb
		RETURNING id::text
	`, body.Version, rd, body.Type, body.ChangelogSummary, detailsJSON, body.SizeMB).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アップグレードパッケージの登録に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "version": body.Version})
}

// GetSchedule handles GET /api/v1/admin/platform/upgrades/schedule
func (h *PlatformUpgradeHandler) GetSchedule(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, version, scheduled_at, status,
		       maintenance_window, rollback_available, notes
		FROM (
		  SELECT id, version, scheduled_at, status,
		         maintenance_window,
		         auto_rollback AS rollback_available,
		         notes
		  FROM platform_upgrade_schedule
		) t
		ORDER BY scheduled_at DESC
	`)
	if err != nil {
		ReadFailure(c, err, []interface{}{})
		return
	}
	defer rows.Close()

	type sched struct {
		ID                string `json:"id"`
		Version           string `json:"version"`
		ScheduledAt       string `json:"scheduled_at"`
		Status            string `json:"status"`
		MaintenanceWindow int    `json:"maintenance_window"`
		RollbackAvailable bool   `json:"rollback_available"`
		Notes             string `json:"notes"`
	}

	var list []sched
	for rows.Next() {
		var s sched
		var at time.Time
		if rows.Scan(&s.ID, &s.Version, &at, &s.Status, &s.MaintenanceWindow, &s.RollbackAvailable, &s.Notes) != nil {
			continue
		}
		s.ScheduledAt = at.Format(time.RFC3339)
		list = append(list, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("GetSchedule: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	if list == nil {
		list = []sched{}
	}
	c.JSON(http.StatusOK, list)
}

// CreateSchedule handles POST /api/v1/admin/platform/upgrades/schedule
func (h *PlatformUpgradeHandler) CreateSchedule(c *gin.Context) {
	var body struct {
		Version           string `json:"version"            binding:"required"`
		ScheduledAt       string `json:"scheduled_at"       binding:"required"`
		MaintenanceWindow int    `json:"maintenance_window"`
		NotifyUsers       bool   `json:"notify_users"`
		AutoRollback      bool   `json:"auto_rollback"`
		Notes             string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "version と scheduled_at は必須です"})
		return
	}
	if body.MaintenanceWindow <= 0 {
		body.MaintenanceWindow = 60
	}

	scheduledAt, err := time.Parse("2006-01-02 15:04", body.ScheduledAt)
	if err != nil {
		// also accept RFC3339
		scheduledAt, err = time.Parse(time.RFC3339, body.ScheduledAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "scheduled_at のフォーマットが不正です (YYYY-MM-DD HH:MM)"})
			return
		}
	}

	ctx := c.Request.Context()
	var id string
	err = h.pool.QueryRow(ctx, `
		INSERT INTO platform_upgrade_schedule
		  (version, scheduled_at, maintenance_window, notify_users, auto_rollback, notes)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id::text
	`, body.Version, scheduledAt, body.MaintenanceWindow, body.NotifyUsers, body.AutoRollback, body.Notes).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "スケジュールの登録に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "スケジュール登録完了"})
}

// GetHistory handles GET /api/v1/admin/platform/upgrade-history
// Returns deployment history from platform_versions (auto-populated on startup).
func (h *PlatformUpgradeHandler) GetHistory(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, version, COALESCE(build_date,''), deployed_at,
		       deployed_by, status, COALESCE(notes,''), duration_min
		FROM platform_versions
		ORDER BY deployed_at DESC
		LIMIT 50
	`)
	if err != nil {
		ReadFailure(c, err, []interface{}{})
		return
	}
	defer rows.Close()

	type hist struct {
		ID          string `json:"id"`
		Version     string `json:"version"`
		BuildDate   string `json:"build_date"`
		StartedAt   string `json:"started_at"`
		CompletedAt string `json:"completed_at"`
		DeployedBy  string `json:"deployed_by"`
		Status      string `json:"status"`
		Notes       string `json:"notes"`
		DurationMin int    `json:"duration_min"`
	}

	var list []hist
	for rows.Next() {
		var hh hist
		var at time.Time
		if rows.Scan(&hh.ID, &hh.Version, &hh.BuildDate, &at, &hh.DeployedBy, &hh.Status, &hh.Notes, &hh.DurationMin) != nil {
			continue
		}
		hh.StartedAt = at.Format(time.RFC3339)
		hh.CompletedAt = at.Format(time.RFC3339)
		list = append(list, hh)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("GetHistory: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	if list == nil {
		list = []hist{}
	}
	c.JSON(http.StatusOK, list)
}

// GetAgentVersions handles GET /api/v1/admin/platform/agent-versions
// Returns real agent version distribution from the agents table.
func (h *PlatformUpgradeHandler) GetAgentVersions(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT
			COALESCE(NULLIF(agent_version,''), 'unknown') AS version,
			COUNT(*) AS cnt,
			ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 1) AS pct
		FROM agents
		GROUP BY agent_version
		ORDER BY cnt DESC
		LIMIT 20
	`)
	if err != nil {
		ReadFailure(c, err, []interface{}{})
		return
	}
	defer rows.Close()

	type dist struct {
		Version string  `json:"version"`
		Count   int     `json:"count"`
		Pct     float64 `json:"pct"`
	}
	var list []dist
	for rows.Next() {
		var d dist
		if rows.Scan(&d.Version, &d.Count, &d.Pct) != nil {
			continue
		}
		list = append(list, d)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("GetAgentVersions: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	if list == nil {
		list = []dist{}
	}
	c.JSON(http.StatusOK, list)
}

package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TIPIntegrationHandler manages Threat Intelligence Platform integrations.
// GET  /api/v1/admin/tip-integrations
// POST /api/v1/admin/tip-integrations/:id/sync
// GET  /api/v1/admin/tip-integrations/history
type TIPIntegrationHandler struct {
	pool *pgxpool.Pool
}

func NewTIPIntegrationHandler(pool *pgxpool.Pool) *TIPIntegrationHandler {
	return &TIPIntegrationHandler{pool: pool}
}

func (h *TIPIntegrationHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "tip_platforms")
}

type tipPlatform struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	PlatformKey   string          `json:"platform_key"`
	Status        string          `json:"status"`
	LastSync      *string         `json:"last_sync"`
	ObjectsSynced int             `json:"objects_synced"`
	SyncDirection string          `json:"sync_direction"`
	Enabled       bool            `json:"enabled"`
	URL           string          `json:"url"`
	APIKey        string          `json:"api_key"`
	VerifySSL     bool            `json:"verify_ssl"`
	SyncInterval  int             `json:"sync_interval"`
	ObjectTypes   json.RawMessage `json:"object_types"`
	MinConfidence int             `json:"min_confidence"`
	TLPLevel      string          `json:"tlp_level"`
	FieldMappings json.RawMessage `json:"field_mappings"`
	Stats         json.RawMessage `json:"stats"`
}

type tipSyncJob struct {
	ID              string  `json:"id"`
	PlatformID      *string `json:"platform_id"`
	PlatformName    string  `json:"platform_name"`
	Direction       string  `json:"direction"`
	StartedAt       string  `json:"started_at"`
	DurationSeconds int     `json:"duration_seconds"`
	ObjectsIn       int     `json:"objects_in"`
	ObjectsOut      int     `json:"objects_out"`
	Status          string  `json:"status"`
	Errors          int     `json:"errors"`
	ErrorMessage    *string `json:"error_message,omitempty"`
}

// List returns all TIP platform configurations.
// GET /api/v1/admin/tip-integrations
func (h *TIPIntegrationHandler) List(c *gin.Context) {
	ctx := c.Request.Context()

	var platforms []tipPlatform

	if h.tableExists(c) {
		rows, err := h.pool.Query(ctx, `
			SELECT id::text, name, platform_key, status, last_sync,
			       objects_synced, sync_direction, enabled, url, api_key,
			       verify_ssl, sync_interval,
			       COALESCE(object_types,'["IOCs"]'::jsonb),
			       min_confidence, tlp_level,
			       COALESCE(field_mappings,'[]'::jsonb),
			       COALESCE(stats,'{}'::jsonb)
			FROM tip_platforms ORDER BY name
		`)
		if err != nil {
			slog.Warn("tip: tip_platforms の読み出しに失敗", "error", err)
		} else {
			defer rows.Close()
			for rows.Next() {
				var p tipPlatform
				var lastSync *time.Time
				if rows.Scan(
					&p.ID, &p.Name, &p.PlatformKey, &p.Status, &lastSync,
					&p.ObjectsSynced, &p.SyncDirection, &p.Enabled, &p.URL, &p.APIKey,
					&p.VerifySSL, &p.SyncInterval, &p.ObjectTypes,
					&p.MinConfidence, &p.TLPLevel, &p.FieldMappings, &p.Stats,
				) != nil {
					continue
				}
				if lastSync != nil {
					s := lastSync.Format(time.RFC3339)
					p.LastSync = &s
				}
				platforms = append(platforms, p)
			}
			if err := rows.Err(); err != nil {
				slog.Warn("tip: tip_platforms の走査に失敗", "error", err)
			}
		}
	}

	// フォールバックの条件は「テーブルが無いこと」ではなく「行が取れなかった
	// こと」です。tip_platforms はマイグレーション 219 が作りますが行を入れる
	// コードがどこにも無く、tableExists は常に true を返すため、実データのある
	// threat_feeds への分岐に一度も到達していませんでした。
	if len(platforms) == 0 {
		fromFeeds, err := h.platformsFromThreatFeeds(ctx)
		if err != nil {
			slog.Error("tip: 脅威フィードから連携基盤を導出できませんでした", "error", err)
			ReadFailure(c, err, gin.H{"platforms": []tipPlatform{}})
			return
		}
		platforms = fromFeeds
	}

	if platforms == nil {
		platforms = []tipPlatform{}
	}
	c.JSON(http.StatusOK, platforms)
}

// platformsFromThreatFeeds presents the configured threat feeds as TIP
// platforms, for deployments that have feeds but no tip_platforms rows.
//
// 読めなかったときは error を返します。以前は nil を返していて、画面には
// 「連携している脅威インテリ基盤: 0件」と出ます。設定してあるフィードが
// 消えたように見えるので、入れ直そうとした人が既にある設定を作り直します。
func (h *TIPIntegrationHandler) platformsFromThreatFeeds(ctx context.Context) ([]tipPlatform, error) {
	var exists bool
	if err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='threat_feeds')`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		// この配備で脅威フィードを使っていないだけ。0件は事実です。
		return nil, nil
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id::text, name, COALESCE(url,''), last_sync_at, COALESCE(last_entry_count, last_count, 0), enabled
		 FROM threat_feeds ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var platforms []tipPlatform
	emptyArr, _ := json.Marshal([]string{"IOCs"})
	emptyMap, _ := json.Marshal(map[string]int{})
	emptyFields, _ := json.Marshal([]interface{}{})
	for rows.Next() {
		var p tipPlatform
		var lastFetched *time.Time
		if rows.Scan(&p.ID, &p.Name, &p.URL, &lastFetched, &p.ObjectsSynced, &p.Enabled) != nil {
			continue
		}
		p.PlatformKey = p.Name
		p.Status = "disconnected"
		if p.Enabled && lastFetched != nil {
			p.Status = "connected"
			s := lastFetched.Format(time.RFC3339)
			p.LastSync = &s
		}
		p.SyncDirection = "inbound"
		p.SyncInterval = 3600
		p.MinConfidence = 50
		p.TLPLevel = "amber"
		p.VerifySSL = true
		p.ObjectTypes = emptyArr
		p.Stats = emptyMap
		p.FieldMappings = emptyFields
		platforms = append(platforms, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return platforms, nil
}

// Sync triggers a manual sync for a TIP platform.
// POST /api/v1/admin/tip-integrations/:id/sync
func (h *TIPIntegrationHandler) Sync(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	if h.tableExists(c) && isValidUUID(id) {
		if _, err := h.pool.Exec(ctx,
			`UPDATE tip_platforms SET last_sync=NOW(), status='connected' WHERE id=$1`, id); !WriteOK(c, err) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Sync triggered", "platform_id": id})
}

// ListHistory returns recent sync job history.
// GET /api/v1/admin/tip-integrations/history
func (h *TIPIntegrationHandler) ListHistory(c *gin.Context) {
	ctx := c.Request.Context()

	exists := tableIsThere(ctx, h.pool, "tip_sync_jobs")
	if !exists {
		c.JSON(http.StatusOK, []tipSyncJob{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, platform_id::text, platform_name, direction,
		       started_at, duration_seconds, objects_in, objects_out,
		       status, errors, error_message
		FROM tip_sync_jobs ORDER BY started_at DESC LIMIT 100
	`)
	if err != nil {
		ReadFailure(c, err, []tipSyncJob{})
		return
	}
	defer rows.Close()

	var jobs []tipSyncJob
	for rows.Next() {
		var j tipSyncJob
		var startedAt time.Time
		if rows.Scan(
			&j.ID, &j.PlatformID, &j.PlatformName, &j.Direction,
			&startedAt, &j.DurationSeconds, &j.ObjectsIn, &j.ObjectsOut,
			&j.Status, &j.Errors, &j.ErrorMessage,
		) != nil {
			continue
		}
		j.StartedAt = startedAt.Format(time.RFC3339)
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListHistory: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, []tipSyncJob{})
		return
	}
	if jobs == nil {
		jobs = []tipSyncJob{}
	}
	c.JSON(http.StatusOK, jobs)
}

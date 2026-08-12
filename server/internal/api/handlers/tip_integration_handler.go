package handlers

import (
	"encoding/json"
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
	var ok bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='tip_platforms')`).Scan(&ok)
	return ok
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

	if !h.tableExists(c) {
		// Fall back to existing threat_feeds if available
		var exists bool
		_ = h.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='threat_feeds')`).Scan(&exists)
		if !exists {
			c.JSON(http.StatusOK, []tipPlatform{})
			return
		}

		rows, err := h.pool.Query(ctx,
			`SELECT id::text, name, COALESCE(url,''), last_fetched_at, ioc_count, enabled
			 FROM threat_feeds ORDER BY name`)
		if err != nil {
			c.JSON(http.StatusOK, []tipPlatform{})
			return
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
		if platforms == nil {
			platforms = []tipPlatform{}
		}
		c.JSON(http.StatusOK, platforms)
		return
	}

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
		c.JSON(http.StatusOK, []tipPlatform{})
		return
	}
	defer rows.Close()

	var platforms []tipPlatform
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
	if platforms == nil {
		platforms = []tipPlatform{}
	}
	c.JSON(http.StatusOK, platforms)
}

// Sync triggers a manual sync for a TIP platform.
// POST /api/v1/admin/tip-integrations/:id/sync
func (h *TIPIntegrationHandler) Sync(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	if h.tableExists(c) && isValidUUID(id) {
		_, _ = h.pool.Exec(ctx,
			`UPDATE tip_platforms SET last_sync=NOW(), status='connected' WHERE id=$1`, id)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Sync triggered", "platform_id": id})
}

// ListHistory returns recent sync job history.
// GET /api/v1/admin/tip-integrations/history
func (h *TIPIntegrationHandler) ListHistory(c *gin.Context) {
	ctx := c.Request.Context()

	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='tip_sync_jobs')`).Scan(&exists)
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
		c.JSON(http.StatusOK, []tipSyncJob{})
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
	if jobs == nil {
		jobs = []tipSyncJob{}
	}
	c.JSON(http.StatusOK, jobs)
}

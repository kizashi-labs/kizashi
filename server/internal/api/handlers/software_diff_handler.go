package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

// SoftwareDiffHandler provides endpoints to view and compute software inventory diffs.
type SoftwareDiffHandler struct {
	pool  *pgxpool.Pool
	store *store.SoftwareDiffStore
}

// NewSoftwareDiffHandler creates a SoftwareDiffHandler.
func NewSoftwareDiffHandler(pool *pgxpool.Pool) *SoftwareDiffHandler {
	return &SoftwareDiffHandler{
		pool:  pool,
		store: store.NewSoftwareDiffStore(pool),
	}
}

func (h *SoftwareDiffHandler) tableExists(c *gin.Context, tableName string) bool {
	var exists bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
		tableName,
	).Scan(&exists)
	return exists
}

// GetDiffs handles GET /endpoints/:id/software/diffs
func (h *SoftwareDiffHandler) GetDiffs(c *gin.Context) {
	agentID := c.Param("id")
	limit := 30
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "30")); err == nil && l > 0 {
		limit = l
	}

	diffs, err := h.store.GetDiffs(c.Request.Context(), agentID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ソフトウェア差分の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"diffs": diffs, "count": len(diffs)})
}

// GetLatestDiff handles GET /endpoints/:id/software/diffs/latest
func (h *SoftwareDiffHandler) GetLatestDiff(c *gin.Context) {
	agentID := c.Param("id")

	diff, err := h.store.GetLatestDiff(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "差分が見つかりません"})
		return
	}
	if diff == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "差分が見つかりません"})
		return
	}
	c.JSON(http.StatusOK, diff)
}

// ComputeDiff handles POST /endpoints/:id/software/diffs/compute
// Reads current software from agent_software, computes diff against previous day snapshot,
// and inserts into software_inventory_diffs.
func (h *SoftwareDiffHandler) ComputeDiff(c *gin.Context) {
	agentID := c.Param("id")
	ctx := c.Request.Context()

	if !h.tableExists(c, "software_inventory_diffs") {
		c.JSON(http.StatusOK, gin.H{"message": "テーブルが存在しません", "added_count": 0, "removed_count": 0})
		return
	}

	// Fetch current software from agent_software
	var currentSoftware []map[string]interface{}
	if h.tableExists(c, "agent_software") {
		if rows, err := h.pool.Query(ctx,
			`SELECT COALESCE(name,''), COALESCE(version,'') FROM agent_software WHERE agent_id = $1`,
			agentID,
		); err == nil {
			for rows.Next() {
				var name, version string
				if scanErr := rows.Scan(&name, &version); scanErr == nil {
					currentSoftware = append(currentSoftware, map[string]interface{}{
						"name":    name,
						"version": version,
					})
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
			rows.Close()
		}
	}

	// Fetch previous day's software from agent_software_history
	var prevSoftware []map[string]interface{}
	if h.tableExists(c, "agent_software_history") {
		if rows, err := h.pool.Query(ctx,
			`SELECT COALESCE(name,''), COALESCE(version,'') FROM agent_software_history
			 WHERE agent_id = $1 AND snapshot_date = CURRENT_DATE - 1`,
			agentID,
		); err == nil {
			for rows.Next() {
				var name, version string
				if scanErr := rows.Scan(&name, &version); scanErr == nil {
					prevSoftware = append(prevSoftware, map[string]interface{}{
						"name":    name,
						"version": version,
					})
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
			rows.Close()
		}
	}

	// Build sets for comparison
	currentSet := make(map[string]bool)
	for _, sw := range currentSoftware {
		key := sw["name"].(string) + "@" + sw["version"].(string)
		currentSet[key] = true
	}
	prevSet := make(map[string]bool)
	for _, sw := range prevSoftware {
		key := sw["name"].(string) + "@" + sw["version"].(string)
		prevSet[key] = true
	}

	// Compute added (in current but not in prev)
	var added []map[string]interface{}
	for _, sw := range currentSoftware {
		key := sw["name"].(string) + "@" + sw["version"].(string)
		if !prevSet[key] {
			added = append(added, sw)
		}
	}

	// Compute removed (in prev but not in current)
	var removed []map[string]interface{}
	for _, sw := range prevSoftware {
		key := sw["name"].(string) + "@" + sw["version"].(string)
		if !currentSet[key] {
			removed = append(removed, sw)
		}
	}

	if added == nil {
		added = []map[string]interface{}{}
	}
	if removed == nil {
		removed = []map[string]interface{}{}
	}

	addedJSON, _ := json.Marshal(added)
	removedJSON, _ := json.Marshal(removed)

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO software_inventory_diffs
		  (agent_id, diff_date, added, removed, added_count, removed_count, created_at)
		VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6)
		RETURNING id`,
		agentID, addedJSON, removedJSON,
		len(added), len(removed), time.Now(),
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "差分の保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":            id,
		"agent_id":      agentID,
		"added_count":   len(added),
		"removed_count": len(removed),
		"added":         added,
		"removed":       removed,
	})
}

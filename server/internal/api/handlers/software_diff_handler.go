package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
//
// It compares the agent's current inventory against the most recent snapshot
// taken before today, and stores the result as that day's diff.
//
// It used to read agent_software and agent_software_history. No migration
// creates either table, and both reads sat behind a tableExists guard, so both
// sides of the comparison were empty on every call and the endpoint answered
// 200 with added_count 0 and removed_count 0 — then persisted that as the day's
// finding. A feature that reports unauthorised software installs could only
// ever report that none had happened. The inventory the agent actually reports
// lands in endpoint_software.
func (h *SoftwareDiffHandler) ComputeDiff(c *gin.Context) {
	agentID := c.Param("id")
	ctx := c.Request.Context()

	if _, err := uuid.Parse(agentID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "エージェントIDの形式が不正です"})
		return
	}

	current, err := h.currentInventory(ctx, agentID)
	if err != nil {
		slog.Warn("現在のソフトウェア一覧の取得に失敗しました", "agent_id", agentID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ソフトウェア一覧の取得に失敗しました"})
		return
	}

	previous, hasPrevious, err := h.store.PreviousSnapshot(ctx, agentID)
	if err != nil {
		slog.Warn("前回スナップショットの取得に失敗しました", "agent_id", agentID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "前回スナップショットの取得に失敗しました"})
		return
	}
	if !hasPrevious {
		// Nothing to compare against yet. Reporting "0 added, 0 removed" here
		// would be indistinguishable from a day on which nothing was installed,
		// which is the exact confusion this endpoint used to produce every time.
		c.JSON(http.StatusOK, gin.H{
			"agent_id":      agentID,
			"baseline":      true,
			"message":       "比較対象の過去スナップショットがまだありません（本日分をベースラインとして記録済み）",
			"added_count":   0,
			"removed_count": 0,
			"added":         []store.SoftwareItem{},
			"removed":       []store.SoftwareItem{},
		})
		return
	}

	added, removed := store.DiffSoftware(previous, current)
	if added == nil {
		added = []store.SoftwareItem{}
	}
	if removed == nil {
		removed = []store.SoftwareItem{}
	}

	id, err := h.store.UpsertDiff(ctx, agentID, added, removed)
	if err != nil {
		slog.Warn("差分の保存に失敗しました", "agent_id", agentID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "差分の保存に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":            id,
		"agent_id":      agentID,
		"baseline":      false,
		"added_count":   len(added),
		"removed_count": len(removed),
		"added":         added,
		"removed":       removed,
	})
}

// currentInventory reads what the agent most recently reported.
func (h *SoftwareDiffHandler) currentInventory(ctx context.Context, agentID string) ([]store.SoftwareItem, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT name, COALESCE(version,'') FROM endpoint_software WHERE agent_id = $1::uuid`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.SoftwareItem
	for rows.Next() {
		var item store.SoftwareItem
		if err := rows.Scan(&item.Name, &item.Version); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

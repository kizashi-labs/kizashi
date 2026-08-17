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

// TimelineHandler handles global security timeline requests.
type TimelineHandler struct {
	pool *pgxpool.Pool
}

// NewTimelineHandler creates a new TimelineHandler.
func NewTimelineHandler(pool *pgxpool.Pool) *TimelineHandler {
	return &TimelineHandler{pool: pool}
}

// TimelineEvent represents a single event in the global timeline.
type TimelineEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	Severity  int       `json:"severity"`
	AgentID   string    `json:"agent_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Link      string    `json:"link"`
}

func (h *TimelineHandler) timelineTableExists(ctx context.Context, table string) bool {
	return tableIsThere(ctx, h.pool, table)
}

// GetTimeline handles GET /api/v1/timeline
func (h *TimelineHandler) GetTimeline(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	fromStr := c.Query("from")
	toStr := c.Query("to")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	ctx := c.Request.Context()

	hasAlerts := h.timelineTableExists(ctx, "alerts")
	hasAudit := h.timelineTableExists(ctx, "audit_logs")

	events := []TimelineEvent{}

	if !hasAlerts && !hasAudit {
		c.JSON(http.StatusOK, gin.H{
			"events": events,
			"total":  0,
			"limit":  limit,
			"offset": offset,
		})
		return
	}

	// Build time filter clauses
	timeFilters := []string{}
	args := []interface{}{}
	argIdx := 1

	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			timeFilters = append(timeFilters, fmt.Sprintf("ts >= $%d", argIdx))
			args = append(args, t)
			argIdx++
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			timeFilters = append(timeFilters, fmt.Sprintf("ts <= $%d", argIdx))
			args = append(args, t)
			argIdx++
		}
	}

	whereClause := ""
	if len(timeFilters) > 0 {
		whereClause = "WHERE "
		for i, f := range timeFilters {
			if i > 0 {
				whereClause += " AND "
			}
			whereClause += f
		}
	}

	// Build UNION parts
	var unionParts []string

	if hasAlerts {
		unionParts = append(unionParts, `
			SELECT id::text AS eid, 'alert' AS etype, COALESCE(title,'') AS etitle,
			       '' AS edetail, COALESCE(severity,0)::int AS eseverity,
			       COALESCE(agent_id::text,'') AS eagent_id, created_at AS ts
			FROM alerts`)
	}
	if hasAudit {
		// audit_logs に resource 列は無い。006 が作るのは resource_id（解決済みの
		// :id パラメータ）で、resource を持つのは別テーブルの audit_events。
		// この UNION 全体がエラーになるため、監査行だけでなく**アラート行も含めた
		// タイムライン全体**が空になっていた。
		unionParts = append(unionParts, `
			SELECT id::text AS eid, 'audit' AS etype,
			       COALESCE(action,'') || CASE WHEN resource_id IS NOT NULL THEN ' ' || resource_id ELSE '' END AS etitle,
			       '' AS edetail, 0 AS eseverity, '' AS eagent_id, created_at AS ts
			FROM audit_logs`)
	}

	if len(unionParts) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"events": events,
			"total":  0,
			"limit":  limit,
			"offset": offset,
		})
		return
	}

	unionQuery := ""
	for i, part := range unionParts {
		if i > 0 {
			unionQuery += "\nUNION ALL\n"
		}
		unionQuery += part
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM (%s) AS combined %s`, unionQuery, whereClause)
	dataQuery := fmt.Sprintf(`
		SELECT eid, etype, etitle, edetail, eseverity, eagent_id, ts
		FROM (%s) AS combined
		%s
		ORDER BY ts DESC
		LIMIT $%d OFFSET $%d
	`, unionQuery, whereClause, argIdx, argIdx+1)

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	dataArgs := make([]interface{}, len(args)+2)
	copy(dataArgs, args)
	dataArgs[len(args)] = limit
	dataArgs[len(args)+1] = offset

	var total int
	if err := h.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		// total = 0 のまま返すと、件数表示と実際に返した行数が食い違います。
		// 「全部で0件」と書かれた下に行が並ぶので、読む側は行のほうを信じます。
		slog.Error("timeline: 総件数を取得できませんでした", "error", err)
		ReadFailure(c, err, gin.H{"events": []any{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx, dataQuery, dataArgs...)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"events": events,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ev TimelineEvent
		var ts time.Time
		if err := rows.Scan(&ev.ID, &ev.Type, &ev.Title, &ev.Detail, &ev.Severity, &ev.AgentID, &ts); err != nil {
			continue
		}
		ev.Timestamp = ts
		switch ev.Type {
		case "alert":
			ev.Link = fmt.Sprintf("/alerts/%s", ev.ID)
		case "audit":
			ev.Link = fmt.Sprintf("/audit/%s", ev.ID)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

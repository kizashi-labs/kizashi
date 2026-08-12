package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SOCQueueHandler provides the 1-person-SOC work queue endpoint.
type SOCQueueHandler struct {
	Pool *pgxpool.Pool
}

func NewSOCQueueHandler(pool *pgxpool.Pool) *SOCQueueHandler {
	return &SOCQueueHandler{Pool: pool}
}

// WorkQueueItem represents a single action item for the SOC analyst.
type WorkQueueItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // alert | incident
	Title     string `json:"title"`
	Severity  int    `json:"severity"` // 1-10
	Status    string `json:"status"`
	Hostname  string `json:"hostname,omitempty"`
	Priority  string `json:"priority"` // urgent | today | week
	Link      string `json:"link"`
	CreatedAt string `json:"created_at"`
	AgeHours  int    `json:"age_hours"`
}

// WorkQueue は GET /api/v1/soc/work-queue
// 未対応のアラート・インシデントを重要度と経過時間で分類して返す。
//
// 分類ルール:
//
//	urgent : severity >= 7 かつ status=open かつ 作成から 24 時間以内
//	         OR severity >= 9 (Critical) なら期間問わず
//	today  : severity >= 5 OR urgent 条件を超過 (24h+)
//	week   : それ以外の open/investigating アイテム
func (h *SOCQueueHandler) WorkQueue(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"urgent": []WorkQueueItem{}, "today": []WorkQueueItem{}, "week": []WorkQueueItem{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	now := time.Now()

	var urgent, today, week []WorkQueueItem

	// ── アラート (open のみ) ──────────────────────────────────────
	// alerts に agent_hostname 列は無い。ホスト名は agents から JOIN で引く。
	alertRows, err := h.Pool.Query(ctx, `
		SELECT al.id::text, COALESCE(al.title,'不明なアラート'), al.severity,
		       al.status, COALESCE(ag.hostname,''), al.created_at
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		WHERE al.status NOT IN ('resolved','false_positive','closed')
		ORDER BY al.severity DESC, al.created_at ASC
		LIMIT 200`)
	if err != nil {
		slog.Warn("soc_queue: alerts query failed", "error", err)
	}
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var item WorkQueueItem
			var createdAt time.Time
			if err := alertRows.Scan(&item.ID, &item.Title, &item.Severity,
				&item.Status, &item.Hostname, &createdAt); err != nil {
				continue
			}
			item.Type = "alert"
			item.Link = fmt.Sprintf("/alerts/%s", item.ID)
			item.CreatedAt = createdAt.Format(time.RFC3339)
			item.AgeHours = int(now.Sub(createdAt).Hours())
			item.Priority = classify(item.Severity, item.AgeHours)
			switch item.Priority {
			case "urgent":
				urgent = append(urgent, item)
			case "today":
				today = append(today, item)
			default:
				week = append(week, item)
			}
		}
	}

	// ── インシデント (open/investigating/contained) ────────────────
	incRows, err := h.Pool.Query(ctx, `
		SELECT id::text, COALESCE(title,'不明なインシデント'), severity,
		       status, created_at
		FROM incidents
		WHERE status NOT IN ('resolved','closed')
		ORDER BY severity DESC, created_at ASC
		LIMIT 100`)
	if err == nil {
		defer incRows.Close()
		for incRows.Next() {
			var item WorkQueueItem
			var createdAt time.Time
			if err := incRows.Scan(&item.ID, &item.Title, &item.Severity,
				&item.Status, &createdAt); err != nil {
				continue
			}
			item.Type = "incident"
			item.Link = fmt.Sprintf("/incidents/%s", item.ID)
			item.CreatedAt = createdAt.Format(time.RFC3339)
			item.AgeHours = int(now.Sub(createdAt).Hours())
			item.Priority = classify(item.Severity, item.AgeHours)
			switch item.Priority {
			case "urgent":
				urgent = append(urgent, item)
			case "today":
				today = append(today, item)
			default:
				week = append(week, item)
			}
		}
	}

	if urgent == nil {
		urgent = []WorkQueueItem{}
	}
	if today == nil {
		today = []WorkQueueItem{}
	}
	if week == nil {
		week = []WorkQueueItem{}
	}

	c.JSON(http.StatusOK, gin.H{
		"urgent":       urgent,
		"today":        today,
		"week":         week,
		"total":        len(urgent) + len(today) + len(week),
		"generated_at": now.Format(time.RFC3339),
	})
}

func classify(severity, ageHours int) string {
	if severity >= 9 {
		return "urgent"
	} // Critical は常に緊急
	if severity >= 7 && ageHours < 24 {
		return "urgent"
	}
	if severity >= 5 || (severity >= 7 && ageHours >= 24) {
		return "today"
	}
	return "week"
}

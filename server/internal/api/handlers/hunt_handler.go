package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HuntHandler manages saved threat hunts.
type HuntHandler struct {
	Store *store.HuntStore
	Pool  *pgxpool.Pool
}

// NewHuntHandler creates a new HuntHandler.
func NewHuntHandler(s *store.HuntStore) *HuntHandler {
	return &HuntHandler{Store: s}
}

// ListSavedHunts returns all saved hunts.
// GET /api/v1/threat-hunting/saved
func (h *HuntHandler) ListSavedHunts(c *gin.Context) {
	hunts, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存済みハントの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": hunts})
}

// CreateSavedHunt saves a new hunt query.
// POST /api/v1/threat-hunting/saved
func (h *HuntHandler) CreateSavedHunt(c *gin.Context) {
	var req struct {
		Name        string          `json:"name" binding:"required"`
		Description string          `json:"description"`
		Params      json.RawMessage `json:"params"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameは必須です"})
		return
	}

	createdBy := "analyst"
	if userVal, ok := c.Get("user"); ok {
		if m, ok := userVal.(map[string]interface{}); ok {
			if email, ok := m["email"].(string); ok && email != "" {
				createdBy = email
			}
		}
	}

	hunt, err := h.Store.Create(c.Request.Context(), &store.SavedHunt{
		Name:        req.Name,
		Description: req.Description,
		Params:      req.Params,
		CreatedBy:   createdBy,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ハントの保存に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, hunt)
}

// DeleteSavedHunt removes a saved hunt.
// DELETE /api/v1/threat-hunting/saved/:id
func (h *HuntHandler) DeleteSavedHunt(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ハントの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// RecordRun increments run_count and updates last_run for a saved hunt.
// POST /api/v1/threat-hunting/saved/:id/run
func (h *HuntHandler) RecordRun(c *gin.Context) {
	id := c.Param("id")
	h.Store.RecordRun(c.Request.Context(), id)
	c.JSON(http.StatusOK, gin.H{"message": "recorded"})
}

// Search executes a threat hunt query against the events table.
// GET /api/v1/threat-hunting/search?q=...&event_type=...&hostname=...&process_name=...&username=...&start=...&end=...
func (h *HuntHandler) Search(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "DBプールが未設定です"})
		return
	}

	q := c.Query("q")
	eventType := c.Query("event_type")
	hostname := c.Query("hostname")
	processName := c.Query("process_name")
	username := c.Query("username")
	startStr := c.Query("start")
	endStr := c.Query("end")
	limitStr := c.DefaultQuery("limit", "200")

	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	// Build WHERE conditions
	var conditions []string
	var args []interface{}
	i := 1

	if eventType != "" {
		conditions = append(conditions, fmt.Sprintf("e.event_type = $%d", i))
		args = append(args, eventType)
		i++
	}
	if hostname != "" {
		conditions = append(conditions, fmt.Sprintf("a.hostname ILIKE $%d", i))
		args = append(args, "%"+hostname+"%")
		i++
	}
	if processName != "" {
		conditions = append(conditions, fmt.Sprintf("e.raw_data->>'image' ILIKE $%d OR e.raw_data->>'cmdline' ILIKE $%d", i, i))
		args = append(args, "%"+processName+"%")
		i++
	}
	if username != "" {
		conditions = append(conditions, fmt.Sprintf("e.raw_data->>'username' ILIKE $%d", i))
		args = append(args, "%"+username+"%")
		i++
	}
	if q != "" {
		conditions = append(conditions, fmt.Sprintf("e.raw_data::text ILIKE $%d", i))
		args = append(args, "%"+q+"%")
		i++
	}
	if startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			conditions = append(conditions, fmt.Sprintf("e.time >= $%d", i))
			args = append(args, t)
			i++
		}
	}
	if endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			conditions = append(conditions, fmt.Sprintf("e.time <= $%d", i))
			args = append(args, t)
			i++
		}
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + conditions[0]
		for _, cond := range conditions[1:] {
			where += " AND " + cond
		}
	}

	ctx := c.Request.Context()

	countQuery := `SELECT COUNT(*) FROM events e LEFT JOIN agents a ON a.id = e.agent_id ` + where
	var total int
	_ = h.Pool.QueryRow(ctx, countQuery, args...).Scan(&total)

	dataQuery := `
		SELECT e.event_id, e.event_type, COALESCE(a.hostname, e.agent_id::text) AS hostname,
		       e.severity, e.raw_data, e.time
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		` + where + `
		ORDER BY e.time DESC
		LIMIT $` + fmt.Sprintf("%d", i)
	args = append(args, limit)

	rows, err := h.Pool.Query(ctx, dataQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type EventRecord struct {
		ID          string                 `json:"id"`
		EventType   string                 `json:"event_type"`
		Hostname    string                 `json:"hostname"`
		ProcessName string                 `json:"process_name,omitempty"`
		Username    string                 `json:"username,omitempty"`
		Severity    int                    `json:"severity,omitempty"`
		Timestamp   time.Time              `json:"timestamp"`
		Details     map[string]interface{} `json:"details,omitempty"`
	}

	var records []EventRecord
	for rows.Next() {
		var rec EventRecord
		var rawData []byte
		if err := rows.Scan(&rec.ID, &rec.EventType, &rec.Hostname, &rec.Severity, &rawData, &rec.Timestamp); err != nil {
			continue
		}
		if len(rawData) > 0 {
			_ = json.Unmarshal(rawData, &rec.Details)
			if rec.Details != nil {
				if v, ok := rec.Details["image"].(string); ok {
					rec.ProcessName = v
				} else if v, ok := rec.Details["cmdline"].(string); ok {
					rec.ProcessName = v
				}
				if v, ok := rec.Details["username"].(string); ok {
					rec.Username = v
				}
			}
		}
		records = append(records, rec)
	}
	if rows.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "行の読み取りに失敗しました"})
		return
	}
	if records == nil {
		records = []EventRecord{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  records,
		"total": total,
	})
}

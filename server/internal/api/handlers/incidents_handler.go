package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/soar"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IncidentHandler provides incident management endpoints.
type IncidentHandler struct {
	Store *store.IncidentStore
	Pool  *pgxpool.Pool
}

func NewIncidentHandler(s *store.IncidentStore) *IncidentHandler {
	return &IncidentHandler{Store: s, Pool: s.Pool()}
}

var validIncidentStatuses = map[string]bool{
	"open": true, "investigating": true, "contained": true, "resolved": true, "closed": true,
}

// isValidIncidentStatus reports whether s is an accepted incident status value.
func isValidIncidentStatus(s string) bool {
	return validIncidentStatuses[s]
}

// clampIncidentSeverity returns the input if in [1,10], otherwise 7 (default).
func clampIncidentSeverity(v int) int {
	if v >= 1 && v <= 10 {
		return v
	}
	return 7
}

// defaultIncidentStatus returns "open" when s is empty.
func defaultIncidentStatus(s string) string {
	if s == "" {
		return "open"
	}
	return s
}

// List returns paginated incidents.
// GET /api/v1/incidents?status=open&page=1&per_page=20
func (h *IncidentHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	page, perPage, offset := clampPageParams(page, perPage, 20, 200)

	status := c.Query("status")
	incidents, total, err := h.Store.List(
		c.Request.Context(),
		status,
		perPage, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "インシデント一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":     incidents,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Get returns a single incident with its linked alerts.
// GET /api/v1/incidents/:id
func (h *IncidentHandler) Get(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	inc, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "インシデントが見つかりません"})
		return
	}
	alerts, err := h.Store.ListAlerts(c.Request.Context(), id)
	if err != nil {
		// インシデントを構成しているのはアラートです。取得できないまま
		// 200 を返すと、詳細画面は「アラート0件のインシデント」になります。
		ReadFailure(c, err, gin.H{"incident": inc, "alerts": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"incident": inc, "alerts": alerts})
}

// Create adds a new incident.
// POST /api/v1/incidents
func (h *IncidentHandler) Create(c *gin.Context) {
	var req struct {
		Title       string `json:"title"       binding:"required"`
		Description string `json:"description"`
		Severity    int    `json:"severity"`
		Status      string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title は必須です"})
		return
	}
	req.Severity = clampIncidentSeverity(req.Severity)
	req.Status = defaultIncidentStatus(req.Status)

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	inc := &store.Incident{
		Title:       req.Title,
		Description: req.Description,
		Severity:    req.Severity,
		Status:      req.Status,
		CreatedBy:   &uid,
	}
	id, err := h.Store.Insert(c.Request.Context(), inc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "インシデントの作成に失敗しました"})
		return
	}

	// Best-effort SOAR auto-ticket creation: run in background so it never blocks the response.
	if h.Pool != nil {
		incTitle := req.Title
		incDesc := req.Description
		incSeverity := req.Severity
		incID := id
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Query for active SOAR configs with auto_create enabled.
			rows, err := h.Pool.Query(ctx, `
				SELECT id, name, type, config
				FROM soar_configs
				WHERE auto_create = true AND enabled = true`)
			if err != nil {
				slog.Warn("SOAR auto-ticket: soar_configs クエリに失敗しました", "error", err)
				return
			}
			defer rows.Close()

			type soarRow struct {
				ID     string
				Name   string
				Type   string
				Config json.RawMessage
			}

			var configs []soarRow
			for rows.Next() {
				var r soarRow
				if scanErr := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Config); scanErr != nil {
					slog.Warn("SOAR auto-ticket: 行のスキャンに失敗しました", "error", scanErr)
					continue
				}
				configs = append(configs, r)
			}
			if err := rows.Err(); err != nil {
				slog.Warn("SOAR auto-ticket: soar_configs クエリに失敗しました", "error", err)
				return
			}
			rows.Close()

			for _, sc := range configs {
				var configMap map[string]interface{}
				if err := json.Unmarshal(sc.Config, &configMap); err != nil {
					slog.Warn("SOAR auto-ticket: config のパースに失敗しました", "name", sc.Name, "error", err)
					continue
				}

				client, err := soar.NewClient(sc.Type, configMap)
				if err != nil {
					slog.Warn("SOAR auto-ticket: クライアントの作成に失敗しました", "name", sc.Name, "error", err)
					continue
				}

				ticketReq := soar.TicketRequest{
					Title:       "[EDR] " + incTitle,
					Description: incDesc,
					Priority:    severityToPriority(incSeverity),
					Labels:      []string{"edr", "security"},
					IncidentID:  incID,
				}

				resp, err := client.CreateTicket(ctx, ticketReq)
				if err != nil {
					slog.Warn("SOAR auto-ticket: CreateTicket に失敗しました", "name", sc.Name, "error", err)
					continue
				}

				_, err = h.Pool.Exec(ctx, `
					UPDATE incidents
					SET external_ticket_id  = $2,
					    external_ticket_url = $3,
					    external_system     = $4,
					    updated_at          = NOW()
					WHERE id = $1`,
					incID, resp.TicketID, resp.TicketURL, resp.System,
				)
				if err != nil {
					slog.Warn("SOAR auto-ticket: インシデントのチケット情報更新に失敗しました", "incident_id", incID, "error", err)
				} else {
					slog.Info("SOAR auto-ticket: チケットを作成しました", "ticket_id", resp.TicketID, "system", resp.System, "incident_id", incID)
				}
			}
		}()
	}

	c.JSON(http.StatusCreated, gin.H{"message": "インシデントを作成しました", "id": id})
}

// Update modifies an incident.
// PUT /api/v1/incidents/:id
func (h *IncidentHandler) Update(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	var req struct {
		Title       string  `json:"title"       binding:"required"`
		Description string  `json:"description"`
		Status      string  `json:"status"      binding:"required"`
		Severity    int     `json:"severity"`
		AssignedTo  *string `json:"assigned_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title と status は必須です"})
		return
	}
	if req.Severity < 1 || req.Severity > 10 {
		req.Severity = 7
	}

	if err := h.Store.Update(c.Request.Context(), id, req.Title, req.Description, req.Status, req.Severity, req.AssignedTo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "インシデントの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "インシデントを更新しました", "id": id})
}

// Delete removes an incident.
// DELETE /api/v1/incidents/:id
func (h *IncidentHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "インシデントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "インシデントを削除しました", "id": id})
}

// LinkAlert adds an alert to an incident.
// POST /api/v1/incidents/:id/alerts
func (h *IncidentHandler) LinkAlert(c *gin.Context) {
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	var req struct {
		AlertID string `json:"alert_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "alert_id は必須です"})
		return
	}
	if err := h.Store.LinkAlert(c.Request.Context(), id, req.AlertID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラートのリンクに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "アラートをリンクしました"})
}

// UnlinkAlert removes an alert from an incident.
// DELETE /api/v1/incidents/:id/alerts/:alert_id
func (h *IncidentHandler) UnlinkAlert(c *gin.Context) {
	id := c.Param("id")
	alertID := c.Param("alert_id")
	if err := h.Store.UnlinkAlert(c.Request.Context(), id, alertID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラートのリンク解除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "アラートのリンクを解除しました"})
}

// ListNotes returns notes for an incident.
// GET /api/v1/incidents/:id/notes
func (h *IncidentHandler) ListNotes(c *gin.Context) {
	id := c.Param("id")
	notes, err := h.Store.ListNotes(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ノートの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": notes})
}

// AddNote adds a note to an incident.
// POST /api/v1/incidents/:id/notes
func (h *IncidentHandler) AddNote(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Body string `json:"body" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body は必須です"})
		return
	}
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	note, err := h.Store.AddNote(c.Request.Context(), id, uid, req.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ノートの追加に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, note)
}

// Assign sets the assigned_to field on an incident.
// PATCH /api/v1/incidents/:id/assign
func (h *IncidentHandler) Assign(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		AssignedTo string `json:"assigned_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	var assignedTo *string
	if req.AssignedTo != "" {
		assignedTo = &req.AssignedTo
	}
	inc, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "インシデントが見つかりません"})
		return
	}
	if err := h.Store.Update(c.Request.Context(), id, inc.Title, inc.Description, inc.Status, inc.Severity, assignedTo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アサインの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "担当者を更新しました", "id": id})
}

// Transition changes the status of an incident.
// PATCH /api/v1/incidents/:id/status
func (h *IncidentHandler) Transition(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status は必須です"})
		return
	}
	if !isValidIncidentStatus(req.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status は open/investigating/contained/resolved/closed のいずれかです"})
		return
	}
	inc, err := h.Store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "インシデントが見つかりません"})
		return
	}
	if err := h.Store.Update(c.Request.Context(), id, inc.Title, inc.Description, req.Status, inc.Severity, inc.AssignedTo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータス遷移に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ステータスを更新しました", "id": id, "status": req.Status})
}

// timelineEvent represents a single entry in the incident timeline.
type timelineEvent struct {
	TS     string `json:"ts"`
	Type   string `json:"type"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}

// Timeline returns chronological events for an incident.
// GET /api/v1/incidents/:id/timeline
func (h *IncidentHandler) Timeline(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	// Verify the incident exists.
	inc, err := h.Store.Get(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "インシデントが見つかりません"})
		return
	}

	var events []timelineEvent

	// 1. Creation event derived from incident row itself.
	actor := ""
	if inc.CreatedByName != "" {
		actor = inc.CreatedByName
	}
	events = append(events, timelineEvent{
		TS:     inc.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Type:   "created",
		Actor:  actor,
		Detail: inc.Title,
	})

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"timeline": events})
		return
	}

	// 2. Alert-linked events from incident_alerts joined to alerts.
	alertRows, err := h.Pool.Query(ctx, `
		SELECT ia.linked_at,
		       COALESCE(al.title, ia.alert_id::text, '')
		FROM incident_alerts ia
		LEFT JOIN alerts al ON al.id::text = ia.alert_id
		WHERE ia.incident_id = $1
		ORDER BY ia.linked_at ASC`, id)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var ts string
			var detail string
			if scanErr := alertRows.Scan(&ts, &detail); scanErr == nil {
				events = append(events, timelineEvent{
					TS:     ts,
					Type:   "alert_linked",
					Actor:  "",
					Detail: detail,
				})
			}
		}
		if err := alertRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		alertRows.Close()
	}

	// 3. Notes / timeline entries from incident_notes.
	noteRows, err := h.Pool.Query(ctx, `
		SELECT n.created_at,
		       COALESCE(NULLIF(u.full_name,''), u.email, 'System'),
		       n.body
		FROM incident_notes n
		LEFT JOIN users u ON u.id = n.user_id
		WHERE n.incident_id = $1
		ORDER BY n.created_at ASC`, id)
	if err == nil {
		defer noteRows.Close()
		for noteRows.Next() {
			var ts, actor2, body string
			if scanErr := noteRows.Scan(&ts, &actor2, &body); scanErr == nil {
				events = append(events, timelineEvent{
					TS:     ts,
					Type:   "note",
					Actor:  actor2,
					Detail: body,
				})
			}
		}
		if err := noteRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		noteRows.Close()
	}

	// 4. Comments from incident_comments (added by migration 051).
	commentRows, err := h.Pool.Query(ctx, `
		SELECT ic.created_at,
		       COALESCE(NULLIF(u.full_name,''), u.email, ''),
		       ic.body
		FROM incident_comments ic
		LEFT JOIN users u ON u.id = ic.user_id
		WHERE ic.incident_id = $1
		ORDER BY ic.created_at ASC`, id)
	if err == nil {
		defer commentRows.Close()
		for commentRows.Next() {
			var ts, actor3, body string
			if scanErr := commentRows.Scan(&ts, &actor3, &body); scanErr == nil {
				events = append(events, timelineEvent{
					TS:     ts,
					Type:   "comment",
					Actor:  actor3,
					Detail: body,
				})
			}
		}
		if err := commentRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		commentRows.Close()
	}

	// Sort all events chronologically by timestamp string (ISO-8601 sorts lexicographically).
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j].TS < events[j-1].TS; j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}

	if events == nil {
		events = []timelineEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"timeline": events})
}

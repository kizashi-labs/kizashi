package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeceptionHandler manages deception trap resources.
type DeceptionHandler struct {
	pool *pgxpool.Pool
}

// NewDeceptionHandler creates a new DeceptionHandler.
func NewDeceptionHandler(pool *pgxpool.Pool) *DeceptionHandler {
	return &DeceptionHandler{pool: pool}
}

func (h *DeceptionHandler) checkTrapsTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='deception_traps')`).Scan(&exists)
	return err == nil && exists
}

func (h *DeceptionHandler) checkEventsTable(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='deception_events')`).Scan(&exists)
	return err == nil && exists
}

type deceptionTrap struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	TargetPath      *string `json:"target_path"`
	Description     *string `json:"description"`
	IsActive        bool    `json:"is_active"`
	TriggerCount    int     `json:"trigger_count"`
	LastTriggeredAt *string `json:"last_triggered_at"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

type deceptionEvent struct {
	ID          string          `json:"id"`
	TrapID      string          `json:"trap_id"`
	EndpointID  *string         `json:"endpoint_id"`
	Hostname    *string         `json:"hostname"`
	ProcessName *string         `json:"process_name"`
	ProcessPID  *int            `json:"process_pid"`
	UserName    *string         `json:"user_name"`
	IPAddress   *string         `json:"ip_address"`
	Details     json.RawMessage `json:"details"`
	Severity    string          `json:"severity"`
	CreatedAt   string          `json:"created_at"`
}

// ListTraps returns all deception traps.
// GET /api/v1/admin/deception/traps
func (h *DeceptionHandler) ListTraps(c *gin.Context) {
	if !h.checkTrapsTable(c) {
		c.JSON(http.StatusOK, gin.H{"traps": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, type, target_path, description, is_active, trigger_count,
		        last_triggered_at, created_at, updated_at
		 FROM deception_traps ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list traps"})
		return
	}
	defer rows.Close()

	var result []deceptionTrap
	for rows.Next() {
		var t deceptionTrap
		var lastTriggered *time.Time
		var createdAt, updatedAt time.Time
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Type, &t.TargetPath, &t.Description,
			&t.IsActive, &t.TriggerCount, &lastTriggered, &createdAt, &updatedAt,
		); err != nil {
			continue
		}
		if lastTriggered != nil {
			s := lastTriggered.Format(time.RFC3339)
			t.LastTriggeredAt = &s
		}
		t.CreatedAt = createdAt.Format(time.RFC3339)
		t.UpdatedAt = updatedAt.Format(time.RFC3339)
		result = append(result, t)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []deceptionTrap{}
	}
	c.JSON(http.StatusOK, gin.H{"traps": result, "total": len(result)})
}

// CreateTrap creates a new deception trap.
// POST /api/v1/admin/deception/traps
func (h *DeceptionHandler) CreateTrap(c *gin.Context) {
	if !h.checkTrapsTable(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		TargetPath  *string `json:"target_path"`
		Description *string `json:"description"`
		IsActive    *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Type == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type is required"})
		return
	}
	isActive := true
	if body.IsActive != nil {
		isActive = *body.IsActive
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO deception_traps (name, type, target_path, description, is_active)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		body.Name, body.Type, body.TargetPath, body.Description, isActive,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create trap"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Trap created"})
}

// UpdateTrap updates a deception trap.
// PUT /api/v1/admin/deception/traps/:id
func (h *DeceptionHandler) UpdateTrap(c *gin.Context) {
	if !h.checkTrapsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		TargetPath  *string `json:"target_path"`
		Description *string `json:"description"`
		IsActive    *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE deception_traps SET name=$1, type=$2, target_path=$3, description=$4,
		        is_active=$5, updated_at=NOW()
		 WHERE id=$6`,
		body.Name, body.Type, body.TargetPath, body.Description, body.IsActive, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update trap"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Trap not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Trap updated"})
}

// DeleteTrap deletes a deception trap.
// DELETE /api/v1/admin/deception/traps/:id
func (h *DeceptionHandler) DeleteTrap(c *gin.Context) {
	if !h.checkTrapsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM deception_traps WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete trap"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Trap deleted"})
}

// ToggleTrap flips the is_active state of a trap.
// POST /api/v1/admin/deception/traps/:id/toggle
func (h *DeceptionHandler) ToggleTrap(c *gin.Context) {
	if !h.checkTrapsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var isActive bool
	err := h.pool.QueryRow(ctx,
		`UPDATE deception_traps SET is_active = NOT is_active, updated_at=NOW()
		 WHERE id=$1 RETURNING is_active`, id,
	).Scan(&isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle trap"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_active": isActive})
}

// ListEvents returns paginated deception events, optionally filtered by trap_id.
// GET /api/v1/admin/deception/events
func (h *DeceptionHandler) ListEvents(c *gin.Context) {
	if !h.checkEventsTable(c) {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	trapID := c.Query("trap_id")

	ctx := c.Request.Context()
	var rows interface {
		Next() bool
		Scan(...any) error
		Close()
		Err() error
	}
	var err error
	if trapID != "" {
		rows, err = h.pool.Query(ctx,
			`SELECT id, trap_id, endpoint_id, hostname, process_name, process_pid,
			        user_name, ip_address::text, details, severity, created_at
			 FROM deception_events WHERE trap_id=$1
			 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
			trapID, limit, offset)
	} else {
		rows, err = h.pool.Query(ctx,
			`SELECT id, trap_id, endpoint_id, hostname, process_name, process_pid,
			        user_name, ip_address::text, details, severity, created_at
			 FROM deception_events
			 ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
			limit, offset)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list events"})
		return
	}
	defer func() {
		type closer interface{ Close() }
		if cl, ok := rows.(closer); ok {
			cl.Close()
		}
	}()

	var result []deceptionEvent
	for rows.Next() {
		var ev deceptionEvent
		var createdAt time.Time
		var details []byte
		if err := rows.Scan(
			&ev.ID, &ev.TrapID, &ev.EndpointID, &ev.Hostname,
			&ev.ProcessName, &ev.ProcessPID, &ev.UserName, &ev.IPAddress,
			&details, &ev.Severity, &createdAt,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []deceptionEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": result, "total": len(result)})
}

// GetEventDetail returns a single deception event.
// GET /api/v1/admin/deception/events/:id
func (h *DeceptionHandler) GetEventDetail(c *gin.Context) {
	if !h.checkEventsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	var ev deceptionEvent
	var createdAt time.Time
	var details []byte
	err := h.pool.QueryRow(ctx,
		`SELECT id, trap_id, endpoint_id, hostname, process_name, process_pid,
		        user_name, ip_address::text, details, severity, created_at
		 FROM deception_events WHERE id=$1`, id,
	).Scan(
		&ev.ID, &ev.TrapID, &ev.EndpointID, &ev.Hostname,
		&ev.ProcessName, &ev.ProcessPID, &ev.UserName, &ev.IPAddress,
		&details, &ev.Severity, &createdAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Event not found"})
		return
	}
	if len(details) > 0 {
		ev.Details = json.RawMessage(details)
	}
	ev.CreatedAt = createdAt.Format(time.RFC3339)
	c.JSON(http.StatusOK, ev)
}

// SimulateTrigger inserts a mock deception_event for a trap (for testing).
// POST /api/v1/admin/deception/traps/:id/simulate
func (h *DeceptionHandler) SimulateTrigger(c *gin.Context) {
	if !h.checkTrapsTable(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	trapID := c.Param("id")

	var body struct {
		Hostname    string `json:"hostname"`
		ProcessName string `json:"process_name"`
		ProcessPID  *int   `json:"process_pid"`
		UserName    string `json:"user_name"`
		IPAddress   string `json:"ip_address"`
		Severity    string `json:"severity"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}

	// Apply defaults for simulation — use clearly synthetic values
	shortID := uuid.New().String()[:8]
	if body.Hostname == "" {
		body.Hostname = fmt.Sprintf("sim-host-%s", shortID)
	}
	if body.ProcessName == "" {
		body.ProcessName = "suspicious.exe"
	}
	if body.UserName == "" {
		body.UserName = fmt.Sprintf("sim-user-%s", shortID)
	}
	if body.IPAddress == "" {
		body.IPAddress = "192.0.2.1" // RFC 5737 TEST-NET-1, documentation-only
	}
	if body.Severity == "" {
		body.Severity = "high"
	}

	ctx := c.Request.Context()

	// Verify trap exists
	var trapName string
	err := h.pool.QueryRow(ctx, `SELECT name FROM deception_traps WHERE id=$1`, trapID).Scan(&trapName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Trap not found"})
		return
	}

	details := map[string]interface{}{
		"simulated": true,
		"trap_name": trapName,
		"source":    "manual_simulation",
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		slog.Warn("deception: シミュレーション詳細のシリアライズに失敗しました", "error", err)
		detailsJSON = []byte("{}")
	}

	var eventID string
	err = h.pool.QueryRow(ctx,
		`INSERT INTO deception_events
		 (trap_id, hostname, process_name, process_pid, user_name, ip_address, details, severity)
		 VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8) RETURNING id`,
		trapID, body.Hostname, body.ProcessName, body.ProcessPID,
		body.UserName, body.IPAddress, detailsJSON, body.Severity,
	).Scan(&eventID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to simulate trigger"})
		return
	}

	// Increment trigger_count on the trap
	if _, execErr := h.pool.Exec(ctx,
		`UPDATE deception_traps SET trigger_count = trigger_count + 1,
		        last_triggered_at=NOW(), updated_at=NOW()
		 WHERE id=$1`, trapID,
	); execErr != nil {
		slog.Warn("deception: trigger_count の更新に失敗しました", "trap_id", trapID, "error", execErr)
	}

	// Return the created event
	var ev deceptionEvent
	var createdAt time.Time
	var detailsOut []byte
	err = h.pool.QueryRow(ctx,
		`SELECT id, trap_id, endpoint_id, hostname, process_name, process_pid,
		        user_name, ip_address::text, details, severity, created_at
		 FROM deception_events WHERE id=$1`, eventID,
	).Scan(
		&ev.ID, &ev.TrapID, &ev.EndpointID, &ev.Hostname,
		&ev.ProcessName, &ev.ProcessPID, &ev.UserName, &ev.IPAddress,
		&detailsOut, &ev.Severity, &createdAt,
	)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": eventID, "message": "Simulation triggered"})
		return
	}
	if len(detailsOut) > 0 {
		ev.Details = json.RawMessage(detailsOut)
	}
	ev.CreatedAt = createdAt.Format(time.RFC3339)
	c.JSON(http.StatusCreated, ev)
}

// ListAssets returns all deception assets from the deception_assets table.
// GET /api/v1/admin/deception/assets
func (h *DeceptionHandler) ListAssets(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, asset_type, COALESCE(description,''), COALESCE(emulated_service,''),
		       COALESCE(listen_port::text,''), status, alert_on_access, triggered_count, last_triggered, created_at
		FROM deception_assets ORDER BY status, name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"assets": []any{}})
		return
	}
	defer rows.Close()

	type Asset struct {
		ID              string  `json:"id"`
		Name            string  `json:"name"`
		AssetType       string  `json:"asset_type"`
		Description     string  `json:"description"`
		EmulatedService string  `json:"emulated_service"`
		ListenPort      string  `json:"listen_port"`
		Status          string  `json:"status"`
		AlertOnAccess   bool    `json:"alert_on_access"`
		TriggeredCount  int     `json:"triggered_count"`
		LastTriggered   *string `json:"last_triggered"`
		CreatedAt       string  `json:"created_at"`
	}
	var list []Asset
	for rows.Next() {
		var a Asset
		var lastTriggered *time.Time
		var createdAt time.Time
		if err := rows.Scan(&a.ID, &a.Name, &a.AssetType, &a.Description, &a.EmulatedService,
			&a.ListenPort, &a.Status, &a.AlertOnAccess, &a.TriggeredCount, &lastTriggered, &createdAt); err != nil {
			continue
		}
		a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if lastTriggered != nil {
			s := lastTriggered.UTC().Format(time.RFC3339)
			a.LastTriggered = &s
		}
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if list == nil {
		list = []Asset{}
	}
	c.JSON(http.StatusOK, gin.H{"assets": list})
}

// CreateAsset creates a new deception asset in the deception_assets table.
// POST /api/v1/admin/deception/assets
func (h *DeceptionHandler) CreateAsset(c *gin.Context) {
	var req struct {
		Name            string `json:"name" binding:"required"`
		AssetType       string `json:"asset_type"`
		Description     string `json:"description"`
		EmulatedService string `json:"emulated_service"`
		ListenPort      int    `json:"listen_port"`
		AlertOnAccess   bool   `json:"alert_on_access"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.AssetType == "" {
		req.AssetType = "honeypot"
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO deception_assets (name, asset_type, description, emulated_service, listen_port, alert_on_access)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id
	`, req.Name, req.AssetType, req.Description, req.EmulatedService, req.ListenPort, req.AlertOnAccess).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// AssetStats returns summary statistics for deception assets.
// GET /api/v1/admin/deception/stats
func (h *DeceptionHandler) AssetStats(c *gin.Context) {
	var total, active, triggered int
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE status='active'),
		       COUNT(*) FILTER (WHERE status='triggered')
		FROM deception_assets
	`).Scan(&total, &active, &triggered)
	var eventCount int
	h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM deception_events`).Scan(&eventCount)
	c.JSON(http.StatusOK, gin.H{
		"total_assets": total,
		"active":       active,
		"triggered":    triggered,
		"total_events": eventCount,
	})
}

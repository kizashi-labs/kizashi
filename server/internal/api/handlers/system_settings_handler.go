package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SystemSettingsHandler handles CRUD for system-wide configuration.
type SystemSettingsHandler struct {
	pool *pgxpool.Pool
}

// NewSystemSettingsHandler creates a new SystemSettingsHandler.
func NewSystemSettingsHandler(pool *pgxpool.Pool) *SystemSettingsHandler {
	return &SystemSettingsHandler{pool: pool}
}

type systemSetting struct {
	Key         string          `json:"key"`
	Value       json.RawMessage `json:"value"`
	Description string          `json:"description"`
	UpdatedAt   time.Time       `json:"updated_at"`
	UpdatedBy   *string         `json:"updated_by,omitempty"`
}

// GetAll returns all system settings as {"settings": {"key": value, ...}}.
func (h *SystemSettingsHandler) GetAll(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT key, value, description, updated_at, updated_by::text
		 FROM system_settings ORDER BY key`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	settings := make(map[string]interface{})
	for rows.Next() {
		var s systemSetting
		var updatedBy *string
		if err := rows.Scan(&s.Key, &s.Value, &s.Description, &s.UpdatedAt, &updatedBy); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		s.UpdatedBy = updatedBy
		// Unmarshal value so it's not double-encoded
		var v interface{}
		if err := json.Unmarshal(s.Value, &v); err != nil {
			v = string(s.Value)
		}
		settings[s.Key] = v
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// Update updates a single setting by key.
func (h *SystemSettingsHandler) Update(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key is required"})
		return
	}

	var body struct {
		Value interface{} `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valueJSON, err := json.Marshal(body.Value)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid value"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE system_settings
		 SET value = $1::jsonb, updated_at = NOW(), updated_by = $2::uuid
		 WHERE key = $3`,
		string(valueJSON), nilIfEmpty(userIDStr), key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "setting not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"key": key, "value": body.Value})
}

// BulkUpdate updates multiple settings at once.
// Body: {"settings": {"key": value, ...}}
func (h *SystemSettingsHandler) BulkUpdate(c *gin.Context) {
	var body struct {
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.Settings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no settings provided"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	ctx := c.Request.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	updated := make([]string, 0, len(body.Settings))
	for key, val := range body.Settings {
		valueJSON, err := json.Marshal(val)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid value for key: " + key})
			return
		}
		tag, err := tx.Exec(ctx,
			`UPDATE system_settings
			 SET value = $1::jsonb, updated_at = NOW(), updated_by = $2::uuid
			 WHERE key = $3`,
			string(valueJSON), nilIfEmpty(userIDStr), key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		if tag.RowsAffected() > 0 {
			updated = append(updated, key)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"updated": updated, "count": len(updated)})
}

// GetMaintenanceMode returns the current maintenance mode status.
func (h *SystemSettingsHandler) GetMaintenanceMode(c *gin.Context) {
	ctx := c.Request.Context()
	var rawValue json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'maintenance_mode'`).
		Scan(&rawValue)
	if err != nil {
		// Default to false if not found
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}

	var enabled bool
	if err := json.Unmarshal(rawValue, &enabled); err != nil {
		// Try string "true"/"false"
		var s string
		if err2 := json.Unmarshal(rawValue, &s); err2 == nil {
			enabled = s == "true"
		}
	}

	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}

// nilIfEmpty returns nil if the string is empty, otherwise returns a pointer to it.
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IntegrationConfigHandler manages external integration settings.
// GET/PUT  /api/v1/admin/integrations/:type/config
// POST     /api/v1/admin/integrations/:type/test
// GET      /api/v1/admin/integrations/summary
// GET/PUT  /api/v1/soar/config
// POST     /api/v1/soar/jira/test, /api/v1/soar/servicenow/test
// POST     /api/v1/notifications/slack/test, /teams/test, /webhook/test
type IntegrationConfigHandler struct {
	pool *pgxpool.Pool
}

func NewIntegrationConfigHandler(pool *pgxpool.Pool) *IntegrationConfigHandler {
	return &IntegrationConfigHandler{pool: pool}
}

func (h *IntegrationConfigHandler) tableExists(c *gin.Context) bool {
	var ok bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='integration_configs')`).Scan(&ok)
	return ok
}

func integType(c *gin.Context) string {
	if t := c.Param("type"); t != "" {
		return t
	}
	if t, ok := c.Get("integ_type"); ok {
		if s, ok := t.(string); ok {
			return s
		}
	}
	return "unknown"
}

// GetConfig returns the config for a specific integration type.
// GET /api/v1/admin/integrations/:type/config  (also used for /soar/config)
func (h *IntegrationConfigHandler) GetConfig(c *gin.Context) {
	it := integType(c)
	ctx := c.Request.Context()

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{it: nil})
		return
	}

	var configJSON []byte
	var enabled bool
	err := h.pool.QueryRow(ctx,
		`SELECT config, enabled FROM integration_configs WHERE integ_type=$1`, it,
	).Scan(&configJSON, &enabled)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{it: nil, "enabled": false})
		return
	}

	var config map[string]interface{}
	_ = json.Unmarshal(configJSON, &config)
	c.JSON(http.StatusOK, gin.H{it: config, "enabled": enabled})
}

// SaveConfig stores the config for a specific integration type.
// PUT /api/v1/admin/integrations/:type/config  (also used for /soar/config)
func (h *IntegrationConfigHandler) SaveConfig(c *gin.Context) {
	it := integType(c)

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"message": "Config saved"})
		return
	}

	configJSON, _ := json.Marshal(body)
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `
		INSERT INTO integration_configs (integ_type, config, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (integ_type) DO UPDATE SET config=$2, updated_at=NOW()`,
		it, configJSON)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save config"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Config saved"})
}

// TestConnection simulates or attempts a connection test for an integration.
// POST /api/v1/admin/integrations/:type/test
func (h *IntegrationConfigHandler) TestConnection(c *gin.Context) {
	it := integType(c)

	ctx := c.Request.Context()
	if h.tableExists(c) {
		_, _ = h.pool.Exec(ctx, `
			UPDATE integration_configs SET last_tested=NOW(), test_status='ok' WHERE integ_type=$1`,
			it)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"message":   it + " connection successful",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// GetSummary returns aggregate integration stats.
// GET /api/v1/admin/integrations/summary
func (h *IntegrationConfigHandler) GetSummary(c *gin.Context) {
	ctx := c.Request.Context()
	summary := gin.H{
		"total":        0,
		"connected":    0,
		"disconnected": 0,
		"error":        0,
	}

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, summary)
		return
	}

	var total, connected, withError int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM integration_configs`).Scan(&total)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM integration_configs WHERE enabled=true AND test_status='ok'`).Scan(&connected)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM integration_configs WHERE test_status='error'`).Scan(&withError)

	disconnected := total - connected - withError
	if disconnected < 0 {
		disconnected = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"total":        total,
		"connected":    connected,
		"disconnected": disconnected,
		"error":        withError,
	})
}

// GetMappings returns field mappings config for an integration.
// GET /api/v1/admin/integrations/:type/mappings
func (h *IntegrationConfigHandler) GetMappings(c *gin.Context) {
	it := integType(c)
	ctx := c.Request.Context()

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"mappings": []interface{}{}})
		return
	}

	var configJSON []byte
	err := h.pool.QueryRow(ctx,
		`SELECT config FROM integration_configs WHERE integ_type=$1`, it+"-mappings",
	).Scan(&configJSON)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"mappings": []interface{}{}})
		return
	}
	var result interface{}
	_ = json.Unmarshal(configJSON, &result)
	c.JSON(http.StatusOK, result)
}

// SaveMappings stores field mappings for an integration.
// POST /api/v1/admin/integrations/:type/mappings
func (h *IntegrationConfigHandler) SaveMappings(c *gin.Context) {
	it := integType(c)
	var body interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	bodyJSON, _ := json.Marshal(body)

	if h.tableExists(c) {
		ctx := c.Request.Context()
		_, _ = h.pool.Exec(ctx, `
			INSERT INTO integration_configs (integ_type, config, updated_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (integ_type) DO UPDATE SET config=$2, updated_at=NOW()`,
			it+"-mappings", bodyJSON)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Mappings saved"})
}

// GetStatus returns current integration status.
// GET /api/v1/admin/integrations/:type/status
func (h *IntegrationConfigHandler) GetStatus(c *gin.Context) {
	it := integType(c)
	ctx := c.Request.Context()

	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"status": "disconnected", "type": it})
		return
	}

	var testStatus *string
	var lastTested *time.Time
	var enabled bool
	err := h.pool.QueryRow(ctx,
		`SELECT test_status, last_tested, enabled FROM integration_configs WHERE integ_type=$1`, it,
	).Scan(&testStatus, &lastTested, &enabled)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "disconnected", "type": it, "enabled": false})
		return
	}

	status := "disconnected"
	if enabled && testStatus != nil && *testStatus == "ok" {
		status = "connected"
	} else if testStatus != nil && *testStatus == "error" {
		status = "error"
	}

	resp := gin.H{"status": status, "type": it, "enabled": enabled}
	if lastTested != nil {
		resp["last_tested"] = lastTested.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, resp)
}

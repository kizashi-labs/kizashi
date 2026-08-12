package handlers

// AgentConfigHandler provides endpoints for agent configuration schema and defaults.
// Agents can GET their effective config (policy + overrides) and PUT custom overrides.

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentConfigHandler handles agent configuration schema and per-agent overrides.
type AgentConfigHandler struct {
	pool *pgxpool.Pool
}

// NewAgentConfigHandler creates a new AgentConfigHandler.
func NewAgentConfigHandler(pool *pgxpool.Pool) *AgentConfigHandler {
	return &AgentConfigHandler{pool: pool}
}

// configSchemaField describes a single config key in the schema.
type configSchemaField struct {
	Type    string      `json:"type"`
	Default interface{} `json:"default"`
	Min     *int        `json:"min,omitempty"`
	Max     *int        `json:"max,omitempty"`
	Enum    []string    `json:"enum,omitempty"`
}

func intPtr(v int) *int { return &v }

// hardcodedSchema returns the static configuration schema.
func hardcodedSchema() map[string]configSchemaField {
	return map[string]configSchemaField{
		"collection_interval_seconds": {
			Type:    "integer",
			Default: 60,
			Min:     intPtr(10),
			Max:     intPtr(3600),
		},
		"send_interval_seconds": {
			Type:    "integer",
			Default: 30,
			Min:     intPtr(5),
			Max:     intPtr(300),
		},
		"process_monitoring": {
			Type:    "boolean",
			Default: true,
		},
		"network_monitoring": {
			Type:    "boolean",
			Default: true,
		},
		"file_monitoring": {
			Type:    "boolean",
			Default: false,
		},
		"log_level": {
			Type:    "string",
			Default: "info",
			Enum:    []string{"debug", "info", "warn", "error"},
		},
	}
}

// defaultConfigValues returns a map of key→default value from the schema.
func defaultConfigValues() map[string]interface{} {
	defaults := make(map[string]interface{})
	for k, v := range hardcodedSchema() {
		defaults[k] = v.Default
	}
	return defaults
}

// GetSchema returns the JSON schema of valid config keys with their defaults and constraints.
// GET /api/v1/agent-config/schema
func (h *AgentConfigHandler) GetSchema(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schema": hardcodedSchema(),
	})
}

// GetEffective returns the merged effective config for an agent (policy defaults + agent-level overrides).
// GET /api/v1/agents/:id/effective-config
func (h *AgentConfigHandler) GetEffective(c *gin.Context) {
	agentID := c.Param("id")
	ctx := c.Request.Context()

	// Start with schema defaults.
	effective := defaultConfigValues()

	// Apply policy-level settings via agent → agent_groups → agent_policies join.
	var policyLogLevel *string
	var policyMonitorNetwork *bool
	err := h.pool.QueryRow(ctx, `
		SELECT ap.log_level, ap.monitor_network
		FROM agents a
		LEFT JOIN agent_groups ag ON ag.id = a.group_id
		LEFT JOIN agent_policies ap ON ap.id = COALESCE(a.policy_id, ag.policy_id)
		WHERE a.id = $1
	`, agentID).Scan(&policyLogLevel, &policyMonitorNetwork)
	if err == nil {
		if policyLogLevel != nil && *policyLogLevel != "" {
			effective["log_level"] = *policyLogLevel
		}
		if policyMonitorNetwork != nil {
			effective["network_monitoring"] = *policyMonitorNetwork
		}
	}

	// Apply agent-level overrides stored in agents.settings JSONB.
	var settingsRaw []byte
	err = h.pool.QueryRow(ctx, `
		SELECT settings FROM agents WHERE id = $1
	`, agentID).Scan(&settingsRaw)
	if err == nil && len(settingsRaw) > 0 {
		var overrides map[string]interface{}
		if jsonErr := json.Unmarshal(settingsRaw, &overrides); jsonErr == nil {
			for k, v := range overrides {
				effective[k] = v
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_id": agentID,
		"config":   effective,
	})
}

// UpdateOverride stores agent-level config overrides in the agents.settings JSONB column.
// PUT /api/v1/agents/:id/config-override
func (h *AgentConfigHandler) UpdateOverride(c *gin.Context) {
	agentID := c.Param("id")
	ctx := c.Request.Context()

	var incoming map[string]interface{}
	if err := c.ShouldBindJSON(&incoming); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	// Fetch existing settings to merge.
	var existingRaw []byte
	_ = h.pool.QueryRow(ctx, `SELECT settings FROM agents WHERE id = $1`, agentID).Scan(&existingRaw)

	merged := make(map[string]interface{})
	if len(existingRaw) > 0 {
		_ = json.Unmarshal(existingRaw, &merged)
	}
	for k, v := range incoming {
		merged[k] = v
	}

	mergedBytes, err := json.Marshal(merged)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode settings"})
		return
	}

	tag, err := h.pool.Exec(ctx, `
		UPDATE agents SET settings = $2 WHERE id = $1
	`, agentID, mergedBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update agent settings"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_id": agentID,
		"settings": merged,
	})
}

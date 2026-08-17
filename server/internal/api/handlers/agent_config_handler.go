package handlers

// AgentConfigHandler provides endpoints for agent configuration schema and defaults.
// Agents can GET their effective config (policy + overrides) and PUT custom overrides.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
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

// validateOverrides checks incoming overrides against the schema this handler
// publishes at /api/v1/agent-config/schema.
//
// Nothing checked them before. That mattered less while the write always failed
// with 42703, but making it work without this would mean an operator could
// store log_level "verbose" or a collection interval of 0 — values the schema
// says are invalid, served back as the agent's effective config. A published
// schema that the write path ignores is not a schema.
//
// Returns one message per offending key, so a caller fixing a bad body is not
// made to discover the problems one at a time.
func validateOverrides(incoming map[string]interface{}) []string {
	schema := hardcodedSchema()
	var problems []string

	keys := make([]string, 0, len(incoming))
	for k := range incoming {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		field, known := schema[key]
		if !known {
			problems = append(problems, fmt.Sprintf("%q は設定項目ではありません", key))
			continue
		}
		value := incoming[key]

		switch field.Type {
		case "boolean":
			if _, ok := value.(bool); !ok {
				problems = append(problems, fmt.Sprintf("%q は真偽値である必要があります", key))
			}
		case "string":
			str, ok := value.(string)
			if !ok {
				problems = append(problems, fmt.Sprintf("%q は文字列である必要があります", key))
				continue
			}
			if len(field.Enum) > 0 && !slices.Contains(field.Enum, str) {
				problems = append(problems, fmt.Sprintf("%q は %s のいずれかである必要があります (指定値: %q)",
					key, strings.Join(field.Enum, ", "), str))
			}
		case "integer":
			// A request body decodes JSON numbers to float64, but the schema's
			// own defaults are Go ints, and this must accept a config value in
			// either representation to be usable by any caller. A float is only
			// an integer if it is whole.
			var n int
			switch num := value.(type) {
			case float64:
				if num != math.Trunc(num) {
					problems = append(problems, fmt.Sprintf("%q は整数である必要があります", key))
					continue
				}
				n = int(num)
			case int:
				n = num
			default:
				problems = append(problems, fmt.Sprintf("%q は整数である必要があります", key))
				continue
			}
			if field.Min != nil && n < *field.Min {
				problems = append(problems, fmt.Sprintf("%q は %d 以上である必要があります (指定値: %d)",
					key, *field.Min, n))
			}
			if field.Max != nil && n > *field.Max {
				problems = append(problems, fmt.Sprintf("%q は %d 以下である必要があります (指定値: %d)",
					key, *field.Max, n))
			}
		}
	}
	return problems
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
	//
	// This used to discard its error, which is how a missing column became an
	// effective config silently reported without its top layer.
	var settingsRaw []byte
	err = h.pool.QueryRow(ctx, `
		SELECT settings FROM agents WHERE id = $1
	`, agentID).Scan(&settingsRaw)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	case err != nil:
		slog.Warn("エージェント個別設定の読み込みに失敗しました", "agent", agentID, "error", err)
	case len(settingsRaw) > 0:
		var overrides map[string]interface{}
		if jsonErr := json.Unmarshal(settingsRaw, &overrides); jsonErr != nil {
			slog.Warn("エージェント個別設定のJSONが不正です", "agent", agentID, "error", jsonErr)
		} else {
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

	if problems := validateOverrides(incoming); len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "設定値が不正です",
			"details": problems,
		})
		return
	}

	// Fetch existing settings to merge.
	var existingRaw []byte
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT settings FROM agents WHERE id = $1`, agentID).Scan(&existingRaw)) {
		return
	}

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

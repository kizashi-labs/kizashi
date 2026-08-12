package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AssetCriticalityHandler computes and stores asset criticality scores.
type AssetCriticalityHandler struct {
	pool *pgxpool.Pool
}

// NewAssetCriticalityHandler creates a new AssetCriticalityHandler.
func NewAssetCriticalityHandler(pool *pgxpool.Pool) *AssetCriticalityHandler {
	return &AssetCriticalityHandler{pool: pool}
}

type criticalityFactor struct {
	Name   string `json:"name"`
	Impact int    `json:"impact"`
	Value  string `json:"value"`
}

type criticalityResult struct {
	AgentID string              `json:"agent_id"`
	Score   int                 `json:"score"`
	Factors []criticalityFactor `json:"factors"`
	Tier    string              `json:"tier"`
}

func scoreTier(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

func (h *AssetCriticalityHandler) computeScoreForAgent(c *gin.Context, agentID string) (*criticalityResult, error) {
	ctx := c.Request.Context()

	// Query agent details
	var osType, osVersion, status string
	err := h.pool.QueryRow(ctx,
		`SELECT os_type, COALESCE(os_version, ''), status FROM agents WHERE id = $1`, agentID,
	).Scan(&osType, &osVersion, &status)
	if err != nil {
		return nil, err
	}

	score := 50
	var factors []criticalityFactor

	// +20 if server OS (linux/server type)
	combined := strings.ToLower(osType + " " + osVersion)
	if strings.Contains(combined, "server") || strings.Contains(combined, "linux") ||
		strings.Contains(combined, "centos") || strings.Contains(combined, "rhel") ||
		strings.Contains(combined, "debian") {
		score += 20
		factors = append(factors, criticalityFactor{
			Name:   "server_os",
			Impact: 20,
			Value:  osType + " " + osVersion,
		})
	}

	// -10 if offline
	//
	// 'inactive'(30日以上未確認で DeadAgentCleanup が退役判定した状態)も対象に含める。
	// 'offline' だけを見ていると、**より長く死んでいるホストほど減点されない**という
	// 反転が起きる(数時間落ちた 'offline' は -10、30日死んだ 'inactive' は減点なし)。
	if status == "offline" || status == "inactive" {
		score -= 10
		factors = append(factors, criticalityFactor{
			Name:   "offline_penalty",
			Impact: -10,
			Value:  status,
		})
	}

	// +15 if active alerts
	var activeAlerts int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id = $1 AND status NOT IN ('resolved', 'closed')`, agentID,
	).Scan(&activeAlerts)
	if activeAlerts > 0 {
		score += 15
		factors = append(factors, criticalityFactor{
			Name:   "active_alerts",
			Impact: 15,
			Value:  fmt.Sprintf("%d", activeAlerts),
		})
	}

	// +10 if high vuln count
	var highVulns int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vulnerabilities WHERE agent_id = $1 AND severity IN ('high','critical')`, agentID,
	).Scan(&highVulns)
	if highVulns > 0 {
		score += 10
		factors = append(factors, criticalityFactor{
			Name:   "high_vulnerabilities",
			Impact: 10,
			Value:  fmt.Sprintf("%d", highVulns),
		})
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	if factors == nil {
		factors = []criticalityFactor{}
	}

	result := &criticalityResult{
		AgentID: agentID,
		Score:   score,
		Factors: factors,
		Tier:    scoreTier(score),
	}

	// Store score in system_metadata
	key := "agent_criticality_" + agentID
	scoreJSON, _ := json.Marshal(result)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO system_metadata (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, string(scoreJSON),
	)

	return result, nil
}

// GetScore computes and returns the criticality score for a specific agent.
// GET /api/v1/endpoints/:id/criticality
func (h *AssetCriticalityHandler) GetScore(c *gin.Context) {
	agentID := c.Param("id")
	result, err := h.computeScoreForAgent(c, agentID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to compute criticality score"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// BulkScore computes criticality scores for all agents and returns them sorted.
// POST /api/v1/endpoints/criticality/bulk
func (h *AssetCriticalityHandler) BulkScore(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `SELECT id FROM agents ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list agents"})
		return
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			agentIDs = append(agentIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	results := []*criticalityResult{}
	for _, id := range agentIDs {
		r, err := h.computeScoreForAgent(c, id)
		if err == nil {
			results = append(results, r)
		}
	}

	// Sort by score descending
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Score > results[i].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  results,
		"total": len(results),
	})
}

// SetManualScore stores a manual override for an agent's criticality score.
// PUT /api/v1/endpoints/:id/criticality
func (h *AssetCriticalityHandler) SetManualScore(c *gin.Context) {
	agentID := c.Param("id")
	var req struct {
		Score  int    `json:"score" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Score < 0 || req.Score > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "score must be between 0 and 100"})
		return
	}

	result := &criticalityResult{
		AgentID: agentID,
		Score:   req.Score,
		Factors: []criticalityFactor{
			{Name: "manual_override", Impact: 0, Value: req.Reason},
		},
		Tier: scoreTier(req.Score),
	}

	key := "agent_criticality_" + agentID
	scoreJSON, _ := json.Marshal(result)
	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO system_metadata (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, string(scoreJSON),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store manual score"})
		return
	}

	c.JSON(http.StatusOK, result)
}

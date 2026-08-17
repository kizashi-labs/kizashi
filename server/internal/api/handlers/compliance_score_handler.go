package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/compliance"
	"github.com/edr-platform/server/internal/store"
)

// ComplianceScoreHandler handles CIS benchmark auto-scoring endpoints.
type ComplianceScoreHandler struct {
	pool       *pgxpool.Pool
	scoreStore *store.ComplianceScoreStore
}

// NewComplianceScoreHandler creates a new ComplianceScoreHandler.
func NewComplianceScoreHandler(pool *pgxpool.Pool) *ComplianceScoreHandler {
	return &ComplianceScoreHandler{
		pool:       pool,
		scoreStore: store.NewComplianceScoreStore(pool),
	}
}

// ListScores handles GET /api/v1/compliance/scores
// Returns all agents' compliance scores ordered by score ascending (worst first).
func (h *ComplianceScoreHandler) ListScores(c *gin.Context) {
	scores, err := h.scoreStore.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コンプライアンススコアの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scores": scores})
}

// GetScore handles GET /api/v1/compliance/scores/:agent_id
// Returns the compliance score for a specific agent.
func (h *ComplianceScoreHandler) GetScore(c *gin.Context) {
	agentID := c.Param("agent_id")
	framework := c.DefaultQuery("framework", "CIS")

	score, err := h.scoreStore.GetByAgent(c.Request.Context(), agentID, framework)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "指定されたエージェントのスコアが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, score)
}

// ComputeScore handles POST /api/v1/compliance/scores/:agent_id/compute
// Triggers recomputation of CIS compliance score for the specified agent.
func (h *ComplianceScoreHandler) ComputeScore(c *gin.Context) {
	agentID := c.Param("agent_id")

	result, err := compliance.ScoreAgent(c.Request.Context(), h.pool, agentID)
	if errors.Is(err, compliance.ErrNothingAssessed) {
		// Nothing was measured, so nothing is stored. Answering 503 rather than
		// 500 says the assessment can be retried — and, unlike the previous
		// behaviour, does not leave a fabricated score of 100 behind.
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "コンプライアンス判定を実行できませんでした。スコアは更新していません"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Build details JSON
	//
	// assessed travels with each check because passed=false alone cannot say
	// whether the check failed or could not be run, and the stored record is
	// what an auditor reads months later.
	type checkJSON struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Passed   bool   `json:"passed"`
		Assessed bool   `json:"assessed"`
	}
	type detailsJSON struct {
		Checks []checkJSON `json:"checks"`
		// Assessed / Declared record how much of the benchmark this score is
		// actually about. A 100 over three of eight checks is a different claim
		// from a 100 over eight.
		Assessed int `json:"assessed_checks"`
		Declared int `json:"declared_checks"`
	}
	d := detailsJSON{
		Checks:   make([]checkJSON, len(result.Checks)),
		Assessed: result.Assessed,
		Declared: len(result.Checks),
	}
	for i, ch := range result.Checks {
		d.Checks[i] = checkJSON{
			ID:       ch.ID,
			Title:    ch.Title,
			Severity: ch.Severity,
			Passed:   ch.Passed,
			Assessed: ch.Assessed,
		}
	}
	detailsBytes, _ := json.Marshal(d)

	scoreRecord := &store.ComplianceScore{
		AgentID:      result.AgentID,
		Framework:    "CIS",
		Score:        result.Score,
		TotalChecks:  result.Total,
		PassedChecks: result.Passed,
		Details:      detailsBytes,
	}

	saved, err := h.scoreStore.Upsert(c.Request.Context(), scoreRecord)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, saved)
}

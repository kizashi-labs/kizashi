package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ZeroTrustHandler manages zero trust access policies.
type ZeroTrustHandler struct {
	pool *pgxpool.Pool
}

// NewZeroTrustHandler creates a new ZeroTrustHandler.
func NewZeroTrustHandler(pool *pgxpool.Pool) *ZeroTrustHandler {
	return &ZeroTrustHandler{pool: pool}
}

func (h *ZeroTrustHandler) policyTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "zero_trust_policies")
}

func (h *ZeroTrustHandler) logTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "zero_trust_access_logs")
}

type ztPolicy struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	PolicyType  string      `json:"policy_type"`
	Conditions  interface{} `json:"conditions"`
	Action      string      `json:"action"`
	Priority    int         `json:"priority"`
	Enabled     bool        `json:"enabled"`
	MatchCount  int         `json:"match_count"`
	CreatedBy   *string     `json:"created_by"`
	CreatedAt   string      `json:"created_at"`
	UpdatedAt   string      `json:"updated_at"`
}

func scanZTPolicy(row interface{ Scan(...any) error }) (*ztPolicy, error) {
	var p ztPolicy
	var condRaw []byte
	var createdAt, updatedAt time.Time
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.PolicyType, &condRaw,
		&p.Action, &p.Priority, &p.Enabled, &p.MatchCount, &p.CreatedBy,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	if condRaw != nil {
		_ = json.Unmarshal(condRaw, &p.Conditions)
	}
	if p.Conditions == nil {
		p.Conditions = map[string]interface{}{}
	}
	p.CreatedAt = createdAt.Format(time.RFC3339)
	p.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &p, nil
}

const ztPolicyCols = `id, name, description, policy_type, conditions, action, priority,
	enabled, match_count, created_by, created_at, updated_at`

var validZTActions = map[string]bool{
	"allow":        true,
	"deny":         true,
	"mfa_required": true,
	"quarantine":   true,
}

// ListPolicies returns policies ordered by priority.
// GET /api/v1/zero-trust/policies
func (h *ZeroTrustHandler) ListPolicies(c *gin.Context) {
	if !h.policyTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"policies": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT `+ztPolicyCols+` FROM zero_trust_policies ORDER BY priority ASC, created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシー一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var result []ztPolicy
	for rows.Next() {
		p, err := scanZTPolicy(rows)
		if err == nil {
			result = append(result, *p)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシー一覧の取得に失敗しました"})
		return
	}
	if result == nil {
		result = []ztPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": result, "total": len(result)})
}

// GetPolicy returns a single policy.
// GET /api/v1/zero-trust/policies/:id
func (h *ZeroTrustHandler) GetPolicy(c *gin.Context) {
	if !h.policyTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	p, err := scanZTPolicy(h.pool.QueryRow(ctx,
		`SELECT `+ztPolicyCols+` FROM zero_trust_policies WHERE id=$1`, id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ポリシーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// CreatePolicy creates a new zero trust policy.
// POST /api/v1/zero-trust/policies
func (h *ZeroTrustHandler) CreatePolicy(c *gin.Context) {
	if !h.policyTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "テーブルが存在しません"})
		return
	}
	var body struct {
		Name        string      `json:"name" binding:"required"`
		Description string      `json:"description"`
		PolicyType  string      `json:"policy_type"`
		Conditions  interface{} `json:"conditions"`
		Action      string      `json:"action"`
		Priority    int         `json:"priority"`
		Enabled     *bool       `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nameは必須です"})
		return
	}
	if body.Action == "" {
		body.Action = "deny"
	}
	if !validZTActions[body.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "actionはallow/deny/mfa_required/quarantineのいずれかを指定してください"})
		return
	}
	if body.PolicyType == "" {
		body.PolicyType = "network"
	}
	if body.Priority == 0 {
		body.Priority = 100
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	condJSON, _ := json.Marshal(body.Conditions)
	if condJSON == nil || string(condJSON) == "null" {
		condJSON = []byte("{}")
	}
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO zero_trust_policies (name, description, policy_type, conditions, action, priority, enabled, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		body.Name, body.Description, body.PolicyType, condJSON, body.Action, body.Priority, enabled, userIDStr,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "ポリシーを作成しました"})
}

// UpdatePolicy updates a policy.
// PUT /api/v1/zero-trust/policies/:id
func (h *ZeroTrustHandler) UpdatePolicy(c *gin.Context) {
	if !h.policyTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		PolicyType  string      `json:"policy_type"`
		Conditions  interface{} `json:"conditions"`
		Action      string      `json:"action"`
		Priority    int         `json:"priority"`
		Enabled     *bool       `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	if body.Action != "" && !validZTActions[body.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "actionはallow/deny/mfa_required/quarantineのいずれかを指定してください"})
		return
	}
	condJSON, _ := json.Marshal(body.Conditions)
	if condJSON == nil || string(condJSON) == "null" {
		condJSON = []byte("{}")
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE zero_trust_policies SET name=$1, description=$2, policy_type=$3, conditions=$4,
		                                action=$5, priority=$6, enabled=$7, updated_at=NOW()
		 WHERE id=$8`,
		body.Name, body.Description, body.PolicyType, condJSON,
		body.Action, body.Priority, body.Enabled, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ポリシーを更新しました"})
}

// DeletePolicy deletes a policy.
// DELETE /api/v1/zero-trust/policies/:id
func (h *ZeroTrustHandler) DeletePolicy(c *gin.Context) {
	if !h.policyTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM zero_trust_policies WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ポリシーを削除しました"})
}

// TogglePolicy flips the enabled state of a policy.
// POST /api/v1/zero-trust/policies/:id/toggle
func (h *ZeroTrustHandler) TogglePolicy(c *gin.Context) {
	if !h.policyTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	var enabled bool
	err := h.pool.QueryRow(ctx,
		`UPDATE zero_trust_policies SET enabled = NOT enabled, updated_at=NOW() WHERE id=$1 RETURNING enabled`, id,
	).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ポリシーの切り替えに失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}

// EvaluateAccess evaluates access against zero trust policies.
// POST /api/v1/zero-trust/evaluate
func (h *ZeroTrustHandler) EvaluateAccess(c *gin.Context) {
	var body struct {
		AgentID  string `json:"agent_id"`
		UserID   string `json:"user_id"`
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}

	ctx := c.Request.Context()

	decision := "allow"
	reason := "デフォルトポリシー: 許可"
	var matchedPolicyID *string
	riskScore := 0

	if h.policyTableExists(c) {
		// Run through policies in priority order
		rows, err := h.pool.Query(ctx,
			`SELECT id, action, name FROM zero_trust_policies WHERE enabled=TRUE ORDER BY priority ASC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var pid, paction, pname string
				if err := rows.Scan(&pid, &paction, &pname); err != nil {
					continue
				}
				// Simple matching: apply first enabled policy found
				// In production, conditions would be evaluated here
				decision = paction
				reason = "ポリシー '" + pname + "' に一致しました"
				matchedPolicyID = &pid
				switch paction {
				case "deny":
					riskScore = 80
				case "mfa_required":
					riskScore = 50
				case "quarantine":
					riskScore = 90
				default:
					riskScore = 10
				}
				break
			}
			if err := rows.Err(); err != nil {
				slog.Warn("row iteration error", "error", err)
			}
		}
	}

	// Log access decision
	if h.logTableExists(c) {
		agentIDPtr := &body.AgentID
		if body.AgentID == "" {
			agentIDPtr = nil
		}
		userIDPtr := &body.UserID
		if body.UserID == "" {
			userIDPtr = nil
		}
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO zero_trust_access_logs (policy_id, agent_id, user_id, resource, action, decision, reason, risk_score)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			matchedPolicyID, agentIDPtr, userIDPtr, body.Resource, body.Action, decision, reason, riskScore,
		); !WriteOK(c, err) {
			return
		}
		// Update match_count if policy matched
		if matchedPolicyID != nil {
			if _, err := h.pool.Exec(ctx,
				`UPDATE zero_trust_policies SET match_count = match_count + 1 WHERE id=$1`, *matchedPolicyID); !WriteOK(c, err) {
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"decision":          decision,
		"matched_policy_id": matchedPolicyID,
		"risk_score":        riskScore,
		"reason":            reason,
	})
}

// GetAccessLogs returns zero trust access logs.
// GET /api/v1/zero-trust/access-logs
func (h *ZeroTrustHandler) GetAccessLogs(c *gin.Context) {
	if !h.logTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"logs": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	agentID := c.Query("agent_id")
	decision := c.Query("decision")
	from := c.Query("from")
	to := c.Query("to")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	query := `SELECT id, policy_id, agent_id, user_id, resource, action, decision, reason, risk_score, logged_at
	          FROM zero_trust_access_logs WHERE 1=1`
	args := []interface{}{}
	i := 1
	if agentID != "" {
		query += ` AND agent_id=$` + strconv.Itoa(i)
		args = append(args, agentID)
		i++
	}
	if decision != "" {
		query += ` AND decision=$` + strconv.Itoa(i)
		args = append(args, decision)
		i++
	}
	if from != "" {
		query += ` AND logged_at >= $` + strconv.Itoa(i)
		args = append(args, from)
		i++
	}
	if to != "" {
		query += ` AND logged_at <= $` + strconv.Itoa(i)
		args = append(args, to)
		i++
	}
	query += ` ORDER BY logged_at DESC LIMIT $` + strconv.Itoa(i) + ` OFFSET $` + strconv.Itoa(i+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アクセスログの取得に失敗しました"})
		return
	}
	defer rows.Close()

	type accessLog struct {
		ID        string  `json:"id"`
		PolicyID  *string `json:"policy_id"`
		AgentID   *string `json:"agent_id"`
		UserID    *string `json:"user_id"`
		Resource  string  `json:"resource"`
		Action    string  `json:"action"`
		Decision  string  `json:"decision"`
		Reason    string  `json:"reason"`
		RiskScore int     `json:"risk_score"`
		LoggedAt  string  `json:"logged_at"`
	}

	var result []accessLog
	for rows.Next() {
		var al accessLog
		var loggedAt time.Time
		if err := rows.Scan(
			&al.ID, &al.PolicyID, &al.AgentID, &al.UserID,
			&al.Resource, &al.Action, &al.Decision, &al.Reason,
			&al.RiskScore, &loggedAt,
		); err != nil {
			continue
		}
		al.LoggedAt = loggedAt.Format(time.RFC3339)
		result = append(result, al)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アクセスログの取得に失敗しました"})
		return
	}
	if result == nil {
		result = []accessLog{}
	}
	c.JSON(http.StatusOK, gin.H{"logs": result, "total": len(result)})
}

// GetStats returns zero trust statistics.
// GET /api/v1/zero-trust/stats
func (h *ZeroTrustHandler) GetStats(c *gin.Context) {
	if !h.logTableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"allow_today":        0,
			"deny_today":         0,
			"mfa_today":          0,
			"top_denied":         []interface{}{},
			"top_flagged_agents": []interface{}{},
		})
		return
	}
	ctx := c.Request.Context()

	var allow, deny, mfa int
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT
			  COUNT(*) FILTER (WHERE decision='allow' AND logged_at >= NOW() - INTERVAL '1 day'),
			  COUNT(*) FILTER (WHERE decision='deny' AND logged_at >= NOW() - INTERVAL '1 day'),
			  COUNT(*) FILTER (WHERE decision='mfa_required' AND logged_at >= NOW() - INTERVAL '1 day')
			 FROM zero_trust_access_logs`).Scan(&allow, &deny, &mfa)) {
		return
	}

	// Top denied resources
	type resourceCount struct {
		Resource string `json:"resource"`
		Count    int    `json:"count"`
	}
	var topDenied []resourceCount
	deniedRows, err := h.pool.Query(ctx,
		`SELECT resource, COUNT(*) as cnt FROM zero_trust_access_logs
		 WHERE decision='deny' AND logged_at >= NOW() - INTERVAL '7 days'
		 GROUP BY resource ORDER BY cnt DESC LIMIT 10`)
	if !ReadOK(c, err) {
		return
	}
	if deniedRows != nil {
		defer deniedRows.Close()
		for deniedRows.Next() {
			var rc resourceCount
			if err := deniedRows.Scan(&rc.Resource, &rc.Count); err == nil {
				topDenied = append(topDenied, rc)
			}
		}
		if err := deniedRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if topDenied == nil {
		topDenied = []resourceCount{}
	}

	// Top flagged agents
	type agentCount struct {
		AgentID string `json:"agent_id"`
		Count   int    `json:"count"`
	}
	var topAgents []agentCount
	agentRows, err := h.pool.Query(ctx,
		`SELECT agent_id::TEXT, COUNT(*) as cnt FROM zero_trust_access_logs
		 WHERE decision IN ('deny','quarantine') AND agent_id IS NOT NULL AND logged_at >= NOW() - INTERVAL '7 days'
		 GROUP BY agent_id ORDER BY cnt DESC LIMIT 10`)
	if !ReadOK(c, err) {
		return
	}
	if agentRows != nil {
		defer agentRows.Close()
		for agentRows.Next() {
			var ac agentCount
			if err := agentRows.Scan(&ac.AgentID, &ac.Count); err == nil {
				topAgents = append(topAgents, ac)
			}
		}
		if err := agentRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if topAgents == nil {
		topAgents = []agentCount{}
	}

	c.JSON(http.StatusOK, gin.H{
		"allow_today":        allow,
		"deny_today":         deny,
		"mfa_today":          mfa,
		"top_denied":         topDenied,
		"top_flagged_agents": topAgents,
	})
}

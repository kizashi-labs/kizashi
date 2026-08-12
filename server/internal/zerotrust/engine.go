package zerotrust

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TrustLevel represents a Zero Trust access level
type TrustLevel string

const (
	TrustLevelHigh      TrustLevel = "high"      // score >= 80: full access
	TrustLevelMedium    TrustLevel = "medium"    // score 50-79: limited access
	TrustLevelLow       TrustLevel = "low"       // score 20-49: read only
	TrustLevelUntrusted TrustLevel = "untrusted" // score <20: blocked
)

// DevicePosture represents the current security posture of an endpoint
type DevicePosture struct {
	AgentID    string     `json:"agent_id"`
	Hostname   string     `json:"hostname"`
	TrustScore int        `json:"trust_score"` // 0-100
	TrustLevel TrustLevel `json:"trust_level"`
	LastSeen   time.Time  `json:"last_seen"`
	CheckedAt  time.Time  `json:"checked_at"`
	// Posture factors
	AgentHealthy     bool `json:"agent_healthy"`
	OSPatched        bool `json:"os_patched"`
	DiskEncrypted    bool `json:"disk_encrypted"`
	FirewallEnabled  bool `json:"firewall_enabled"`
	AVEnabled        bool `json:"av_enabled"`
	MFAEnabled       bool `json:"mfa_enabled"`
	NoActiveAlerts   bool `json:"no_active_alerts"`
	OnCorpNetwork    bool `json:"on_corp_network"`
	CompliancePassed bool `json:"compliance_passed"`
	// Penalties
	ActiveAlertCount  int `json:"active_alert_count"`
	DaysSinceLastSeen int `json:"days_since_last_seen"`
}

// PostureFactors are the weights for trust score calculation
type PostureFactors struct {
	AgentHealthy    int // +15
	OSPatched       int // +20
	DiskEncrypted   int // +15
	FirewallEnabled int // +10
	AVEnabled       int // +10
	MFAEnabled      int // +15
	NoAlerts        int // +10
	OnCorpNetwork   int // +5
	// Penalties per active alert: -5 each (max -30)
	AlertPenalty int
}

// ZeroTrustPolicy defines access control rules
type ZeroTrustPolicy struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Resource   string     `json:"resource"` // e.g., "admin", "reports", "api"
	MinTrust   TrustLevel `json:"min_trust"`
	RequireMFA bool       `json:"require_mfa"`
	Enabled    bool       `json:"enabled"`
}

// AccessDecision is the result of a policy check
type AccessDecision struct {
	Allowed    bool       `json:"allowed"`
	TrustLevel TrustLevel `json:"trust_level"`
	TrustScore int        `json:"trust_score"`
	Reason     string     `json:"reason"`
	RequireMFA bool       `json:"require_mfa"`
	CheckedAt  time.Time  `json:"checked_at"`
}

// Engine evaluates Zero Trust policies
type Engine struct {
	mu       sync.RWMutex
	postures map[string]*DevicePosture // agentID -> posture
	policies []ZeroTrustPolicy
	pool     *pgxpool.Pool
}

// NewEngine creates a new Zero Trust Engine
func NewEngine(pool *pgxpool.Pool) *Engine {
	e := &Engine{
		postures: make(map[string]*DevicePosture),
		pool:     pool,
	}
	e.policies = defaultPolicies()
	return e
}

// EvaluateDevice calculates and stores the trust score for an agent
func (e *Engine) EvaluateDevice(ctx context.Context, agentID string) (*DevicePosture, error) {
	posture, err := e.collectPosture(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("collect posture for %s: %w", agentID, err)
	}

	posture.TrustScore = e.calculateScore(posture)
	posture.TrustLevel = scoreToLevel(posture.TrustScore)
	posture.CheckedAt = time.Now()

	e.mu.Lock()
	e.postures[agentID] = posture
	e.mu.Unlock()

	return posture, nil
}

// CheckAccess evaluates whether a device should be granted access to a resource
func (e *Engine) CheckAccess(agentID, resource string) *AccessDecision {
	e.mu.RLock()
	posture, exists := e.postures[agentID]
	e.mu.RUnlock()

	if !exists {
		return &AccessDecision{
			Allowed:    false,
			TrustLevel: TrustLevelUntrusted,
			TrustScore: 0,
			Reason:     "デバイスポスチャが未評価です",
			CheckedAt:  time.Now(),
		}
	}

	e.mu.RLock()
	policies := make([]ZeroTrustPolicy, len(e.policies))
	copy(policies, e.policies)
	e.mu.RUnlock()

	for _, policy := range policies {
		if !policy.Enabled || policy.Resource != resource {
			continue
		}
		minScore := levelToMinScore(policy.MinTrust)
		if posture.TrustScore < minScore {
			return &AccessDecision{
				Allowed:    false,
				TrustLevel: posture.TrustLevel,
				TrustScore: posture.TrustScore,
				Reason:     fmt.Sprintf("トラストスコア不足 (%d < %d required for %s)", posture.TrustScore, minScore, resource),
				CheckedAt:  time.Now(),
			}
		}
		return &AccessDecision{
			Allowed:    true,
			TrustLevel: posture.TrustLevel,
			TrustScore: posture.TrustScore,
			RequireMFA: policy.RequireMFA && !posture.MFAEnabled,
			Reason:     "アクセス許可",
			CheckedAt:  time.Now(),
		}
	}

	// No matching policy: default allow if trust is high
	allowed := posture.TrustLevel == TrustLevelHigh || posture.TrustLevel == TrustLevelMedium
	reason := "デフォルトポリシー"
	if !allowed {
		reason = "トラストスコアが低すぎます"
	}
	return &AccessDecision{
		Allowed:    allowed,
		TrustLevel: posture.TrustLevel,
		TrustScore: posture.TrustScore,
		Reason:     reason,
		CheckedAt:  time.Now(),
	}
}

// GetAllPostures returns all cached device postures
func (e *Engine) GetAllPostures() []*DevicePosture {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*DevicePosture, 0, len(e.postures))
	for _, p := range e.postures {
		result = append(result, p)
	}
	return result
}

// GetPolicies returns the current Zero Trust policies
func (e *Engine) GetPolicies() []ZeroTrustPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policies
}

// UpdatePolicy adds or replaces a policy
func (e *Engine) UpdatePolicy(p ZeroTrustPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, existing := range e.policies {
		if existing.ID == p.ID {
			e.policies[i] = p
			return
		}
	}
	e.policies = append(e.policies, p)
}

// DeletePolicy removes a policy by ID
func (e *Engine) DeletePolicy(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, p := range e.policies {
		if p.ID == id {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return true
		}
	}
	return false
}

// collectPosture gathers device posture data from DB
func (e *Engine) collectPosture(ctx context.Context, agentID string) (*DevicePosture, error) {
	posture := &DevicePosture{AgentID: agentID}

	// Check agent health and basic info
	var hostname string
	var lastSeen time.Time
	var osVersion, agentVersion string
	err := e.pool.QueryRow(ctx, `
        SELECT COALESCE(hostname, ''), COALESCE(last_seen, NOW()),
               COALESCE(os_version, ''), COALESCE(agent_version, '')
        FROM agents WHERE id::text = $1
    `, agentID).Scan(&hostname, &lastSeen, &osVersion, &agentVersion)
	if err != nil {
		posture.Hostname = agentID
	} else {
		posture.Hostname = hostname
		posture.LastSeen = lastSeen
		posture.DaysSinceLastSeen = int(math.Round(time.Since(lastSeen).Hours() / 24))
		posture.AgentHealthy = agentVersion != "" && time.Since(lastSeen) < 24*time.Hour
	}

	// Check active alert count
	var alertCount int
	_ = e.pool.QueryRow(ctx, `
        SELECT COUNT(*) FROM alerts
        WHERE agent_id::text = $1 AND status = 'open' AND severity >= 7
    `, agentID).Scan(&alertCount)
	posture.ActiveAlertCount = alertCount
	posture.NoActiveAlerts = alertCount == 0

	// Check compliance data from DB (stored by compliance checker)
	var compliancePct float64
	err2 := e.pool.QueryRow(ctx, `
        SELECT COALESCE((value->>'score')::float, 0)
        FROM system_metadata WHERE key = 'compliance_score_' || $1
    `, agentID).Scan(&compliancePct)
	posture.CompliancePassed = err2 == nil && compliancePct >= 70

	// Determine posture from collected telemetry
	// In production these would come from agent health reports and MDM data
	posture.FirewallEnabled = posture.AgentHealthy
	posture.AVEnabled = posture.AgentHealthy
	posture.OSPatched = posture.DaysSinceLastSeen < 30
	posture.DiskEncrypted = posture.CompliancePassed
	posture.MFAEnabled = false    // would come from IdP integration
	posture.OnCorpNetwork = false // would come from network policy

	return posture, nil
}

func (e *Engine) calculateScore(p *DevicePosture) int {
	score := 0
	if p.AgentHealthy {
		score += 15
	}
	if p.OSPatched {
		score += 20
	}
	if p.DiskEncrypted {
		score += 15
	}
	if p.FirewallEnabled {
		score += 10
	}
	if p.AVEnabled {
		score += 10
	}
	if p.MFAEnabled {
		score += 15
	}
	if p.NoActiveAlerts {
		score += 10
	}
	if p.OnCorpNetwork {
		score += 5
	}
	// Alert penalty
	penalty := p.ActiveAlertCount * 5
	if penalty > 30 {
		penalty = 30
	}
	score -= penalty
	if score < 0 {
		score = 0
	}
	return score
}

func scoreToLevel(score int) TrustLevel {
	switch {
	case score >= 80:
		return TrustLevelHigh
	case score >= 50:
		return TrustLevelMedium
	case score >= 20:
		return TrustLevelLow
	default:
		return TrustLevelUntrusted
	}
}

func levelToMinScore(level TrustLevel) int {
	switch level {
	case TrustLevelHigh:
		return 80
	case TrustLevelMedium:
		return 50
	case TrustLevelLow:
		return 20
	default:
		return 0
	}
}

func defaultPolicies() []ZeroTrustPolicy {
	return []ZeroTrustPolicy{
		{ID: "zt-admin", Name: "管理者パネルアクセス", Resource: "admin", MinTrust: TrustLevelHigh, RequireMFA: true, Enabled: true},
		{ID: "zt-reports", Name: "レポートアクセス", Resource: "reports", MinTrust: TrustLevelMedium, RequireMFA: false, Enabled: true},
		{ID: "zt-api", Name: "APIアクセス", Resource: "api", MinTrust: TrustLevelMedium, RequireMFA: false, Enabled: true},
		{ID: "zt-live-response", Name: "ライブレスポンス", Resource: "live_response", MinTrust: TrustLevelHigh, RequireMFA: true, Enabled: true},
		{ID: "zt-forensics", Name: "フォレンジクス", Resource: "forensics", MinTrust: TrustLevelHigh, RequireMFA: true, Enabled: true},
	}
}

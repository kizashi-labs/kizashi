package xdr

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Domain represents a data source domain
type Domain string

const (
	DomainEndpoint Domain = "endpoint"
	DomainNetwork  Domain = "network"
	DomainCloud    Domain = "cloud"
	DomainIdentity Domain = "identity"
	DomainEmail    Domain = "email"
)

// XDREvent is a normalized event from any domain
type XDREvent struct {
	ID        string                 `json:"id"`
	Domain    Domain                 `json:"domain"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	AgentID   string                 `json:"agent_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	HostIP    string                 `json:"host_ip,omitempty"`
	Severity  int                    `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

// XDRIncident represents a correlated cross-domain incident
type XDRIncident struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	Severity      int        `json:"severity"`   // 0-100
	Confidence    int        `json:"confidence"` // 0-100
	Events        []XDREvent `json:"events"`
	Domains       []Domain   `json:"domains"`
	ATTACKTactics []string   `json:"attack_tactics"`
	CreatedAt     time.Time  `json:"created_at"`
	Status        string     `json:"status"` // open, investigating, resolved
}

// CorrelationRule defines a cross-domain correlation pattern
type CorrelationRule struct {
	ID          string
	Name        string
	Description string
	// RequiredDomains: all of these domains must have matching events
	RequiredDomains []Domain
	// TimeWindowMinutes: events must occur within this window
	TimeWindowMinutes int
	// Severity produced when rule matches
	Severity int
	// ATTACKTactics mapped
	ATTACKTactics []string
	// MatchFunc checks if a group of events matches the rule
	MatchFunc func(events []XDREvent) bool
}

// Engine performs cross-domain XDR correlation
type Engine struct {
	mu       sync.RWMutex
	rules    []CorrelationRule
	eventBuf []XDREvent // rolling buffer
	maxBuf   int
	pool     *pgxpool.Pool
}

// NewEngine creates a new XDR Engine with built-in rules
func NewEngine(pool *pgxpool.Pool) *Engine {
	e := &Engine{
		pool:   pool,
		maxBuf: 10000,
	}
	e.rules = builtinRules()
	return e
}

// IngestEvent adds an event to the XDR event buffer
func (e *Engine) IngestEvent(evt XDREvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.eventBuf = append(e.eventBuf, evt)
	if len(e.eventBuf) > e.maxBuf {
		// Drop oldest 10%
		e.eventBuf = e.eventBuf[e.maxBuf/10:]
	}
}

// Correlate runs all correlation rules against the event buffer
func (e *Engine) Correlate(ctx context.Context) ([]*XDRIncident, error) {
	e.mu.RLock()
	buf := make([]XDREvent, len(e.eventBuf))
	copy(buf, e.eventBuf)
	e.mu.RUnlock()

	var incidents []*XDRIncident
	now := time.Now()

	for _, rule := range e.rules {
		window := time.Duration(rule.TimeWindowMinutes) * time.Minute
		cutoff := now.Add(-window)

		// Filter events within window
		var windowEvents []XDREvent
		for _, evt := range buf {
			if evt.Timestamp.After(cutoff) {
				windowEvents = append(windowEvents, evt)
			}
		}

		// Check required domains are represented
		domainSet := map[Domain]bool{}
		for _, evt := range windowEvents {
			domainSet[evt.Domain] = true
		}
		allPresent := true
		for _, d := range rule.RequiredDomains {
			if !domainSet[d] {
				allPresent = false
				break
			}
		}
		if !allPresent {
			continue
		}

		// Run match function
		if rule.MatchFunc != nil && rule.MatchFunc(windowEvents) {
			incident := &XDRIncident{
				ID:            fmt.Sprintf("xdr-%s-%d", rule.ID, now.UnixNano()),
				Title:         rule.Name,
				Description:   rule.Description,
				Severity:      rule.Severity,
				Confidence:    75,
				Events:        windowEvents,
				Domains:       rule.RequiredDomains,
				ATTACKTactics: rule.ATTACKTactics,
				CreatedAt:     now,
				Status:        "open",
			}
			incidents = append(incidents, incident)
		}
	}
	return incidents, nil
}

// GetRecentEvents returns recent XDR events from the buffer
func (e *Engine) GetRecentEvents(limit int) []XDREvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.eventBuf) {
		limit = len(e.eventBuf)
	}
	result := make([]XDREvent, limit)
	copy(result, e.eventBuf[len(e.eventBuf)-limit:])
	return result
}

// Stats returns engine statistics
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	domainCounts := map[string]int{}
	for _, evt := range e.eventBuf {
		domainCounts[string(evt.Domain)]++
	}
	return map[string]interface{}{
		"buffered_events": len(e.eventBuf),
		"rules":           len(e.rules),
		"domain_counts":   domainCounts,
	}
}

// SeedFromDB populates the event buffer with recent data from the database.
// Called once at startup so domain coverage is non-empty from the first request.
func (e *Engine) SeedFromDB(ctx context.Context) {
	if e.pool == nil {
		return
	}

	// ── Endpoint events from alerts (last 24 h) ──────────────────────────
	alertRows, err := e.pool.Query(ctx, `
		SELECT id::text, COALESCE(agent_id::text,''), severity, title, created_at
		FROM alerts
		WHERE created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC
		LIMIT 500
	`)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var id, agentID, title string
			var sev int
			var ts time.Time
			if err2 := alertRows.Scan(&id, &agentID, &sev, &title, &ts); err2 != nil {
				continue
			}
			lowerTitle := strings.ToLower(title)
			domain := DomainEndpoint
			evtType := "alert"
			if strings.Contains(lowerTitle, "network") || strings.Contains(lowerTitle, "connection") ||
				strings.Contains(lowerTitle, "outbound") || strings.Contains(lowerTitle, "dns") {
				domain = DomainNetwork
				evtType = "outbound"
			} else if strings.Contains(lowerTitle, "cloud") || strings.Contains(lowerTitle, "s3") ||
				strings.Contains(lowerTitle, "aws") || strings.Contains(lowerTitle, "azure") {
				domain = DomainCloud
				evtType = "config_change"
			} else if strings.Contains(lowerTitle, "auth") || strings.Contains(lowerTitle, "login") ||
				strings.Contains(lowerTitle, "ldap") || strings.Contains(lowerTitle, "account") ||
				strings.Contains(lowerTitle, "password") || strings.Contains(lowerTitle, "credential") {
				domain = DomainIdentity
				evtType = "auth_anomaly"
			} else if strings.Contains(lowerTitle, "process") || strings.Contains(lowerTitle, "execution") ||
				strings.Contains(lowerTitle, "powershell") || strings.Contains(lowerTitle, "cmd") {
				evtType = "process"
			} else if strings.Contains(lowerTitle, "file") || strings.Contains(lowerTitle, "document") {
				evtType = "file"
			}
			e.IngestEvent(XDREvent{
				ID:        id,
				Domain:    domain,
				Type:      evtType,
				Timestamp: ts,
				AgentID:   agentID,
				Severity:  sev * 10, // alerts 1-10 → XDR 10-100
				Data:      map[string]interface{}{"title": title},
			})
		}
		if err := alertRows.Err(); err != nil {
			slog.Error("XDRシードのアラート走査が途中で終わりました。相関の対象から漏れるアラートがあります", "error", err)
		}
	}

	// ── Endpoint events from device_events (last 24 h) ──────────────────
	devRows, err := e.pool.Query(ctx, `
		-- device_type is nullable; scanning NULL into a string errors and the row
		-- is skipped, which would silently drop devices whose type the agent did
		-- not report — exactly the endpoint activity this dimension exists for.
		SELECT id::text, agent_id::text, COALESCE(device_type, ''), action, created_at
		FROM device_events
		WHERE created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC
		LIMIT 200
	`)
	if err == nil {
		defer devRows.Close()
		for devRows.Next() {
			var id, agentID, devType, action string
			var ts time.Time
			if err2 := devRows.Scan(&id, &agentID, &devType, &action, &ts); err2 != nil {
				continue
			}
			sev := 30
			if action == "connected" {
				sev = 50
			}
			e.IngestEvent(XDREvent{
				ID:        id,
				Domain:    DomainEndpoint,
				Type:      "device_" + action,
				Timestamp: ts,
				AgentID:   agentID,
				Severity:  sev,
				Data:      map[string]interface{}{"device_type": devType, "action": action},
			})
		}
		if err := devRows.Err(); err != nil {
			slog.Error("XDRシードのデバイスイベント走査が途中で終わりました。相関の対象から漏れるイベントがあります", "error", err)
		}
	}
}

// builtinRules returns the built-in XDR correlation rules
func builtinRules() []CorrelationRule {
	return []CorrelationRule{
		{
			ID:                "xdr-lateral-movement",
			Name:              "クロスドメイン横断的移動",
			Description:       "エンドポイントと認証ログの両方で横断的移動の痕跡が検出されました",
			RequiredDomains:   []Domain{DomainEndpoint, DomainIdentity},
			TimeWindowMinutes: 30,
			Severity:          85,
			ATTACKTactics:     []string{"Lateral Movement", "Credential Access"},
			MatchFunc: func(events []XDREvent) bool {
				hasEndpointAlert := false
				hasAuthAnomaly := false
				for _, e := range events {
					if e.Domain == DomainEndpoint && e.Severity >= 70 {
						hasEndpointAlert = true
					}
					if e.Domain == DomainIdentity && e.Type == "auth_anomaly" {
						hasAuthAnomaly = true
					}
				}
				return hasEndpointAlert && hasAuthAnomaly
			},
		},
		{
			ID:                "xdr-data-exfil",
			Name:              "クロスドメインデータ持ち出し",
			Description:       "エンドポイントの疑わしいファイルアクセスとネットワーク外部通信が検出されました",
			RequiredDomains:   []Domain{DomainEndpoint, DomainNetwork},
			TimeWindowMinutes: 15,
			Severity:          90,
			ATTACKTactics:     []string{"Exfiltration", "Collection"},
			MatchFunc: func(events []XDREvent) bool {
				hasFileAccess := false
				hasExternalConn := false
				for _, e := range events {
					if e.Domain == DomainEndpoint && e.Type == "file" && e.Severity >= 60 {
						hasFileAccess = true
					}
					if e.Domain == DomainNetwork && e.Type == "outbound" {
						if dst, ok := e.Data["dst_port"].(float64); ok && (dst == 443 || dst == 80 || dst == 22) {
							hasExternalConn = true
						}
					}
				}
				return hasFileAccess && hasExternalConn
			},
		},
		{
			ID:                "xdr-cloud-endpoint-compromise",
			Name:              "クラウド・エンドポイント連鎖攻撃",
			Description:       "クラウドリソースへの不正アクセスとエンドポイントへの悪意あるプロセス実行が検出されました",
			RequiredDomains:   []Domain{DomainEndpoint, DomainCloud},
			TimeWindowMinutes: 60,
			Severity:          95,
			ATTACKTactics:     []string{"Initial Access", "Execution", "Privilege Escalation"},
			MatchFunc: func(events []XDREvent) bool {
				hasEndpointHigh := false
				hasCloudAnomaly := false
				for _, e := range events {
					if e.Domain == DomainEndpoint && e.Severity >= 80 {
						hasEndpointHigh = true
					}
					if e.Domain == DomainCloud && (e.Type == "config_change" || e.Type == "privilege_escalation") {
						hasCloudAnomaly = true
					}
				}
				return hasEndpointHigh && hasCloudAnomaly
			},
		},
		{
			ID:                "xdr-identity-endpoint-chain",
			Name:              "認証侵害→エンドポイント侵害",
			Description:       "アカウント侵害後のエンドポイントへの不正アクセスが検出されました",
			RequiredDomains:   []Domain{DomainIdentity, DomainEndpoint},
			TimeWindowMinutes: 120,
			Severity:          88,
			ATTACKTactics:     []string{"Valid Accounts", "Persistence"},
			MatchFunc: func(events []XDREvent) bool {
				var compromisedUsers []string
				endpointUsers := map[string]bool{}
				for _, e := range events {
					if e.Domain == DomainIdentity && e.Type == "account_compromise" && e.UserID != "" {
						compromisedUsers = append(compromisedUsers, e.UserID)
					}
					if e.Domain == DomainEndpoint && e.UserID != "" {
						endpointUsers[e.UserID] = true
					}
				}
				for _, u := range compromisedUsers {
					if endpointUsers[u] {
						return true
					}
				}
				return false
			},
		},
		{
			ID:                "xdr-multi-domain-ransomware",
			Name:              "マルチドメインランサムウェア攻撃",
			Description:       "複数ドメインにわたるランサムウェアの兆候が検出されました",
			RequiredDomains:   []Domain{DomainEndpoint, DomainNetwork},
			TimeWindowMinutes: 20,
			Severity:          99,
			ATTACKTactics:     []string{"Impact", "Exfiltration", "Discovery"},
			MatchFunc: func(events []XDREvent) bool {
				massFileOps := 0
				c2Connections := 0
				for _, e := range events {
					if e.Domain == DomainEndpoint && e.Type == "file" {
						massFileOps++
					}
					if e.Domain == DomainNetwork && e.Severity >= 70 {
						c2Connections++
					}
				}
				return massFileOps >= 50 && c2Connections >= 3
			},
		},
	}
}

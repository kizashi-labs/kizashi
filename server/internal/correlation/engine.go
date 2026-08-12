// Package correlation provides an alert correlation engine that groups
// related security alerts into incidents based on configurable rules.
package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Condition is a single field comparison used within a CorrelationRule.
type Condition struct {
	Field    string `json:"field"`    // agent_id, event_type, severity, etc.
	Operator string `json:"operator"` // eq, contains, gte
	Value    string `json:"value"`
}

// CorrelationRule defines the parameters for grouping alerts into an incident.
type CorrelationRule struct {
	ID          string
	Name        string
	Description string
	EventTypes  []string // alert event types to watch
	Conditions  []Condition
	TimeWindow  time.Duration
	MinEvents   int
	Severity    int
	MITRETactic string
	MITRETech   string
}

// Incident is a correlated group of related alerts.
type Incident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    int       `json:"severity"`
	Status      string    `json:"status"` // open, investigating, resolved, closed
	AlertIDs    []string  `json:"alert_ids"`
	AgentIDs    []string  `json:"agent_ids"`
	MITRETactic string    `json:"mitre_tactic"`
	MITRETech   string    `json:"mitre_tech"`
	RuleID      string    `json:"correlation_rule_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CorrelationStats holds aggregate statistics for the correlation engine.
type CorrelationStats struct {
	TotalIncidents   int `json:"total_incidents"`
	OpenIncidents    int `json:"open_incidents"`
	RulesCount       int `json:"rules_count"`
	AlertsCorrelated int `json:"alerts_correlated"`
}

// alertEvent is an internal representation of a processed alert.
type alertEvent struct {
	AlertID   string
	AgentID   string
	EventType string
	// Subtypes are the correlation sub-type tokens derived from the alert's
	// MITRE technique and base event category (see DeriveEventSubtypes). Rule
	// EventTypes are matched against this set, not the bare base category.
	Subtypes []string
	Severity int
	Data     map[string]interface{}
	At       time.Time
}

// Engine correlates incoming alerts into incidents.
type Engine struct {
	pool      *pgxpool.Pool
	rules     []*CorrelationRule
	incidents []*Incident
	// sliding window of recent events per rule (rule_id -> []alertEvent)
	eventBuffer map[string][]alertEvent
	mu          sync.RWMutex

	totalCorrelated int
}

// NewEngine creates a new correlation Engine.
func NewEngine(pool *pgxpool.Pool) *Engine {
	return &Engine{
		pool:        pool,
		eventBuffer: make(map[string][]alertEvent),
	}
}

// AddRule adds a correlation rule to the engine.
func (e *Engine) AddRule(rule *CorrelationRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == rule.ID {
			e.rules[i] = rule
			return
		}
	}
	e.rules = append(e.rules, rule)
}

// ProcessAlert checks all rules against the incoming alert event and returns
// a new Incident if any rule's conditions and time-window threshold are met.
func (e *Engine) ProcessAlert(
	ctx context.Context,
	alertID, agentID, eventType, mitreTech string,
	severity int,
	data map[string]interface{},
) *Incident {
	event := alertEvent{
		AlertID:   alertID,
		AgentID:   agentID,
		EventType: eventType,
		Subtypes:  DeriveEventSubtypes(eventType, mitreTech, severity, data),
		Severity:  severity,
		Data:      data,
		At:        time.Now().UTC(),
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.rules {
		if !e.eventMatchesRule(event, rule) {
			continue
		}

		// Add to sliding window buffer for this rule
		buf := e.eventBuffer[rule.ID]
		buf = append(buf, event)

		// Prune events outside the time window
		cutoff := time.Now().UTC().Add(-rule.TimeWindow)
		pruned := buf[:0]
		for _, ev := range buf {
			if ev.At.After(cutoff) {
				pruned = append(pruned, ev)
			}
		}
		buf = pruned
		e.eventBuffer[rule.ID] = buf

		if len(buf) < rule.MinEvents {
			continue
		}

		// Check whether a matching incident is already open
		if e.hasOpenIncident(rule.ID) {
			// Append alert to existing incident
			e.appendAlertToIncident(rule.ID, alertID, agentID)
			continue
		}

		// Create a new incident
		incident := e.createIncident(rule, buf)
		e.incidents = append(e.incidents, incident)
		e.totalCorrelated += len(buf)

		// Persist to DB (best-effort)
		if e.pool != nil {
			go e.persistIncident(ctx, incident)
		}

		slog.Info("correlation: incident created",
			"incident_id", incident.ID,
			"rule", rule.Name,
			"alerts", len(incident.AlertIDs),
		)
		return incident
	}
	return nil
}

// GetIncidents returns stored incidents, querying DB when available.
func (e *Engine) GetIncidents(ctx context.Context, limit int) ([]*Incident, error) {
	if e.pool != nil {
		return e.fetchIncidentsFromDB(ctx, limit)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]*Incident, 0, len(e.incidents))
	for i := len(e.incidents) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.incidents[i])
	}
	return out, nil
}

// UpdateIncidentStatus updates the status field of an incident by ID.
func (e *Engine) UpdateIncidentStatus(id, status string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, inc := range e.incidents {
		if inc.ID == id {
			inc.Status = status
			inc.UpdatedAt = time.Now().UTC()
		}
	}
	if e.pool != nil {
		go func() {
			_, err := e.pool.Exec(context.Background(),
				`UPDATE incidents SET status=$1, updated_at=NOW() WHERE id=$2`,
				status, id,
			)
			if err != nil {
				slog.Warn("correlation: failed to update incident status in DB",
					"incident_id", id, "error", err)
			}
		}()
	}
}

// GetStats returns aggregate engine statistics.
func (e *Engine) GetStats() CorrelationStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	openCount := 0
	for _, inc := range e.incidents {
		if inc.Status == "open" || inc.Status == "investigating" {
			openCount++
		}
	}
	return CorrelationStats{
		TotalIncidents:   len(e.incidents),
		OpenIncidents:    openCount,
		RulesCount:       len(e.rules),
		AlertsCorrelated: e.totalCorrelated,
	}
}

// ListRules returns all correlation rules.
func (e *Engine) ListRules() []*CorrelationRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*CorrelationRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// GetIncidentByID returns a single incident by ID.
func (e *Engine) GetIncidentByID(id string) (*Incident, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, inc := range e.incidents {
		if inc.ID == id {
			return inc, true
		}
	}
	return nil, false
}

// --- internal helpers ---

func (e *Engine) eventMatchesRule(ev alertEvent, rule *CorrelationRule) bool {
	// Check event type filter. A rule matches when any of its EventTypes is the
	// alert's base category OR one of the derived correlation sub-types.
	if len(rule.EventTypes) > 0 {
		found := false
		for _, et := range rule.EventTypes {
			if strings.EqualFold(et, ev.EventType) || containsFold(ev.Subtypes, et) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check additional conditions
	for _, cond := range rule.Conditions {
		if !evalCondition(cond, ev) {
			return false
		}
	}
	return true
}

func evalCondition(c Condition, ev alertEvent) bool {
	// event_type is evaluated against the base category AND every derived
	// sub-type, so a rule condition like `event_type contains "credential"`
	// matches an alert whose sub-type is "credential_dump".
	if c.Field == "event_type" {
		candidates := append([]string{ev.EventType}, ev.Subtypes...)
		for _, cand := range candidates {
			if matchOp(c.Operator, cand, c.Value) {
				return true
			}
		}
		return false
	}

	var fieldVal string
	switch c.Field {
	case "agent_id":
		fieldVal = ev.AgentID
	case "severity":
		fieldVal = fmt.Sprintf("%d", ev.Severity)
	default:
		// Look in data map
		if ev.Data != nil {
			if v, ok := ev.Data[c.Field]; ok {
				fieldVal = fmt.Sprintf("%v", v)
			}
		}
	}

	return matchOp(c.Operator, fieldVal, c.Value)
}

// matchOp applies a single correlation operator to a field value.
func matchOp(op, fieldVal, want string) bool {
	switch op {
	case "eq":
		return strings.EqualFold(fieldVal, want)
	case "contains":
		return strings.Contains(strings.ToLower(fieldVal), strings.ToLower(want))
	case "gte":
		var fv, cv int
		_, _ = fmt.Sscanf(fieldVal, "%d", &fv)
		_, _ = fmt.Sscanf(want, "%d", &cv)
		return fv >= cv
	}
	return false
}

// containsFold reports whether want equals any element of list (case-insensitive).
func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func (e *Engine) hasOpenIncident(ruleID string) bool {
	for _, inc := range e.incidents {
		if inc.RuleID == ruleID && (inc.Status == "open" || inc.Status == "investigating") {
			return true
		}
	}
	return false
}

func (e *Engine) appendAlertToIncident(ruleID, alertID, agentID string) {
	for _, inc := range e.incidents {
		if inc.RuleID == ruleID && (inc.Status == "open" || inc.Status == "investigating") {
			inc.AlertIDs = appendUnique(inc.AlertIDs, alertID)
			inc.AgentIDs = appendUnique(inc.AgentIDs, agentID)
			inc.UpdatedAt = time.Now().UTC()
			e.totalCorrelated++
			return
		}
	}
}

func (e *Engine) createIncident(rule *CorrelationRule, events []alertEvent) *Incident {
	alertIDs := make([]string, 0, len(events))
	agentSet := map[string]struct{}{}
	for _, ev := range events {
		alertIDs = appendUnique(alertIDs, ev.AlertID)
		agentSet[ev.AgentID] = struct{}{}
	}
	agentIDs := make([]string, 0, len(agentSet))
	for aid := range agentSet {
		agentIDs = append(agentIDs, aid)
	}

	now := time.Now().UTC()
	return &Incident{
		ID:          uuid.New().String(),
		Title:       fmt.Sprintf("[%s] %s", rule.MITRETactic, rule.Name),
		Description: rule.Description,
		Severity:    rule.Severity,
		Status:      "open",
		AlertIDs:    alertIDs,
		AgentIDs:    agentIDs,
		MITRETactic: rule.MITRETactic,
		MITRETech:   rule.MITRETech,
		RuleID:      rule.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func (e *Engine) persistIncident(ctx context.Context, inc *Incident) {
	_, err := e.pool.Exec(ctx,
		`INSERT INTO incidents
		 (id, title, description, severity, status, alert_ids, agent_ids, mitre_tactic, mitre_tech, correlation_rule_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (id) DO NOTHING`,
		inc.ID, inc.Title, inc.Description, inc.Severity, inc.Status,
		inc.AlertIDs, inc.AgentIDs, inc.MITRETactic, inc.MITRETech, inc.RuleID,
	)
	if err != nil {
		slog.Warn("correlation: failed to persist incident", "incident_id", inc.ID, "error", err)
	}
}

func (e *Engine) fetchIncidentsFromDB(ctx context.Context, limit int) ([]*Incident, error) {
	// Check table existence for graceful degradation
	var exists bool
	_ = e.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='incidents')`,
	).Scan(&exists)
	if !exists {
		return e.localIncidents(limit), nil
	}

	if limit <= 0 {
		limit = 50
	}
	rows, err := e.pool.Query(ctx,
		`SELECT id, title, description, severity, status,
		        alert_ids, agent_ids, mitre_tactic, mitre_tech, correlation_rule_id,
		        created_at, updated_at
		 FROM incidents ORDER BY created_at DESC LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch incidents: %w", err)
	}
	defer rows.Close()

	var out []*Incident
	for rows.Next() {
		inc := &Incident{}
		var ruleID *string
		err := rows.Scan(
			&inc.ID, &inc.Title, &inc.Description, &inc.Severity, &inc.Status,
			&inc.AlertIDs, &inc.AgentIDs, &inc.MITRETactic, &inc.MITRETech, &ruleID,
			&inc.CreatedAt, &inc.UpdatedAt,
		)
		if err != nil {
			slog.Warn("correlation: failed to scan incident row", "error", err)
			continue
		}
		if ruleID != nil {
			inc.RuleID = *ruleID
		}
		out = append(out, inc)
	}
	return out, nil
}

func (e *Engine) localIncidents(limit int) []*Incident {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Incident, 0, limit)
	for i := len(e.incidents) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.incidents[i])
	}
	return out
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

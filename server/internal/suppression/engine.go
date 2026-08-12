// Package suppression manages alert suppression rules to reduce noise and false positives.
package suppression

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Condition defines a single matching condition for a suppression rule.
type Condition struct {
	Field    string `json:"field"`    // alert_type, agent_id, hostname, rule_name, severity, process_name
	Operator string `json:"operator"` // eq, contains, regex, lt, lte, gt, gte
	Value    string `json:"value"`
}

// SuppressionRule describes one suppression rule.
type SuppressionRule struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	Conditions  []Condition
	Duration    time.Duration // 0 = permanent
	ExpiresAt   *time.Time
	HitCount    int64
	CreatedAt   time.Time
}

// RuleHit pairs a rule name with its hit count for reporting.
type RuleHit struct {
	RuleName string `json:"rule_name"`
	HitCount int64  `json:"hit_count"`
}

// SuppressionStats summarises engine activity.
type SuppressionStats struct {
	TotalRules      int       `json:"total_rules"`
	ActiveRules     int       `json:"active_rules"`
	TotalSuppressed int64     `json:"total_suppressed"`
	TopRules        []RuleHit `json:"top_rules"`
}

// Engine holds all suppression rules and evaluates incoming alerts.
type Engine struct {
	mu              sync.RWMutex
	rules           []*SuppressionRule
	pool            *pgxpool.Pool
	totalSuppressed int64
}

// NewEngine creates a new Engine backed by the given pool.
func NewEngine(pool *pgxpool.Pool) *Engine {
	return &Engine{pool: pool}
}

// LoadFromDB loads all enabled suppression rules from the database.
// Silently returns nil if the table does not yet exist.
func (e *Engine) LoadFromDB(ctx context.Context) error {
	if e.pool == nil {
		return nil
	}

	rows, err := e.pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''), enabled, conditions,
		       COALESCE(duration_seconds,0), expires_at, hit_count, created_at
		FROM suppression_rules
		WHERE enabled = true
		ORDER BY created_at
	`)
	if err != nil {
		// Table may not exist yet — graceful degradation.
		slog.Debug("suppression: could not load rules from DB", "error", err)
		return nil
	}
	defer rows.Close()

	var loaded []*SuppressionRule
	for rows.Next() {
		var (
			r         SuppressionRule
			condJSON  []byte
			durationS int64
			expiresAt *time.Time
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Enabled,
			&condJSON, &durationS, &expiresAt, &r.HitCount, &r.CreatedAt); err != nil {
			continue
		}
		r.Duration = time.Duration(durationS) * time.Second
		r.ExpiresAt = expiresAt
		_ = json.Unmarshal(condJSON, &r.Conditions)
		loaded = append(loaded, &r)
	}

	e.mu.Lock()
	e.rules = loaded
	e.mu.Unlock()

	slog.Info("suppression: loaded rules from DB", "count", len(loaded))
	return nil
}

// ShouldSuppress returns (suppressed, rule_name) for the given alert map.
func (e *Engine) ShouldSuppress(alert map[string]interface{}) (bool, string) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	now := time.Now()
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if matchesAll(r.Conditions, alert) {
			atomic.AddInt64(&r.HitCount, 1)
			atomic.AddInt64(&e.totalSuppressed, 1)
			// Persist hit increment asynchronously.
			if e.pool != nil {
				go e.incrementHit(r.ID)
			}
			return true, r.Name
		}
	}
	return false, ""
}

func (e *Engine) incrementHit(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = e.pool.Exec(ctx,
		`UPDATE suppression_rules SET hit_count = hit_count + 1, updated_at = NOW() WHERE id = $1`, id)
}

// AddRule inserts a new rule into the engine and DB.
func (e *Engine) AddRule(rule *SuppressionRule) error {
	condJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}
	if e.pool == nil {
		e.mu.Lock()
		e.rules = append(e.rules, rule)
		e.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var durationS int64
	if rule.Duration > 0 {
		durationS = int64(rule.Duration.Seconds())
	}
	err = e.pool.QueryRow(ctx, `
		INSERT INTO suppression_rules (name, description, enabled, conditions, duration_seconds, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		rule.Name, rule.Description, rule.Enabled, condJSON, durationS, rule.ExpiresAt,
	).Scan(&rule.ID)
	if err != nil {
		return fmt.Errorf("insert suppression rule: %w", err)
	}
	e.mu.Lock()
	e.rules = append(e.rules, rule)
	e.mu.Unlock()
	return nil
}

// UpdateRule updates an existing rule by ID.
func (e *Engine) UpdateRule(id string, updated *SuppressionRule) error {
	condJSON, err := json.Marshal(updated.Conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}
	if e.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var durationS int64
		if updated.Duration > 0 {
			durationS = int64(updated.Duration.Seconds())
		}
		_, err = e.pool.Exec(ctx, `
			UPDATE suppression_rules
			SET name=$1, description=$2, enabled=$3, conditions=$4,
			    duration_seconds=$5, expires_at=$6, updated_at=NOW()
			WHERE id=$7`,
			updated.Name, updated.Description, updated.Enabled, condJSON,
			durationS, updated.ExpiresAt, id)
		if err != nil {
			return fmt.Errorf("update suppression rule: %w", err)
		}
	}
	e.mu.Lock()
	for i, r := range e.rules {
		if r.ID == id {
			updated.ID = id
			updated.HitCount = r.HitCount
			updated.CreatedAt = r.CreatedAt
			e.rules[i] = updated
			break
		}
	}
	e.mu.Unlock()
	return nil
}

// DeleteRule removes a rule by ID from the engine and DB.
func (e *Engine) DeleteRule(id string) error {
	if e.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := e.pool.Exec(ctx, `DELETE FROM suppression_rules WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("delete suppression rule: %w", err)
		}
	}
	e.mu.Lock()
	filtered := e.rules[:0]
	for _, r := range e.rules {
		if r.ID != id {
			filtered = append(filtered, r)
		}
	}
	e.rules = filtered
	e.mu.Unlock()
	return nil
}

// GetStats returns current suppression statistics.
func (e *Engine) GetStats() SuppressionStats {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	stats := SuppressionStats{
		TotalRules:      len(rules),
		TotalSuppressed: atomic.LoadInt64(&e.totalSuppressed),
	}
	for _, r := range rules {
		if r.Enabled {
			stats.ActiveRules++
		}
		if r.HitCount > 0 {
			stats.TopRules = append(stats.TopRules, RuleHit{
				RuleName: r.Name,
				HitCount: r.HitCount,
			})
		}
	}
	// Simple sort: bubble top 5 by hit count.
	for i := 0; i < len(stats.TopRules) && i < 5; i++ {
		for j := i + 1; j < len(stats.TopRules); j++ {
			if stats.TopRules[j].HitCount > stats.TopRules[i].HitCount {
				stats.TopRules[i], stats.TopRules[j] = stats.TopRules[j], stats.TopRules[i]
			}
		}
	}
	if len(stats.TopRules) > 5 {
		stats.TopRules = stats.TopRules[:5]
	}
	return stats
}

// GetRules returns a copy of all rules.
func (e *Engine) GetRules() []*SuppressionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*SuppressionRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// matchesAll checks that every condition matches the alert.
func matchesAll(conds []Condition, alert map[string]interface{}) bool {
	for _, c := range conds {
		val, ok := alertField(alert, c.Field)
		if !ok {
			return false
		}
		if !conditionMatches(c, val) {
			return false
		}
	}
	return len(conds) > 0
}

// alertField resolves a field name from the alert map (case-insensitive).
func alertField(alert map[string]interface{}, field string) (string, bool) {
	lower := strings.ToLower(field)
	for k, v := range alert {
		if strings.ToLower(k) == lower {
			return fmt.Sprintf("%v", v), true
		}
	}
	return "", false
}

// conditionMatches applies the condition operator.
func conditionMatches(c Condition, val string) bool {
	switch strings.ToLower(c.Operator) {
	case "eq":
		return strings.EqualFold(val, c.Value)
	case "contains":
		return strings.Contains(strings.ToLower(val), strings.ToLower(c.Value))
	case "regex":
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return false
		}
		return re.MatchString(val)
	case "lt":
		a, b := toFloat(val), toFloat(c.Value)
		return a < b
	case "lte":
		a, b := toFloat(val), toFloat(c.Value)
		return a <= b
	case "gt":
		a, b := toFloat(val), toFloat(c.Value)
		return a > b
	case "gte":
		a, b := toFloat(val), toFloat(c.Value)
		return a >= b
	default:
		return strings.EqualFold(val, c.Value)
	}
}

func toFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

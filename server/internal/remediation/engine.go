// Package remediation provides an auto-remediation engine that executes
// configurable actions in response to security alerts and incidents.
package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// RuleTrigger defines what events activate a RemediationRule.
type RuleTrigger struct {
	EventType   string            `json:"event_type"` // alert, incident
	MinSeverity int               `json:"min_severity"`
	Tags        []string          `json:"tags"`       // match any tag
	Conditions  map[string]string `json:"conditions"` // field:value pairs
}

// RemediationAction is a single remediation step to execute.
// Supported types: isolate_network, un_isolate_network, kill_process,
// quarantine_file, create_alert, notify, webhook.
type RemediationAction struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
	Delay  time.Duration     `json:"delay"`
}

// RemediationRule defines trigger conditions and the actions to take.
type RemediationRule struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Enabled  bool                `json:"enabled"`
	Trigger  RuleTrigger         `json:"trigger"`
	Actions  []RemediationAction `json:"actions"`
	Cooldown time.Duration       `json:"cooldown"`
	// RollbackTimeout, when >0 and the rule contains isolate_network, schedules
	// automatic un-isolation after this duration unless an analyst approves first.
	RollbackTimeout time.Duration `json:"rollback_timeout,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
}

// ActionResult records the outcome of a single action execution.
type ActionResult struct {
	ActionType string        `json:"action_type"`
	Success    bool          `json:"success"`
	Message    string        `json:"message"`
	Duration   time.Duration `json:"duration_ms"`
}

// ExecutionLog records a full rule execution event.
type ExecutionLog struct {
	ID               string         `json:"id"`
	RuleID           string         `json:"rule_id"`
	RuleName         string         `json:"rule_name"`
	TriggerID        string         `json:"trigger_id"` // alert/incident ID
	AgentID          string         `json:"agent_id"`
	Actions          []ActionResult `json:"actions"`
	Status           string         `json:"status"` // success, partial, failed
	ExecutedAt       time.Time      `json:"executed_at"`
	RollbackAt       *time.Time     `json:"rollback_at,omitempty"`
	RollbackApproved bool           `json:"rollback_approved"`
	RollbackDone     bool           `json:"rollback_done"`
}

// RemediationExclusion prevents auto-remediation on matching hosts.
type RemediationExclusion struct {
	ID              string    `json:"id"`
	HostnamePattern string    `json:"hostname_pattern"` // glob pattern, e.g. "dc-*", "prod-db-*"
	Reason          string    `json:"reason"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       string    `json:"created_by,omitempty"`
}

// rollbackEntry tracks a pending automatic rollback for an isolated agent.
type rollbackEntry struct {
	cancel      context.CancelFunc
	executionID string
	agentID     string
	scheduledAt time.Time
}

// Engine is the auto-remediation engine.
type Engine struct {
	pool       *pgxpool.Pool
	natsConn   *nats.Conn
	rules      []*RemediationRule
	logs       []ExecutionLog
	exclusions []RemediationExclusion
	// lastExec tracks last execution time per (rule, agent) to enforce cooldown.
	// Keyed per-agent — NOT per-rule-globally — so cooldown only throttles repeated
	// action on the SAME host. A rule-global cooldown would let the first isolated
	// host suppress isolation of every OTHER host for the cooldown window, which is
	// exactly wrong for a spreading attack (each host must be acted on).
	lastExec         map[string]time.Time
	pendingRollbacks sync.Map // key: executionID → *rollbackEntry
	mu               sync.RWMutex
}

// NewEngine creates a new remediation Engine.
func NewEngine(pool *pgxpool.Pool, natsConn *nats.Conn) *Engine {
	return &Engine{
		pool:     pool,
		natsConn: natsConn,
		lastExec: make(map[string]time.Time),
	}
}

// AddRule adds or replaces a remediation rule.
func (e *Engine) AddRule(rule *RemediationRule) {
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

// TriggerOnAlert evaluates all enabled rules against the incoming alert and
// cooldownKey builds the per-(rule, agent) key used to throttle repeated
// remediation on the same host without suppressing action on other hosts. The
// NUL separator can't appear in a UUID rule ID or agent ID, so keys never collide.
func cooldownKey(ruleID, agentID string) string {
	return ruleID + "\x00" + agentID
}

// executes actions for rules whose trigger conditions are satisfied.
// hostname is used for exclusion list matching; pass "" if unknown.
func (e *Engine) TriggerOnAlert(
	ctx context.Context,
	alertID, agentID, hostname string,
	severity int,
	tags []string,
) []ExecutionLog {
	if e.IsExcluded(hostname) {
		slog.Info("remediation: agent excluded from auto-remediation",
			"agent_id", agentID, "hostname", hostname)
		return nil
	}

	e.mu.Lock()
	rules := make([]*RemediationRule, len(e.rules))
	copy(rules, e.rules)
	e.mu.Unlock()

	var logs []ExecutionLog
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !e.triggerMatches(rule.Trigger, "alert", severity, tags) {
			continue
		}
		cdKey := cooldownKey(rule.ID, agentID)
		e.mu.RLock()
		last := e.lastExec[cdKey]
		e.mu.RUnlock()
		if rule.Cooldown > 0 && time.Since(last) < rule.Cooldown {
			slog.Debug("remediation: rule skipped (cooldown)", "rule_id", rule.ID, "agent_id", agentID)
			continue
		}

		log := e.executeRule(ctx, rule, alertID, agentID)
		logs = append(logs, log)

		e.mu.Lock()
		e.lastExec[cdKey] = time.Now()
		e.logs = append(e.logs, log)
		e.mu.Unlock()

		if e.pool != nil {
			go e.persistLog(context.Background(), log)
		}

		// Schedule rollback if rule has RollbackTimeout and isolation was performed
		if rule.RollbackTimeout > 0 && e.executionIsolated(log) {
			e.scheduleRollback(rule.RollbackTimeout, log.ID, agentID)
		}
	}
	return logs
}

// ApproveExecution cancels a pending automatic rollback for an execution.
// Returns true if a rollback was pending and successfully cancelled.
func (e *Engine) ApproveExecution(executionID string) bool {
	v, ok := e.pendingRollbacks.LoadAndDelete(executionID)
	if !ok {
		return false
	}
	entry := v.(*rollbackEntry)
	entry.cancel()

	// Mark as approved in in-memory log
	e.mu.Lock()
	for i, l := range e.logs {
		if l.ID == executionID {
			e.logs[i].RollbackApproved = true
			break
		}
	}
	e.mu.Unlock()

	slog.Info("remediation: rollback cancelled by analyst approval",
		"execution_id", executionID, "agent_id", entry.agentID)
	return true
}

// ListPendingRollbacks returns execution IDs with pending automatic rollbacks.
func (e *Engine) ListPendingRollbacks() []map[string]interface{} {
	var out []map[string]interface{}
	e.pendingRollbacks.Range(func(k, v interface{}) bool {
		entry := v.(*rollbackEntry)
		out = append(out, map[string]interface{}{
			"execution_id": entry.executionID,
			"agent_id":     entry.agentID,
			"scheduled_at": entry.scheduledAt,
		})
		return true
	})
	return out
}

// ─── Exclusion list ───────────────────────────────────────────────────────────

// LoadExclusionsFromDB reads all rows from remediation_exclusions and populates
// the in-memory list. Call once at startup after the DB is ready.
func (e *Engine) LoadExclusionsFromDB(ctx context.Context) error {
	if e.pool == nil {
		return nil
	}
	var exists bool
	_ = e.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='remediation_exclusions')`,
	).Scan(&exists)
	if !exists {
		return nil // migration not yet run
	}

	rows, err := e.pool.Query(ctx,
		`SELECT id::text, hostname_pattern, reason, created_by, created_at
		 FROM remediation_exclusions ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("remediation: failed to load exclusions: %w", err)
	}
	defer rows.Close()

	var loaded []RemediationExclusion
	for rows.Next() {
		var ex RemediationExclusion
		if err := rows.Scan(&ex.ID, &ex.HostnamePattern, &ex.Reason, &ex.CreatedBy, &ex.CreatedAt); err != nil {
			slog.Warn("remediation: failed to scan exclusion row", "error", err)
			continue
		}
		loaded = append(loaded, ex)
	}

	e.mu.Lock()
	e.exclusions = loaded
	e.mu.Unlock()

	slog.Info("remediation: 除外リストをDBから読み込みました", "count", len(loaded))
	return nil
}

// AddExclusion adds a hostname exclusion pattern (in-memory + DB if available).
func (e *Engine) AddExclusion(ex RemediationExclusion) {
	if ex.ID == "" {
		ex.ID = uuid.New().String()
	}
	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now().UTC()
	}
	e.mu.Lock()
	e.exclusions = append(e.exclusions, ex)
	e.mu.Unlock()

	if e.pool != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := e.pool.Exec(ctx,
				`INSERT INTO remediation_exclusions (id, hostname_pattern, reason, created_by, created_at)
				 VALUES ($1::uuid, $2, $3, $4, $5)
				 ON CONFLICT (hostname_pattern) DO UPDATE
				   SET reason = EXCLUDED.reason, created_by = EXCLUDED.created_by`,
				ex.ID, ex.HostnamePattern, ex.Reason, ex.CreatedBy, ex.CreatedAt,
			)
			if err != nil {
				slog.Warn("remediation: 除外リストのDB保存に失敗しました",
					"pattern", ex.HostnamePattern, "error", err)
			}
		}()
	}
}

// RemoveExclusion removes an exclusion by ID (in-memory + DB if available).
// Returns true if found and removed.
func (e *Engine) RemoveExclusion(id string) bool {
	e.mu.Lock()
	found := false
	for i, ex := range e.exclusions {
		if ex.ID == id {
			e.exclusions = append(e.exclusions[:i], e.exclusions[i+1:]...)
			found = true
			break
		}
	}
	e.mu.Unlock()

	if found && e.pool != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := e.pool.Exec(ctx,
				`DELETE FROM remediation_exclusions WHERE id = $1::uuid`, id,
			); err != nil {
				slog.Warn("remediation: 除外リストのDB削除に失敗しました",
					"id", id, "error", err)
			}
		}()
	}
	return found
}

// ListExclusions returns all current exclusions.
func (e *Engine) ListExclusions() []RemediationExclusion {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]RemediationExclusion, len(e.exclusions))
	copy(out, e.exclusions)
	return out
}

// IsExcluded returns true if hostname matches any exclusion pattern.
// Empty hostname never matches (pass the real hostname to benefit from exclusions).
func (e *Engine) IsExcluded(hostname string) bool {
	if hostname == "" {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ex := range e.exclusions {
		if matched, _ := filepath.Match(ex.HostnamePattern, hostname); matched {
			return true
		}
	}
	return false
}

// ─── Rule management ─────────────────────────────────────────────────────────

// GetRules returns all remediation rules.
func (e *Engine) GetRules() []*RemediationRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*RemediationRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// GetExecutionLogs returns recent execution logs from DB or in-memory.
func (e *Engine) GetExecutionLogs(ctx context.Context, limit int) ([]ExecutionLog, error) {
	if e.pool != nil {
		return e.fetchLogsFromDB(ctx, limit)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]ExecutionLog, 0, limit)
	for i := len(e.logs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.logs[i])
	}
	return out, nil
}

// EnableRule sets the enabled state of a rule by ID.
func (e *Engine) EnableRule(id string, enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rules {
		if r.ID == id {
			r.Enabled = enabled
			return
		}
	}
}

// GetRuleByID returns a rule by ID.
func (e *Engine) GetRuleByID(id string) (*RemediationRule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// DryRun simulates triggering all rules against a test event without executing actions.
func (e *Engine) DryRun(eventType string, severity int, tags []string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var matched []string
	for _, rule := range e.rules {
		if rule.Enabled && e.triggerMatches(rule.Trigger, eventType, severity, tags) {
			matched = append(matched, rule.Name)
		}
	}
	return matched
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (e *Engine) triggerMatches(trigger RuleTrigger, eventType string, severity int, tags []string) bool {
	if trigger.EventType != "" && !strings.EqualFold(trigger.EventType, eventType) {
		return false
	}
	if severity < trigger.MinSeverity {
		return false
	}
	if len(trigger.Tags) > 0 {
		matched := false
		for _, rt := range trigger.Tags {
			for _, at := range tags {
				if strings.EqualFold(rt, at) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (e *Engine) executeRule(ctx context.Context, rule *RemediationRule, triggerID, agentID string) ExecutionLog {
	start := time.Now()
	log := ExecutionLog{
		ID:         uuid.New().String(),
		RuleID:     rule.ID,
		RuleName:   rule.Name,
		TriggerID:  triggerID,
		AgentID:    agentID,
		ExecutedAt: start,
	}

	if rule.RollbackTimeout > 0 {
		rollbackAt := start.Add(rule.RollbackTimeout)
		log.RollbackAt = &rollbackAt
	}

	successCount := 0
	for _, action := range rule.Actions {
		if action.Delay > 0 {
			actionCopy := action
			go func() {
				select {
				case <-time.After(actionCopy.Delay):
					e.dispatchAction(ctx, actionCopy, agentID, triggerID)
				case <-ctx.Done():
					slog.Debug("remediation: delayed action cancelled", "action", actionCopy.Type, "agent_id", agentID)
				}
			}()
			log.Actions = append(log.Actions, ActionResult{
				ActionType: action.Type,
				Success:    true,
				Message:    fmt.Sprintf("scheduled with %s delay", action.Delay),
			})
			successCount++
			continue
		}

		result := e.dispatchAction(ctx, action, agentID, triggerID)
		log.Actions = append(log.Actions, result)
		if result.Success {
			successCount++
		}
	}

	switch {
	case successCount == len(rule.Actions):
		log.Status = "success"
	case successCount == 0:
		log.Status = "failed"
	default:
		log.Status = "partial"
	}

	slog.Info("remediation: rule executed",
		"rule", rule.Name, "agent_id", agentID, "status", log.Status)
	return log
}

func (e *Engine) dispatchAction(ctx context.Context, action RemediationAction, agentID, triggerID string) ActionResult {
	start := time.Now()
	result := ActionResult{ActionType: action.Type}

	switch action.Type {
	case "isolate_network":
		result.Success, result.Message = e.actionIsolateNetwork(ctx, agentID, triggerID)
	case "un_isolate_network":
		result.Success, result.Message = e.actionUnisolateNetwork(ctx, agentID, triggerID)
	case "kill_process":
		pid := action.Params["pid"]
		name := action.Params["process_name"]
		result.Success, result.Message = e.actionKillProcess(ctx, agentID, triggerID, pid, name)
	case "quarantine_file":
		path := action.Params["file_path"]
		result.Success, result.Message = e.actionQuarantineFile(ctx, agentID, triggerID, path)
	case "create_alert":
		title := action.Params["title"]
		if title == "" {
			title = "Auto-remediation triggered alert"
		}
		result.Success, result.Message = e.actionCreateAlert(ctx, agentID, triggerID, title)
	case "notify":
		msg := action.Params["message"]
		result.Success, result.Message = e.actionNotify(ctx, agentID, triggerID, msg)
	case "webhook":
		result.Success, result.Message = e.actionWebhook(ctx, action.Params, agentID, triggerID)
	default:
		result.Success = false
		result.Message = fmt.Sprintf("unknown action type: %s", action.Type)
	}

	result.Duration = time.Since(start)
	return result
}

func (e *Engine) actionIsolateNetwork(ctx context.Context, agentID, alertID string) (bool, string) {
	if e.natsConn == nil {
		return false, "NATS not available"
	}
	subject := fmt.Sprintf("commands.%s.isolate", agentID)
	payload, _ := json.Marshal(map[string]interface{}{
		"agent_id": agentID,
		"reason":   "auto-remediation",
		"alert_id": alertID,
	})
	if err := e.natsConn.Publish(subject, payload); err != nil {
		return false, fmt.Sprintf("NATS publish failed: %v", err)
	}
	return true, fmt.Sprintf("isolation command sent to agent %s", agentID)
}

// actionUnisolateNetwork sends an un-isolation command (used by auto-rollback).
func (e *Engine) actionUnisolateNetwork(ctx context.Context, agentID, alertID string) (bool, string) {
	if e.natsConn == nil {
		return false, "NATS not available"
	}
	subject := fmt.Sprintf("commands.%s.unisolate", agentID)
	payload, _ := json.Marshal(map[string]interface{}{
		"agent_id": agentID,
		"reason":   "auto-remediation rollback",
	})
	if err := e.natsConn.Publish(subject, payload); err != nil {
		return false, fmt.Sprintf("NATS publish failed: %v", err)
	}
	return true, fmt.Sprintf("un-isolation command sent to agent %s", agentID)
}

func (e *Engine) actionKillProcess(ctx context.Context, agentID, alertID, pid, name string) (bool, string) {
	if e.natsConn == nil {
		return false, "NATS not available"
	}
	pidNum, _ := strconv.ParseUint(pid, 10, 32)
	subject := fmt.Sprintf("commands.%s.kill_process", agentID)
	payload, _ := json.Marshal(map[string]interface{}{
		"agent_id": agentID,
		"pid":      uint32(pidNum),
		"reason":   fmt.Sprintf("auto-remediation (alert=%s process=%s)", alertID, name),
	})
	if err := e.natsConn.Publish(subject, payload); err != nil {
		return false, fmt.Sprintf("NATS publish failed: %v", err)
	}
	return true, fmt.Sprintf("kill process command sent (pid=%s name=%s)", pid, name)
}

func (e *Engine) actionQuarantineFile(ctx context.Context, agentID, alertID, filePath string) (bool, string) {
	if e.natsConn == nil {
		return false, "NATS not available"
	}
	subject := fmt.Sprintf("commands.%s.quarantine_file", agentID)
	payload, _ := json.Marshal(map[string]interface{}{
		"agent_id": agentID,
		"path":     filePath,
		"alert_id": alertID,
	})
	if err := e.natsConn.Publish(subject, payload); err != nil {
		return false, fmt.Sprintf("NATS publish failed: %v", err)
	}
	return true, fmt.Sprintf("quarantine command sent for %s", filePath)
}

func (e *Engine) actionCreateAlert(ctx context.Context, agentID, triggerID, title string) (bool, string) {
	if e.pool == nil {
		return true, "alert creation skipped (no DB)"
	}
	// alerts に type 列は無い(id/rule_id/agent_id/severity/status/title/
	// description/source/... )。以前は存在しない type 列を指定していて INSERT が
	// 42703 で常時失敗し、自動修復アクションのアラートが保存されていなかった。
	// 分類は source 列で表す。
	_, err := e.pool.Exec(ctx,
		`INSERT INTO alerts (agent_id, title, severity, status, source)
		 VALUES ($1::uuid, $2, 7, 'open', 'auto_remediation')
		 ON CONFLICT DO NOTHING`,
		agentID, title,
	)
	if err != nil {
		return false, fmt.Sprintf("DB insert failed: %v", err)
	}
	return true, "auto-remediation alert created"
}

func (e *Engine) actionNotify(ctx context.Context, agentID, triggerID, message string) (bool, string) {
	if e.natsConn == nil {
		slog.Info("remediation notify (no NATS)", "agent_id", agentID, "message", message)
		return true, "notification logged (NATS unavailable)"
	}
	payload := fmt.Sprintf(`{"type":"remediation_notify","agent_id":"%s","trigger_id":"%s","message":"%s"}`,
		agentID, triggerID, message)
	if err := e.natsConn.Publish("remediation.notifications", []byte(payload)); err != nil {
		return false, fmt.Sprintf("NATS publish failed: %v", err)
	}
	return true, "notification published"
}

// actionWebhook POSTs a JSON payload to the configured external URL.
// Required param: "url". Optional: "method" (default POST), "timeout_seconds" (default 10).
// The payload includes agent_id, trigger_id, timestamp, and any extra k/v in params.
func (e *Engine) actionWebhook(ctx context.Context, params map[string]string, agentID, triggerID string) (bool, string) {
	targetURL := params["url"]
	if targetURL == "" {
		return false, "webhook: url param is required"
	}

	method := params["method"]
	if method == "" {
		method = http.MethodPost
	}

	timeoutSec := 10
	if s := params["timeout_seconds"]; s != "" {
		var n int
		if cnt, _ := fmt.Sscanf(s, "%d", &n); cnt == 1 && n > 0 {
			timeoutSec = n
		}
	}

	body := map[string]interface{}{
		"agent_id":   agentID,
		"trigger_id": triggerID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"source":     "edr-remediation-engine",
	}
	for k, v := range params {
		if k != "url" && k != "method" && k != "timeout_seconds" {
			body[k] = v
		}
	}

	data, err := json.Marshal(body)
	if err != nil {
		return false, fmt.Sprintf("webhook: marshal failed: %v", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, targetURL, bytes.NewReader(data))
	if err != nil {
		return false, fmt.Sprintf("webhook: request creation failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-EDR-Source", "remediation-engine")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Sprintf("webhook: HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Sprintf("webhook: server returned HTTP %d", resp.StatusCode)
	}
	return true, fmt.Sprintf("webhook: delivered to %s (HTTP %d)", targetURL, resp.StatusCode)
}

// scheduleRollback starts a goroutine that auto-un-isolates an agent after timeout.
func (e *Engine) scheduleRollback(timeout time.Duration, executionID, agentID string) {
	rollbackCtx, cancel := context.WithCancel(context.Background())
	entry := &rollbackEntry{
		cancel:      cancel,
		executionID: executionID,
		agentID:     agentID,
		scheduledAt: time.Now().UTC(),
	}
	e.pendingRollbacks.Store(executionID, entry)

	go func() {
		select {
		case <-time.After(timeout):
			// Timeout expired without analyst approval → execute rollback
			e.pendingRollbacks.Delete(executionID)
			ok, msg := e.actionUnisolateNetwork(context.Background(), agentID, executionID)
			slog.Info("remediation: auto-rollback executed",
				"execution_id", executionID, "agent_id", agentID,
				"success", ok, "message", msg)

			// Mark rollback done in in-memory log
			e.mu.Lock()
			for i, l := range e.logs {
				if l.ID == executionID {
					e.logs[i].RollbackDone = true
					break
				}
			}
			e.mu.Unlock()

		case <-rollbackCtx.Done():
			// Analyst approved → rollback cancelled
		}
	}()

	slog.Info("remediation: rollback scheduled",
		"execution_id", executionID, "agent_id", agentID, "timeout", timeout)
}

// executionIsolated returns true if the log contains a successful isolate_network action.
func (e *Engine) executionIsolated(log ExecutionLog) bool {
	for _, a := range log.Actions {
		if a.ActionType == "isolate_network" && a.Success {
			return true
		}
	}
	return false
}

func (e *Engine) persistLog(ctx context.Context, log ExecutionLog) {
	var exists bool
	_ = e.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='remediation_logs')`,
	).Scan(&exists)
	if !exists {
		return
	}

	actionsJSON := buildActionsJSON(log.Actions)
	_, err := e.pool.Exec(ctx,
		`INSERT INTO remediation_logs
		 (id, rule_id, rule_name, trigger_id, agent_id, actions_result, status, executed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		log.ID, log.RuleID, log.RuleName, log.TriggerID,
		nullableUUID(log.AgentID), actionsJSON, log.Status, log.ExecutedAt,
	)
	if err != nil {
		slog.Warn("remediation: failed to persist log", "log_id", log.ID, "error", err)
	}
}

func (e *Engine) fetchLogsFromDB(ctx context.Context, limit int) ([]ExecutionLog, error) {
	var exists bool
	_ = e.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='remediation_logs')`,
	).Scan(&exists)
	if !exists {
		return e.localLogs(limit), nil
	}

	if limit <= 0 {
		limit = 50
	}
	rows, err := e.pool.Query(ctx,
		`SELECT id, rule_id, rule_name, trigger_id, COALESCE(agent_id::text,''), status, executed_at
		 FROM remediation_logs ORDER BY executed_at DESC LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remediation logs: %w", err)
	}
	defer rows.Close()

	var out []ExecutionLog
	for rows.Next() {
		var l ExecutionLog
		if err := rows.Scan(&l.ID, &l.RuleID, &l.RuleName, &l.TriggerID, &l.AgentID, &l.Status, &l.ExecutedAt); err != nil {
			slog.Warn("remediation: failed to scan log row", "error", err)
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

func (e *Engine) localLogs(limit int) []ExecutionLog {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]ExecutionLog, 0, limit)
	for i := len(e.logs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.logs[i])
	}
	return out
}

func buildActionsJSON(actions []ActionResult) string {
	if len(actions) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i, a := range actions {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(
			`{"action_type":%q,"success":%v,"message":%q}`,
			a.ActionType, a.Success, a.Message,
		))
	}
	sb.WriteString("]")
	return sb.String()
}

func nullableUUID(id string) interface{} {
	if id == "" {
		return nil
	}
	return id
}

// Package collector provides event collection components for the EDR agent.
// process_monitor.go implements process execution blocking by polling the running
// process list every 5 seconds and checking it against deny rules fetched from
// the EDR server. Matching processes trigger an alert event and, for "block" or
// "alert_and_block" actions, the process is forcibly terminated.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProcessBlockRule mirrors the server-side process_block_rules record.
type ProcessBlockRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ProcessName string `json:"process_name"` // exact name or glob (e.g. "cmd.exe", "pow*")
	RuleType    string `json:"rule_type"`    // "allow" | "deny"
	Action      string `json:"action"`       // "alert" | "block" | "alert_and_block"
	Enabled     bool   `json:"enabled"`
	Severity    string `json:"severity"`
}

// ProcessInfo holds information about a running process used for matching.
type ProcessInfo struct {
	PID  int
	Name string
}

// processListFn is the platform-specific function that returns running processes.
// It is set to defaultProcessList by default and can be replaced in tests.
var processListFn = defaultProcessList

// ProcessMonitor polls the running process list and enforces block rules fetched
// from the EDR server.
type ProcessMonitor struct {
	sender    EventSender
	agentID   string
	serverURL string

	mu    sync.RWMutex
	rules []ProcessBlockRule

	scanInterval    time.Duration
	refreshInterval time.Duration
}

// NewProcessMonitor creates a ProcessMonitor.
// scanInterval controls how often processes are scanned (default 5s).
// refreshInterval controls how often rules are re-fetched from the server (default 60s).
func NewProcessMonitor(sender EventSender, agentID, serverURL string, scanInterval, refreshInterval time.Duration) *ProcessMonitor {
	if scanInterval <= 0 {
		scanInterval = 5 * time.Second
	}
	if refreshInterval <= 0 {
		refreshInterval = 60 * time.Second
	}
	return &ProcessMonitor{
		sender:          sender,
		agentID:         agentID,
		serverURL:       serverURL,
		scanInterval:    scanInterval,
		refreshInterval: refreshInterval,
	}
}

// Run blocks until ctx is cancelled. It fetches rules immediately on start,
// then refreshes them every refreshInterval and scans processes every scanInterval.
func (m *ProcessMonitor) Run(ctx context.Context) {
	// Initial rule fetch — failure is non-fatal; we just start with no rules.
	if err := m.refreshRules(ctx); err != nil {
		slog.Warn("[process_monitor] 初回ルール取得失敗", "error", err)
	}

	scanTicker := time.NewTicker(m.scanInterval)
	refreshTicker := time.NewTicker(m.refreshInterval)
	defer scanTicker.Stop()
	defer refreshTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-refreshTicker.C:
			if err := m.refreshRules(ctx); err != nil {
				slog.Warn("[process_monitor] ルール更新失敗", "error", err)
			}
		case <-scanTicker.C:
			m.scan(ctx)
		}
	}
}

// FetchProcessBlockRules fetches the deny rules applicable to an agent from the
// server (GET /api/v1/process-rules/agent/:id). Exported so the Linux eBPF LSM
// prevention path (platform/linux, build tag "prevention") can reuse the same
// rule source as the polling path — see docs/design/Linux改ざん防止と実行前防御設計.md (Ph2).
func FetchProcessBlockRules(ctx context.Context, serverURL, agentID string) ([]ProcessBlockRule, error) {
	url := strings.TrimRight(serverURL, "/") + "/api/v1/process-rules/agent/" + agentID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var payload struct {
		Rules []ProcessBlockRule `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return payload.Rules, nil
}

// refreshRules fetches applicable rules from the server.
func (m *ProcessMonitor) refreshRules(ctx context.Context) error {
	rules, err := FetchProcessBlockRules(ctx, m.serverURL, m.agentID)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()

	slog.Debug("[process_monitor] ルール更新完了", "count", len(rules))
	return nil
}

// scan lists running processes and checks each against deny rules.
func (m *ProcessMonitor) scan(ctx context.Context) {
	m.mu.RLock()
	rules := make([]ProcessBlockRule, len(m.rules))
	copy(rules, m.rules)
	m.mu.RUnlock()

	if len(rules) == 0 {
		return
	}

	procs, err := processListFn()
	if err != nil {
		slog.Warn("[process_monitor] プロセスリスト取得失敗", "error", err)
		return
	}

	for _, proc := range procs {
		for _, rule := range rules {
			if rule.RuleType != "deny" {
				continue
			}
			if !matchProcessName(proc.Name, rule.ProcessName) {
				continue
			}
			m.handleMatch(ctx, proc, rule)
		}
	}
}

// handleMatch fires an alert and optionally kills the process.
func (m *ProcessMonitor) handleMatch(ctx context.Context, proc ProcessInfo, rule ProcessBlockRule) {
	action := rule.Action

	slog.Info("[process_monitor] 禁止プロセスを検出",
		"process", proc.Name,
		"pid", proc.PID,
		"rule", rule.Name,
		"action", action,
	)

	// Send alert event for "alert", "alert_and_block"
	if action == "alert" || action == "alert_and_block" {
		m.emitEvent(ctx, proc, rule)
	}

	// Kill process for "block", "alert_and_block"
	if action == "block" || action == "alert_and_block" {
		m.emitEvent(ctx, proc, rule) // also emit for block-only so it is recorded
		if err := killProcess(proc.PID); err != nil {
			slog.Warn("[process_monitor] プロセス終了失敗",
				"pid", proc.PID,
				"process", proc.Name,
				"error", err,
			)
		} else {
			slog.Info("[process_monitor] プロセスを終了しました",
				"pid", proc.PID,
				"process", proc.Name,
			)
		}
	}
}

// blockEventPayload is JSON-serialised into the event ID field.
type blockEventPayload struct {
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
	Action      string `json:"action"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
}

// BuildProcessBlockEvent encodes a process_block decision into an EventBatch
// using the same wire format as the polling path ("process_block:<uuid>:<json>"
// in the event ID). Exported so the Linux eBPF LSM prevention path can emit the
// same event type, making its decisions visible through the existing server-side
// process_block ingestion with no server changes (Ph2). Returns nil if the
// payload cannot be serialised.
func BuildProcessBlockEvent(agentID string, payload blockEventPayload) *v1.EventBatch {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[process_block] イベントのシリアライズ失敗", "error", err)
		return nil
	}

	// Encode as "process_block:<uuid>:<json>" into the ID field — same pattern
	// used by fim_collector.go and resource_collector.go.
	eventID := fmt.Sprintf("process_block:%s:%s", newEventID(), string(data))

	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}

// ProcessBlockPayload constructs the JSON payload carried by a process_block
// event. action is "alert"/"block"/"alert_and_block" for the polling path, or
// "audit" for an eBPF LSM audit-mode decision (reported but not blocked).
func ProcessBlockPayload(processName string, pid int, action, ruleID, ruleName, severity string) blockEventPayload {
	return blockEventPayload{
		ProcessName: processName,
		PID:         pid,
		Action:      action,
		RuleID:      ruleID,
		RuleName:    ruleName,
		Severity:    severity,
	}
}

// emitEvent sends a process_block event to the server.
func (m *ProcessMonitor) emitEvent(ctx context.Context, proc ProcessInfo, rule ProcessBlockRule) {
	batch := BuildProcessBlockEvent(m.agentID,
		ProcessBlockPayload(proc.Name, proc.PID, rule.Action, rule.ID, rule.Name, rule.Severity))
	if batch == nil {
		return
	}

	if err := m.sender.SendEvents(ctx, batch); err != nil {
		slog.Warn("[process_monitor] イベント送信失敗",
			"process", proc.Name,
			"pid", proc.PID,
			"error", err,
		)
	}
}

// killProcess terminates a process by PID using os.FindProcess + Kill.
// This is cross-platform: on Unix Kill sends SIGKILL; on Windows it calls
// TerminateProcess. No platform-specific imports are required.
func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	return p.Kill()
}

// matchProcessName reports whether procName matches the rule pattern.
// Pattern can be an exact name (case-insensitive) or a glob (e.g. "pow*").
func matchProcessName(procName, pattern string) bool {
	// Normalize to base name only for comparison.
	base := strings.ToLower(filepath.Base(procName))
	pat := strings.ToLower(pattern)

	// Try exact match first.
	if base == pat {
		return true
	}

	// Try glob match.
	matched, err := filepath.Match(pat, base)
	if err == nil && matched {
		return true
	}

	return false
}

// defaultProcessList returns the currently running processes using /proc on Linux
// and the toolhelp32 API on Windows. The implementation delegates to the
// platform-specific processListImpl function defined in per-OS files.
func defaultProcessList() ([]ProcessInfo, error) {
	return processListImpl()
}

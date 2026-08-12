package behavioral

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// kernelThreadPrefixes are well-known Linux kernel worker/daemon thread name
// prefixes. Their names carry dynamic suffixes — CPU id, worker id, workqueue
// name (kworker/u4:1, kworker/0:0-events, kworker/u4:0-ext4-rsv-, ...) — that
// change constantly, so each variant looks like a brand-new "process" to the
// per-agent baseline. Without this exclusion the baseline unknown-process
// detector emits a first-seen alert for every fresh suffix, flooding alerts
// with benign kernel activity (observed in prod: hundreds of thousands of
// "通常見られないプロセス: kworker/*" rows). These are kernel-managed and
// benign, so they are excluded from process-anomaly checks entirely.
var kernelThreadPrefixes = []string{
	"kworker/", "ksoftirqd/", "migration/", "rcu_", "kthreadd",
	"kswapd", "kcompactd", "ksmd", "khugepaged", "kintegrityd",
	"kblockd", "kdevtmpfs", "watchdog/", "irq/", "cpuhp/",
	"kauditd", "khungtaskd", "oom_reaper", "writeback", "kthrotld",
	"scsi_eh_", "scsi_tmf_", "jbd2/", "ext4-", "kdmflush",
	"nfsd", "lockd", "kverityd", "cryptd", "charger_manager",
}

// isLinuxKernelThread reports whether name is a Linux kernel worker/daemon
// thread. It tolerates the bracketed form (`[kworker/u4:1]`) used by ps-style
// listings before prefix matching against kernelThreadPrefixes.
func isLinuxKernelThread(name string) bool {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "[")
	name = strings.TrimSuffix(name, "]")
	if name == "" {
		return false
	}
	for _, p := range kernelThreadPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// suspiciousExecPrefixes are absolute-path directory prefixes that are classic
// malware staging / drop locations. A never-before-seen process is only worth a
// first-seen alert when it executes from one of these — a general-purpose Linux
// host legitimately spawns hundreds of distinct short-lived utilities (chmod, rm,
// bc, egrep, cron/motd scripts, sftp-server, …) that all live under the
// package-managed system directories (/usr, /bin, /sbin, /lib, /etc, /opt, …), so
// keying "unusual process" on first-seen NAME alone floods alerts with benign
// tooling (measured 2026-07-07: 771 distinct benign process names on 3 agents).
// A copy of any tool — even a renamed coreutil — dropped into one of these dirs
// is the real signal (observed here: /tmp/dropper, /tmp/xmrig, /tmp/…kworker
// masquerade). Non-system LOLBin *abuse* (e.g. `chmod +x /tmp/x`) is command-line
// shaped and stays the Sigma layer's job — this detector deliberately scopes to
// *location*, not name, so it never has to allowlist chmod/rm by name.
var suspiciousExecPrefixes = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/",
	"/home/", "/root/", "/mnt/", "/media/",
}

// suspiciousExecPrefixesWindows mirrors suspiciousExecPrefixes for Windows drop
// locations. Matched case-insensitively against a normalized (backslash→slash,
// lowercased) path so `C:\Users\x\AppData\Local\Temp\evil.exe` is caught.
var suspiciousExecPrefixesWindows = []string{
	"/appdata/local/temp/", "/appdata/roaming/", "/windows/temp/",
	"/users/public/", "/downloads/", "/programdata/", "/$recycle.bin/",
	"\\temp\\", // bare \Temp\ fallback for paths without a drive/users prefix
}

// isSuspiciousExecPath reports whether imagePath is an absolute executable path
// that resolves to a known malware-staging directory (see suspiciousExecPrefixes).
// It returns false for anything it cannot confidently place there — empty paths,
// bare comm names ("chmod", "runc"), truncated telemetry ("/usr/bin8"), container
// runtime artifacts ("/moby/<hash>/bin/sh", "/proc/self/fd/6") — because on this
// platform image_path is frequently unresolved and defaulting to *suppress* is
// what keeps the benign long-tail (and the kernel-thread firehose) silent.
func isSuspiciousExecPath(imagePath string) bool {
	p := strings.TrimSpace(imagePath)
	if p == "" {
		return false
	}
	// Windows: normalize drive-letter / UNC / any backslash path to lowercase
	// forward-slash before prefix matching.
	if (len(p) >= 2 && p[1] == ':') || strings.Contains(p, `\`) {
		w := strings.ToLower(strings.ReplaceAll(p, `\`, `/`))
		for _, pref := range suspiciousExecPrefixesWindows {
			needle := strings.ToLower(strings.ReplaceAll(pref, `\`, `/`))
			if strings.Contains(w, needle) {
				return true
			}
		}
		return false
	}
	// Linux/Unix: only consider genuinely absolute paths; a bare name or a
	// relative fragment tells us nothing about the execution location.
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, pref := range suspiciousExecPrefixes {
		if strings.HasPrefix(p, pref) {
			return true
		}
	}
	return false
}

// ActivityCategory represents a type of activity being baselined
type ActivityCategory string

const (
	CategoryProcess ActivityCategory = "process"
	CategoryNetwork ActivityCategory = "network"
	CategoryFile    ActivityCategory = "file"
	CategoryAuth    ActivityCategory = "auth"
	CategoryDNS     ActivityCategory = "dns"
)

// BaselineMetric holds statistical metrics for an activity
type BaselineMetric struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Count  int     `json:"count"`
}

// AgentBaseline stores the behavioral baseline for an agent
type AgentBaseline struct {
	AgentID   string                               `json:"agent_id"`
	Hostname  string                               `json:"hostname"`
	UpdatedAt time.Time                            `json:"updated_at"`
	Metrics   map[ActivityCategory]*BaselineMetric `json:"metrics"`
	// Typical processes: process_name -> freq (events/hour)
	TypicalProcesses map[string]float64 `json:"typical_processes"`
	// Typical domains: domain -> freq
	TypicalDomains map[string]float64 `json:"typical_domains"`
	// Typical ports: port -> freq
	TypicalPorts map[int]float64 `json:"typical_ports"`
}

// AnomalyEvent represents a behavioral anomaly
type AnomalyEvent struct {
	ID        string           `json:"id"`
	AgentID   string           `json:"agent_id"`
	Category  ActivityCategory `json:"category"`
	EventType string           `json:"event_type"`
	Score     float64          `json:"anomaly_score"` // 0.0-1.0 (1.0 = most anomalous)
	Detail    string           `json:"detail"`
	Timestamp time.Time        `json:"timestamp"`
	Severity  int              `json:"severity"` // 0-100
}

// Engine maintains behavioral baselines and detects anomalies
type Engine struct {
	mu        sync.RWMutex
	baselines map[string]*AgentBaseline // agentID -> baseline
	anomalies []AnomalyEvent
	pool      *pgxpool.Pool
}

// NewEngine creates a new behavioral Engine
func NewEngine(pool *pgxpool.Pool) *Engine {
	return &Engine{
		baselines: make(map[string]*AgentBaseline),
		pool:      pool,
	}
}

// BuildBaseline constructs a behavioral baseline for an agent from historical events
func (e *Engine) BuildBaseline(ctx context.Context, agentID string, lookbackDays int) (*AgentBaseline, error) {
	if lookbackDays <= 0 {
		lookbackDays = 14
	}
	since := time.Now().AddDate(0, 0, -lookbackDays)

	baseline := &AgentBaseline{
		AgentID:          agentID,
		UpdatedAt:        time.Now(),
		Metrics:          make(map[ActivityCategory]*BaselineMetric),
		TypicalProcesses: make(map[string]float64),
		TypicalDomains:   make(map[string]float64),
		TypicalPorts:     make(map[int]float64),
	}

	// Get hostname
	_ = e.pool.QueryRow(ctx,
		`SELECT COALESCE(hostname, $1) FROM agents WHERE id::text = $1`, agentID,
	).Scan(&baseline.Hostname)

	// Count events by category per hour
	rows, err := e.pool.Query(ctx, `
        SELECT event_type, COUNT(*) as cnt,
               date_trunc('hour', time) as hour
        FROM events
        WHERE agent_id::text = $1 AND time >= $2
        GROUP BY event_type, date_trunc('hour', time)
    `, agentID, since)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	categoryHourly := map[ActivityCategory][]float64{}
	for rows.Next() {
		var evtType string
		var cnt int
		var _ time.Time // hour (unused directly)
		if err := rows.Scan(&evtType, &cnt, new(time.Time)); err != nil {
			continue
		}
		cat := eventTypeToCategory(evtType)
		categoryHourly[cat] = append(categoryHourly[cat], float64(cnt))
	}

	for cat, samples := range categoryHourly {
		baseline.Metrics[cat] = computeMetric(samples)
	}

	// Build typical process list
	procRows, err := e.pool.Query(ctx, `
        SELECT raw_data->>'process_name' as pname, COUNT(*) as cnt
        FROM events
        WHERE agent_id::text = $1 AND event_type = 'process' AND time >= $2
          AND raw_data->>'process_name' IS NOT NULL
        GROUP BY raw_data->>'process_name'
        ORDER BY cnt DESC
        LIMIT 50
    `, agentID, since)
	if err == nil {
		defer procRows.Close()
		totalHours := float64(lookbackDays * 24)
		for procRows.Next() {
			var pname string
			var cnt int
			if err := procRows.Scan(&pname, &cnt); err == nil && pname != "" &&
				!isLinuxKernelThread(pname) {
				// Skip kernel threads: their dynamic suffixes would otherwise
				// crowd out real userspace processes from the top-50 baseline.
				baseline.TypicalProcesses[pname] = float64(cnt) / totalHours
			}
		}
	}

	// Build typical DNS domains
	dnsRows, err := e.pool.Query(ctx, `
        SELECT raw_data->>'domain' as domain, COUNT(*) as cnt
        FROM events
        WHERE agent_id::text = $1 AND event_type = 'dns' AND time >= $2
          AND raw_data->>'domain' IS NOT NULL
        GROUP BY raw_data->>'domain'
        ORDER BY cnt DESC
        LIMIT 100
    `, agentID, since)
	if err == nil {
		defer dnsRows.Close()
		totalHours := float64(lookbackDays * 24)
		for dnsRows.Next() {
			var domain string
			var cnt int
			if err := dnsRows.Scan(&domain, &cnt); err == nil && domain != "" {
				baseline.TypicalDomains[domain] = float64(cnt) / totalHours
			}
		}
	}

	e.mu.Lock()
	e.baselines[agentID] = baseline
	e.mu.Unlock()

	return baseline, nil
}

// DetectAnomaly compares current activity against the baseline
func (e *Engine) DetectAnomaly(agentID, eventType string, currentHourlyCount float64, details map[string]interface{}) *AnomalyEvent {
	e.mu.RLock()
	baseline, ok := e.baselines[agentID]
	e.mu.RUnlock()
	if !ok {
		return nil
	}

	cat := eventTypeToCategory(eventType)
	metric, ok := baseline.Metrics[cat]
	if !ok || metric.Count < 10 {
		return nil // Not enough baseline data
	}

	// Z-score based anomaly detection
	zscore := 0.0
	if metric.StdDev > 0 {
		zscore = (currentHourlyCount - metric.Mean) / metric.StdDev
	}

	// Only flag positive anomalies (more than normal)
	if zscore < 3.0 {
		return nil
	}

	// Normalize to 0-1 score
	anomalyScore := math.Min(1.0, (zscore-3.0)/7.0)
	severity := int(anomalyScore*80) + 20

	detail := fmt.Sprintf("%s活動が通常の%.1f倍 (現在: %.0f/h, 平均: %.1f/h, σ=%.1f)",
		cat, currentHourlyCount/metric.Mean, currentHourlyCount, metric.Mean, metric.StdDev)

	id := fmt.Sprintf("ba-%s-%d", agentID[:min8(len(agentID))], time.Now().UnixNano())
	anomaly := &AnomalyEvent{
		ID:        id,
		AgentID:   agentID,
		Category:  cat,
		EventType: eventType,
		Score:     anomalyScore,
		Detail:    detail,
		Timestamp: time.Now(),
		Severity:  severity,
	}

	e.mu.Lock()
	e.anomalies = append(e.anomalies, *anomaly)
	if len(e.anomalies) > 1000 {
		e.anomalies = e.anomalies[100:]
	}
	e.mu.Unlock()

	return anomaly
}

// CheckProcessAnomaly checks if a process is unusual for an agent. processName is
// the observed process name (Linux comm — note the kernel truncates it to 15
// bytes, e.g. "landscape-sysin", "92-unattended-u", so it is NOT a reliable
// identity on its own); imagePath is the resolved executable path from the same
// event and is what actually drives the decision.
//
// It fires only when a never-before-seen process executes from a suspicious
// staging directory (isSuspiciousExecPath). First-seen by name alone is not a
// usable signal on a general-purpose host: legitimate short-lived userland tools
// (chmod/rm/bc/egrep/cron & motd scripts/sftp-server/…) form an unbounded long
// tail under the package-managed system dirs, and the top-50 TypicalProcesses
// baseline can never enumerate them. Scoping to *where* the binary runs from —
// rather than allowlisting benign names, which we cannot do without blinding
// ourselves to LOLBin abuse — kills that tail while still catching dropped/staged
// payloads (a copy of chmod in /tmp, a kworker-named binary under /tmp, …).
func (e *Engine) CheckProcessAnomaly(agentID, processName, imagePath string) *AnomalyEvent {
	e.mu.RLock()
	baseline, ok := e.baselines[agentID]
	e.mu.RUnlock()
	if !ok {
		return nil
	}

	if _, known := baseline.TypicalProcesses[processName]; known {
		return nil
	}
	// Linux kernel threads (kworker/*, ksoftirqd/*, rcu_*, ...) carry dynamic
	// suffixes that never stabilize in the baseline, so every fresh suffix would
	// otherwise be flagged first-seen. They are kernel-managed and benign.
	if isLinuxKernelThread(processName) {
		return nil
	}
	if len(baseline.TypicalProcesses) < 5 {
		return nil // Not enough baseline
	}
	// Location gate: a first-seen process is only anomalous when it runs from a
	// classic drop/staging directory. Everything executing from a system path
	// (or whose path we can't resolve) is treated as benign tooling. This is the
	// core FP suppression — without it a multi-purpose Linux host floods alerts
	// with benign coreutils/cron/motd tooling (measured: 771 distinct names).
	if !isSuspiciousExecPath(imagePath) {
		return nil
	}

	// Prefer the resolved image path in the detail — the *location* is the signal,
	// and the raw comm is truncated to 15 bytes so the path is more informative.
	shown := processName
	if imagePath != "" {
		shown = imagePath
	}
	id := fmt.Sprintf("ba-proc-%s-%d", agentID[:min8(len(agentID))], time.Now().UnixNano())
	return &AnomalyEvent{
		ID:        id,
		AgentID:   agentID,
		Category:  CategoryProcess,
		EventType: "process",
		Score:     0.7,
		Detail:    fmt.Sprintf("未知のプロセスが不審な場所から実行: %s (ベースライン未登録・実行元=%s)", processName, shown),
		Timestamp: time.Now(),
		Severity:  65,
	}
}

// GetBaseline returns the baseline for an agent
func (e *Engine) GetBaseline(agentID string) (*AgentBaseline, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, ok := e.baselines[agentID]
	return b, ok
}

// GetAllBaselines returns all baselines
func (e *Engine) GetAllBaselines() []*AgentBaseline {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*AgentBaseline, 0, len(e.baselines))
	for _, b := range e.baselines {
		result = append(result, b)
	}
	return result
}

// GetRecentAnomalies returns recent anomaly events
func (e *Engine) GetRecentAnomalies(limit int) []AnomalyEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.anomalies) {
		limit = len(e.anomalies)
	}
	start := len(e.anomalies) - limit
	if start < 0 {
		start = 0
	}
	result := make([]AnomalyEvent, len(e.anomalies)-start)
	copy(result, e.anomalies[start:])
	return result
}

func eventTypeToCategory(evtType string) ActivityCategory {
	switch evtType {
	case "process":
		return CategoryProcess
	case "network":
		return CategoryNetwork
	case "file":
		return CategoryFile
	case "auth":
		return CategoryAuth
	case "dns":
		return CategoryDNS
	default:
		return CategoryProcess
	}
}

func computeMetric(samples []float64) *BaselineMetric {
	if len(samples) == 0 {
		return &BaselineMetric{}
	}
	sum := 0.0
	minVal := samples[0]
	maxVal := samples[0]
	for _, s := range samples {
		sum += s
		if s < minVal {
			minVal = s
		}
		if s > maxVal {
			maxVal = s
		}
	}
	mean := sum / float64(len(samples))
	variance := 0.0
	for _, s := range samples {
		diff := s - mean
		variance += diff * diff
	}
	variance /= float64(len(samples))
	return &BaselineMetric{
		Mean:   mean,
		StdDev: math.Sqrt(variance),
		Min:    minVal,
		Max:    maxVal,
		Count:  len(samples),
	}
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}

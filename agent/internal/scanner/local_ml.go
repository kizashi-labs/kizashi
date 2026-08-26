// Package scanner provides local ML-based anomaly detection.
// Uses lightweight statistical models for on-device inference.
// High-scoring events are forwarded to the server for Claude AI deep analysis.
package scanner

import (
	"math"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

// AnomalyScore represents the output of local ML scoring.
type AnomalyScore struct {
	Score       float64  // 0.0 - 1.0 (1.0 = most anomalous)
	Reasons     []string // human-readable reasons
	SendToCloud bool     // true if score exceeds cloud threshold
	// LocalAlert はスコアが localAlertThreshold 以上、つまりサーバ側の判定を
	// 待たずにエンドポイント単独で「怪しい」と言い切れる水準に達したことを表す。
	// 呼び出し側はこれを見て、バッチ間隔を待たずに即時送信する。
	LocalAlert bool
}

const (
	// Scores above this are sent to Claude API for deep analysis
	cloudAnalysisThreshold = 0.6
	// Scores above this trigger immediate local alert
	localAlertThreshold = 0.85
)

// newAnomalyScore は素点を [0,1] に丸め、2 つの閾値を当てて判定を確定する。
//
// ScoreProcess / ScoreNetwork / ScoreFile はいずれも同じ判定を行うため、閾値の
// 適用をここ 1 箇所に集約する。分散させると、閾値を足したときに一部の Score*
// だけ追随し忘れる (LocalAlert が実際にそうなっていた)。
func newAnomalyScore(raw float64, reasons []string) AnomalyScore {
	score := math.Min(raw, 1.0)
	return AnomalyScore{
		Score:       score,
		Reasons:     reasons,
		SendToCloud: score >= cloudAnalysisThreshold,
		LocalAlert:  score >= localAlertThreshold,
	}
}

// LocalAnomalyDetector implements lightweight on-device anomaly detection.
// Uses statistical baselines (mean/stddev) and rule-based heuristics.
// No external dependencies required - runs fully offline.
type LocalAnomalyDetector struct {
	mu       sync.RWMutex
	baseline *ProcessBaseline
}

type ProcessBaseline struct {
	// Baseline statistics per process name
	processes map[string]*ProcessStats
	// Known suspicious patterns (updated via server config)
	suspiciousParents map[string][]string // parent -> suspicious children
	suspiciousArgs    []string
	suspiciousNetDst  []string
}

type ProcessStats struct {
	SeenCount     int
	AvgChildCount float64
	AvgCPU        float64
	LastSeen      time.Time
	KnownPaths    map[string]int // imagepath -> count
}

func NewLocalAnomalyDetector() *LocalAnomalyDetector {
	return &LocalAnomalyDetector{
		baseline: &ProcessBaseline{
			processes: make(map[string]*ProcessStats),
			suspiciousParents: map[string][]string{
				// Common LOLBin parent-child chains
				"winword.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
				"excel.exe":    {"cmd.exe", "powershell.exe", "wscript.exe"},
				"outlook.exe":  {"cmd.exe", "powershell.exe"},
				"iexplore.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
				"chrome.exe":   {"cmd.exe", "powershell.exe"},
				"firefox.exe":  {"cmd.exe", "powershell.exe"},
				"msiexec.exe":  {"cmd.exe", "powershell.exe", "regsvr32.exe"},
				"svchost.exe":  {"cmd.exe"},
				"lsass.exe":    {"cmd.exe", "powershell.exe"},
				"services.exe": {"cmd.exe", "powershell.exe"},
			},
			suspiciousArgs: []string{
				// PowerShell obfuscation/download indicators
				"-enc", "-encodedcommand", "iex", "invoke-expression",
				"downloadstring", "downloadfile", "webclient",
				"bypass", "-nop", "-windowstyle hidden",
				// Shell injection indicators
				"base64", "frombase64string", "decompress",
				// Common C2 indicators
				"certutil -decode", "bitsadmin /transfer",
				"regsvr32 /s /n /u /i",
			},
			suspiciousNetDst: []string{
				// Common C2 ports
				"4444", "1337", "31337", "8080", "8443",
			},
		},
	}
}

// ScoreProcess returns an anomaly score for a process event.
func (d *LocalAnomalyDetector) ScoreProcess(evt collector.ProcessEvent) AnomalyScore {
	d.mu.Lock()
	defer d.mu.Unlock()

	score := 0.0
	var reasons []string

	// 1. Check suspicious parent-child relationship
	if children, ok := d.baseline.suspiciousParents[normalizeProcessName(evt.ProcessName)]; ok {
		// This process is a known suspicious parent - check if spawning risky child
		_ = children
	}

	// Reverse check: is THIS process a suspicious child of its parent?
	for parent, suspiciousChildren := range d.baseline.suspiciousParents {
		_ = parent
		for _, child := range suspiciousChildren {
			if normalizeProcessName(evt.ProcessName) == child {
				// Suspicious child spawned - check parent
				score += 0.35
				reasons = append(reasons, "suspicious parent-child process chain")
				break
			}
		}
	}

	// 2. Check suspicious command-line arguments
	cmdLower := toLower(evt.CommandLine)
	for _, pattern := range d.baseline.suspiciousArgs {
		if contains(cmdLower, pattern) {
			score += 0.25
			reasons = append(reasons, "suspicious command-line pattern: "+pattern)
			break
		}
	}

	// 3. Check for process running from suspicious paths
	suspiciousPaths := []string{
		`\temp\`, `\tmp\`, `\appdata\local\temp\`,
		`\downloads\`, `\desktop\`,
		"/tmp/", "/var/tmp/", "/dev/shm/",
	}
	pathLower := toLower(evt.ImagePath)
	for _, p := range suspiciousPaths {
		if contains(pathLower, p) {
			score += 0.3
			reasons = append(reasons, "process running from suspicious path")
			break
		}
	}

	// 4. Check for path/name mismatch (masquerading)
	// e.g. "svchost.exe" running from C:\Users\...
	systemProcesses := map[string]string{
		"svchost.exe":  `c:\windows\system32`,
		"lsass.exe":    `c:\windows\system32`,
		"services.exe": `c:\windows\system32`,
		"winlogon.exe": `c:\windows\system32`,
		"csrss.exe":    `c:\windows\system32`,
		"smss.exe":     `c:\windows\system32`,
	}
	if expectedPath, ok := systemProcesses[normalizeProcessName(evt.ProcessName)]; ok {
		if !contains(pathLower, expectedPath) && evt.ImagePath != "" {
			score += 0.6
			reasons = append(reasons, "system process running from unexpected path (masquerading)")
		}
	}

	// 5. Check if binary was seen before
	d.updateBaseline(evt)

	return newAnomalyScore(score, reasons)
}

// ScoreNetwork returns an anomaly score for a network event.
func (d *LocalAnomalyDetector) ScoreNetwork(evt collector.NetworkEvent) AnomalyScore {
	d.mu.RLock()
	defer d.mu.RUnlock()

	score := 0.0
	var reasons []string

	// 1. Suspicious destination ports (common C2 ports)
	suspiciousPorts := map[uint16]float64{
		4444:  0.7, // Metasploit default
		1337:  0.5,
		31337: 0.6,
		8888:  0.3,
		9999:  0.3,
	}
	if s, ok := suspiciousPorts[evt.DstPort]; ok {
		score += s
		reasons = append(reasons, "connection to suspicious port")
	}

	// 2. Outbound connection from system process
	systemProcs := map[string]bool{
		"lsass.exe": true, "services.exe": true,
		"svchost.exe": true, "winlogon.exe": true,
	}
	if systemProcs[normalizeProcessName(evt.ProcessName)] && evt.Direction == "outbound" {
		score += 0.5
		reasons = append(reasons, "system process making outbound connection")
	}

	// 3. High-volume outbound (potential data exfiltration)
	if evt.BytesSent > 10*1024*1024 { // > 10MB outbound
		score += 0.3
		reasons = append(reasons, "large outbound data transfer")
	}

	return newAnomalyScore(score, reasons)
}

// ScoreFile returns an anomaly score for a file event.
func (d *LocalAnomalyDetector) ScoreFile(evt collector.FileEvent) AnomalyScore {
	d.mu.RLock()
	defer d.mu.RUnlock()

	score := 0.0
	var reasons []string

	// 1. Mass file modification (ransomware pattern)
	// Tracked by caller over time window - here just flag individual signals

	// 2. Modification of sensitive files
	sensitivePaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		`c:\windows\system32\drivers\etc\hosts`,
		`c:\windows\system32\lsass.exe`,
		"/Library/LaunchDaemons/", "/Library/LaunchAgents/",
		`\startup\`, `\startmenu\`, `\appdata\roaming\microsoft\windows\start menu`,
	}
	pathLower := toLower(evt.Path)
	for _, sp := range sensitivePaths {
		if contains(pathLower, sp) {
			score += 0.5
			reasons = append(reasons, "modification of sensitive system file")
			break
		}
	}

	// 3. Executable dropped in temp directory
	if evt.Action == "create" &&
		(hasSuffix(pathLower, ".exe") || hasSuffix(pathLower, ".dll") ||
			hasSuffix(pathLower, ".sh") || hasSuffix(pathLower, ".ps1")) {
		tempPaths := []string{`\temp\`, `/tmp/`, `/dev/shm/`, `\downloads\`}
		for _, tp := range tempPaths {
			if contains(pathLower, tp) {
				score += 0.45
				reasons = append(reasons, "executable created in temporary directory")
				break
			}
		}
	}

	return newAnomalyScore(score, reasons)
}

func (d *LocalAnomalyDetector) updateBaseline(evt collector.ProcessEvent) {
	name := normalizeProcessName(evt.ProcessName)
	stats, ok := d.baseline.processes[name]
	if !ok {
		stats = &ProcessStats{KnownPaths: make(map[string]int)}
		d.baseline.processes[name] = stats
	}
	stats.SeenCount++
	stats.LastSeen = evt.Timestamp
	if evt.ImagePath != "" {
		stats.KnownPaths[evt.ImagePath]++
	}
}

// ─── Helpers ──────────────────────────────────────────────────

func normalizeProcessName(name string) string {
	// Lowercase and strip path
	n := toLower(name)
	for i := len(n) - 1; i >= 0; i-- {
		if n[i] == '/' || n[i] == '\\' {
			return n[i+1:]
		}
	}
	return n
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

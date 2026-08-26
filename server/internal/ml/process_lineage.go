package ml

import (
	"strings"
	"sync"
)

// ProcessLineageAnalyzer detects suspicious process parent-child relationships.
type ProcessLineageAnalyzer struct {
	mu            sync.RWMutex
	suspiciousMap map[string][]string // parent → suspicious children
	anomalyRules  []lineageRule
}

type lineageRule struct {
	parent   string
	child    string
	reason   string
	severity string
}

// NewProcessLineageAnalyzer creates a new analyzer with built-in rules.
func NewProcessLineageAnalyzer() *ProcessLineageAnalyzer {
	a := &ProcessLineageAnalyzer{
		suspiciousMap: make(map[string][]string),
	}
	// MITRE ATT&CK–based suspicious lineage rules
	a.anomalyRules = []lineageRule{
		// T1059 - Scripting
		{parent: "winword.exe", child: "cmd.exe", reason: "Office macro spawning cmd", severity: "high"},
		{parent: "winword.exe", child: "powershell.exe", reason: "Office macro spawning PowerShell", severity: "critical"},
		{parent: "excel.exe", child: "cmd.exe", reason: "Excel macro spawning cmd", severity: "high"},
		{parent: "excel.exe", child: "powershell.exe", reason: "Excel macro spawning PowerShell", severity: "critical"},
		{parent: "outlook.exe", child: "cmd.exe", reason: "Outlook spawning cmd", severity: "high"},
		{parent: "outlook.exe", child: "powershell.exe", reason: "Outlook spawning PowerShell", severity: "critical"},
		// T1055 - Process Injection
		{parent: "explorer.exe", child: "powershell.exe", reason: "Explorer spawning PowerShell (unusual)", severity: "medium"},
		// T1569 - Service execution
		{parent: "services.exe", child: "cmd.exe", reason: "Services spawning cmd (lateral movement indicator)", severity: "high"},
		// T1203 - Exploitation
		{parent: "iexplore.exe", child: "cmd.exe", reason: "IE spawning cmd (exploit indicator)", severity: "critical"},
		{parent: "chrome.exe", child: "cmd.exe", reason: "Chrome spawning cmd (exploit indicator)", severity: "critical"},
		// T1136 - Persistence via scheduled tasks
		{parent: "schtasks.exe", child: "powershell.exe", reason: "Scheduled task running PowerShell", severity: "high"},
		// Linux equivalents
		{parent: "apache2", child: "bash", reason: "Web server spawning shell (webshell)", severity: "critical"},
		{parent: "nginx", child: "bash", reason: "nginx spawning shell (webshell)", severity: "critical"},
		{parent: "httpd", child: "sh", reason: "httpd spawning shell (webshell)", severity: "critical"},
		{parent: "python3", child: "bash", reason: "Python spawning bash (possible exploit)", severity: "medium"},
		{parent: "python", child: "bash", reason: "Python spawning bash (possible exploit)", severity: "medium"},
		// T1548 - sudo abuse
		{parent: "sudo", child: "bash", reason: "sudo spawning bash (privilege escalation)", severity: "high"},
	}
	return a
}

// AnalysisResult contains the result of a lineage check.
type AnalysisResult struct {
	IsSuspicious bool
	Reason       string
	Severity     string
	Rule         string
}

// Analyze checks whether a parent→child process relationship is suspicious.
func (a *ProcessLineageAnalyzer) Analyze(parentProcess, childProcess string) *AnalysisResult {
	parent := strings.ToLower(strings.TrimSuffix(parentProcess, ".exe"))
	child := strings.ToLower(strings.TrimSuffix(childProcess, ".exe"))

	// Re-add .exe suffix for Windows matching
	parentExe := parent + ".exe"
	childExe := child + ".exe"

	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, rule := range a.anomalyRules {
		rParent := strings.ToLower(rule.parent)
		rChild := strings.ToLower(rule.child)
		if (parent == rParent || parentExe == rParent) &&
			(child == rChild || childExe == rChild) {
			return &AnalysisResult{
				IsSuspicious: true,
				Reason:       rule.reason,
				Severity:     rule.severity,
				Rule:         rule.parent + " → " + rule.child,
			}
		}
	}
	return &AnalysisResult{IsSuspicious: false}
}

// AddRule adds a custom lineage rule at runtime.
func (a *ProcessLineageAnalyzer) AddRule(parent, child, reason, severity string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.anomalyRules = append(a.anomalyRules, lineageRule{
		parent:   strings.ToLower(parent),
		child:    strings.ToLower(child),
		reason:   reason,
		severity: severity,
	})
}

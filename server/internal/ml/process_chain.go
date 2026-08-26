package ml

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ProcessChainEngine maintains a per-agent short-lived process cache and
// matches multi-hop ancestry chain patterns to detect attack sequences.
//
// Design: when a new process event arrives (pid, ppid, name, cmdline) we
// (1) insert it into the per-agent cache,
// (2) walk the PPID chain to reconstruct the ancestry path,
// (3) check each chainRule against that ancestry path.
//
// Ancestry path is ordered newest→oldest:
//
//	[currentProcess, parentProcess, grandparentProcess, ...]
//
// A chainRule.pattern is ordered oldest→newest (attacker's kill-chain order).
// Matching is "subsequence contains" — intermediate processes are allowed.
type ProcessChainEngine struct {
	mu     sync.Mutex
	procs  map[string]map[uint32]*cachedProc // agentID → pid → proc
	rules  []chainRule
	maxAge time.Duration
}

type cachedProc struct {
	pid     uint32
	ppid    uint32
	name    string // lower-cased basename (e.g. "powershell.exe")
	cmdline string // lower-cased
	addedAt time.Time
}

// chainStep is one hop in a chainRule pattern.
// name is matched as a case-insensitive suffix of the process image name.
// cmdline, if non-empty, is an additional substring constraint on that same
// process's command line. Both conditions must be satisfied for the step to match.
// A name of "" matches any process name (useful for cmdline-only constraints).
type chainStep struct {
	name    string
	cmdline string
}

// step is a convenience constructor.
func step(name string) chainStep             { return chainStep{name: name} }
func stepCmd(name, cmdline string) chainStep { return chainStep{name: name, cmdline: cmdline} }

// chainRule defines a multi-hop attack pattern.
// pattern is ordered root→leaf (oldest ancestor first, current process last).
type chainRule struct {
	id       string
	pattern  []chainStep
	reason   string
	severity string
	mitre    string
}

// ChainDetection is returned when a chainRule fires.
type ChainDetection struct {
	RuleID   string
	Reason   string
	Severity string
	MITRE    string
	Chain    []string // actual process names, root→leaf
}

// chainDepth is the max ancestry hops to walk (limits cache lookups).
const chainDepth = 8

// procCacheTTL controls how long process entries live in the cache.
const procCacheTTL = 30 * time.Minute

// NewProcessChainEngine creates an engine with built-in ATT&CK chain rules.
func NewProcessChainEngine() *ProcessChainEngine {
	e := &ProcessChainEngine{
		procs:  make(map[string]map[uint32]*cachedProc),
		maxAge: procCacheTTL,
	}
	e.rules = builtinChainRules()
	return e
}

// Analyze records the process in the per-agent cache, reconstructs the
// ancestry chain, and returns any matching rule detections.
func (e *ProcessChainEngine) Analyze(agentID string, pid, ppid uint32, name, cmdline string) []*ChainDetection {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ensureAgent(agentID)
	e.evictStale(agentID)

	baseName := strings.ToLower(baseProcess(name))
	lowerCmd := strings.ToLower(cmdline)

	e.procs[agentID][pid] = &cachedProc{
		pid:     pid,
		ppid:    ppid,
		name:    baseName,
		cmdline: lowerCmd,
		addedAt: time.Now(),
	}

	// Build ancestry chain: [current, parent, grandparent, ...]
	chain := e.buildChain(agentID, pid, chainDepth)

	// Log chain for debugging (always, so we can confirm events are flowing)
	chainNames := make([]string, len(chain))
	for i, p := range chain {
		chainNames[i] = p.name
	}
	slog.Info("chain analysis", "agent", agentID, "proc", baseName, "pid", pid, "ppid", ppid, "chain", strings.Join(chainNames, "<-"), "cache_size", len(e.procs[agentID]))

	if len(chain) < 2 {
		return nil
	}

	var detections []*ChainDetection
	for _, rule := range e.rules {
		if matchesChain(rule.pattern, chain) {
			// Build human-readable chain (root→leaf)
			readable := make([]string, len(chain))
			for i, p := range chain {
				readable[len(chain)-1-i] = p.name
			}
			detections = append(detections, &ChainDetection{
				RuleID:   rule.id,
				Reason:   rule.reason,
				Severity: rule.severity,
				MITRE:    rule.mitre,
				Chain:    readable,
			})
		}
	}
	return detections
}

// buildChain walks the PPID chain starting at pid, returning at most maxDepth
// entries ordered newest→oldest (current process first).
func (e *ProcessChainEngine) buildChain(agentID string, pid uint32, maxDepth int) []*cachedProc {
	cache := e.procs[agentID]
	var chain []*cachedProc
	visited := make(map[uint32]struct{})
	cur := pid
	for i := 0; i < maxDepth; i++ {
		p, ok := cache[cur]
		if !ok {
			break
		}
		if _, seen := visited[cur]; seen {
			break // cycle guard
		}
		visited[cur] = struct{}{}
		chain = append(chain, p)
		if p.ppid == 0 || p.ppid == cur {
			break
		}
		cur = p.ppid
	}
	return chain
}

// matchesChain returns true if the rule pattern is a subsequence of the
// ancestry chain. pattern is root→leaf; chain is leaf→root.
// Each chainStep.name is matched as a case-insensitive suffix of the process
// image name. chainStep.cmdline, if non-empty, is an additional substring
// constraint on the same process's command line.
func matchesChain(pattern []chainStep, chain []*cachedProc) bool {
	if len(pattern) > len(chain) {
		return false
	}
	// Reverse chain to root→leaf for easier subsequence matching
	reversed := make([]*cachedProc, len(chain))
	for i, p := range chain {
		reversed[len(chain)-1-i] = p
	}

	pi := 0 // pattern index
	for ci := 0; ci < len(reversed) && pi < len(pattern); ci++ {
		proc := reversed[ci]
		s := pattern[pi]
		var matched bool
		if s.name == "" {
			matched = s.cmdline == "" || strings.Contains(proc.cmdline, strings.ToLower(s.cmdline))
		} else {
			nameOK := strings.HasSuffix(proc.name, strings.ToLower(s.name)) || proc.name == strings.ToLower(s.name)
			cmdOK := s.cmdline == "" || strings.Contains(proc.cmdline, strings.ToLower(s.cmdline))
			matched = nameOK && cmdOK
		}
		if matched {
			pi++
		}
	}
	return pi == len(pattern)
}

// ─── helpers ────────────────────────────────────────────────────

func (e *ProcessChainEngine) ensureAgent(agentID string) {
	if e.procs[agentID] == nil {
		e.procs[agentID] = make(map[uint32]*cachedProc)
	}
}

func (e *ProcessChainEngine) evictStale(agentID string) {
	cutoff := time.Now().Add(-e.maxAge)
	cache := e.procs[agentID]
	for pid, p := range cache {
		if p.addedAt.Before(cutoff) {
			delete(cache, pid)
		}
	}
}

// LookupName returns the cached process name for the given PID on this agent,
// or "" if not found. Used by the detection engine to resolve parent names
// from PPID when the event does not include the parent image name directly.
func (e *ProcessChainEngine) LookupName(agentID string, pid uint32) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	cache := e.procs[agentID]
	if cache == nil {
		return ""
	}
	if p, ok := cache[pid]; ok {
		return p.name
	}
	return ""
}

// baseProcess returns the basename of a process path (everything after the
// last backslash or forward slash), falling back to the full string.
func baseProcess(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '\\' || name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

// ─── Built-in ATT&CK chain rules ────────────────────────────────

func builtinChainRules() []chainRule {
	return []chainRule{
		// 1. T1566.001 - Office macro → cmd → PowerShell
		{id: "chain-T1566.001-a", mitre: "T1566.001", severity: "critical",
			reason:  "Office macro spawned cmd which spawned PowerShell (spearphishing execution)",
			pattern: []chainStep{step("winword.exe"), step("cmd.exe"), step("powershell.exe")}},
		// 2. T1566.001 - Excel macro → cmd → PowerShell
		{id: "chain-T1566.001-b", mitre: "T1566.001", severity: "critical",
			reason:  "Excel macro spawned cmd then PowerShell (macro execution chain)",
			pattern: []chainStep{step("excel.exe"), step("cmd.exe"), step("powershell.exe")}},
		// 3. T1566.001 - Outlook → Word → PowerShell
		{id: "chain-T1566.001-c", mitre: "T1566.001", severity: "critical",
			reason:  "Email attachment opened in Word then spawned PowerShell",
			pattern: []chainStep{step("outlook.exe"), step("winword.exe"), step("powershell.exe")}},
		// 4. T1203 - Browser exploit → PowerShell → certutil
		{id: "chain-T1203-a", mitre: "T1203", severity: "critical",
			reason:  "Browser spawned PowerShell then certutil (exploit + download)",
			pattern: []chainStep{step("chrome.exe"), step("powershell.exe"), step("certutil.exe")}},
		// 5. T1203 - IE exploit chain
		{id: "chain-T1203-b", mitre: "T1203", severity: "critical",
			reason:  "Internet Explorer spawned cmd then PowerShell (browser exploit chain)",
			pattern: []chainStep{step("iexplore.exe"), step("cmd.exe"), step("powershell.exe")}},
		// 6. T1021.001 - RDP lateral movement: mstsc → cmd → net
		{id: "chain-T1021.001", mitre: "T1021.001", severity: "high",
			reason:  "RDP session spawned cmd then net.exe (lateral movement recon)",
			pattern: []chainStep{step("mstsc.exe"), step("cmd.exe"), step("net.exe")}},
		// 7. T1059.001 - PowerShell download+exec chain
		{id: "chain-T1059.001", mitre: "T1059.001", severity: "high",
			reason:  "PowerShell invoked certutil (LOLBin download) then cmd",
			pattern: []chainStep{step("powershell.exe"), step("certutil.exe"), step("cmd.exe")}},
		// 8. T1053.005 - svchost (task scheduler) → cmd → PowerShell
		{id: "chain-T1053.005", mitre: "T1053.005", severity: "high",
			reason:  "svchost (task scheduler) spawned cmd then PowerShell (scheduled task abuse)",
			pattern: []chainStep{step("svchost.exe"), step("cmd.exe"), step("powershell.exe")}},
		// 9. T1569.002 - services.exe → cmd → net
		{id: "chain-T1569.002", mitre: "T1569.002", severity: "high",
			reason:  "Windows services spawned cmd then net.exe (service-based lateral movement)",
			pattern: []chainStep{step("services.exe"), step("cmd.exe"), step("net.exe")}},
		// 10. T1055 - explorer → cmd → PowerShell (process injection indicator)
		{id: "chain-T1055", mitre: "T1055", severity: "high",
			reason:  "Explorer spawned cmd then PowerShell (possible process injection in explorer)",
			pattern: []chainStep{step("explorer.exe"), step("cmd.exe"), step("powershell.exe")}},
		// 11. T1547.001 - PowerShell → reg.exe targeting Run key
		{id: "chain-T1547.001", mitre: "T1547.001", severity: "high",
			reason:  "PowerShell spawned reg.exe (autostart persistence via Run key)",
			pattern: []chainStep{step("powershell.exe"), step("reg.exe")}},
		// 12. T1003.001 - cmd → rundll32 comsvcs (LSASS dump)
		{id: "chain-T1003.001", mitre: "T1003.001", severity: "critical",
			reason:  "cmd spawned rundll32 with comsvcs.dll (LSASS memory dump via MiniDump)",
			pattern: []chainStep{step("cmd.exe"), stepCmd("rundll32.exe", "comsvcs")}},
		// 13. T1218.011 - cmd → rundll32 → cmd (proxy execution)
		{id: "chain-T1218.011", mitre: "T1218.011", severity: "high",
			reason:  "cmd → rundll32 → cmd chain (rundll32 proxy execution spawning new shell)",
			pattern: []chainStep{step("cmd.exe"), step("rundll32.exe"), step("cmd.exe")}},
		// 14. T1218 - PowerShell → mshta → cmd (LOLBin chain)
		{id: "chain-T1218", mitre: "T1218", severity: "high",
			reason:  "PowerShell → mshta → cmd (LOLBin proxy execution chain)",
			pattern: []chainStep{step("powershell.exe"), step("mshta.exe"), step("cmd.exe")}},
		// 15. T1505.003 - IIS w3wp → cmd → PowerShell (web shell)
		{id: "chain-T1505.003", mitre: "T1505.003", severity: "critical",
			reason:  "IIS worker (w3wp) spawned cmd then PowerShell (web shell execution chain)",
			pattern: []chainStep{step("w3wp.exe"), step("cmd.exe"), step("powershell.exe")}},
		// 16. T1490 - cmd → vssadmin delete shadows
		{id: "chain-T1490", mitre: "T1490", severity: "critical",
			reason:  "cmd spawned vssadmin to delete shadow copies (ransomware pre-step)",
			pattern: []chainStep{step("cmd.exe"), stepCmd("vssadmin.exe", "delete shadows")}},
		// 17. T1562.001 - PowerShell → sc.exe stop WinDefend
		{id: "chain-T1562.001", mitre: "T1562.001", severity: "critical",
			reason:  "PowerShell spawned sc.exe targeting WinDefend (disabling Windows Defender)",
			pattern: []chainStep{step("powershell.exe"), stepCmd("sc.exe", "windefend")}},
		// 18. T1566.001 - Word macro directly spawning PowerShell (no cmd hop).
		// A stronger IOC than the 3-hop variant; Office spawning PowerShell is
		// almost never legitimate.
		{id: "chain-T1566.001-d", mitre: "T1566.001", severity: "critical",
			reason:  "Word directly spawned PowerShell (malicious macro execution)",
			pattern: []chainStep{step("winword.exe"), step("powershell.exe")}},
		// 19. T1566.001 - Excel macro directly spawning PowerShell.
		{id: "chain-T1566.001-e", mitre: "T1566.001", severity: "critical",
			reason:  "Excel directly spawned PowerShell (malicious macro execution)",
			pattern: []chainStep{step("excel.exe"), step("powershell.exe")}},
		// 20. T1566.001 - PowerPoint macro spawning PowerShell.
		{id: "chain-T1566.001-f", mitre: "T1566.001", severity: "critical",
			reason:  "PowerPoint directly spawned PowerShell (malicious macro execution)",
			pattern: []chainStep{step("powerpnt.exe"), step("powershell.exe")}},
		// 21. T1566.001 - Word macro dropping/launching a Windows Script Host script.
		{id: "chain-T1566.001-g", mitre: "T1566.001", severity: "high",
			reason:  "Word spawned WScript/CScript (macro launching a script payload)",
			pattern: []chainStep{step("winword.exe"), step("wscript.exe")}},
		// 22. T1218.005 - mshta spawning PowerShell (HTA → PowerShell stager).
		{id: "chain-T1218.005", mitre: "T1218.005", severity: "high",
			reason:  "mshta spawned PowerShell (HTA proxy execution stager)",
			pattern: []chainStep{step("mshta.exe"), step("powershell.exe")}},
		// 23. T1047 - WMI provider host spawning PowerShell (remote WMI execution).
		{id: "chain-T1047-a", mitre: "T1047", severity: "high",
			reason:  "WmiPrvSE spawned PowerShell (remote WMI command execution)",
			pattern: []chainStep{step("wmiprvse.exe"), step("powershell.exe")}},
		// 24. T1047 - WMI provider host spawning cmd.
		{id: "chain-T1047-b", mitre: "T1047", severity: "high",
			reason:  "WmiPrvSE spawned cmd (remote WMI command execution)",
			pattern: []chainStep{step("wmiprvse.exe"), step("cmd.exe")}},
		// 25. T1021.006 - WinRM host (wsmprovhost) spawning PowerShell (remote management abuse).
		{id: "chain-T1021.006", mitre: "T1021.006", severity: "high",
			reason:  "WinRM host (wsmprovhost) spawned PowerShell (remote PowerShell execution)",
			pattern: []chainStep{step("wsmprovhost.exe"), step("powershell.exe")}},
		// 26. T1505.003 - IIS worker directly spawning PowerShell (web shell, no cmd hop).
		{id: "chain-T1505.003-b", mitre: "T1505.003", severity: "critical",
			reason:  "IIS worker (w3wp) directly spawned PowerShell (web shell execution)",
			pattern: []chainStep{step("w3wp.exe"), step("powershell.exe")}},
		// 27. T1190 - SQL Server spawning cmd (xp_cmdshell / SQL injection RCE).
		{id: "chain-T1190-sql", mitre: "T1190", severity: "critical",
			reason:  "SQL Server (sqlservr) spawned cmd (xp_cmdshell abuse / SQLi RCE)",
			pattern: []chainStep{step("sqlservr.exe"), step("cmd.exe")}},
	}
}

// Package detection — discovery.go: host-enumeration (ATT&CK Discovery tactic)
// classification and burst scoring.
//
// Discovery commands (whoami, systeminfo, ipconfig, netstat, tasklist, net
// group, …) are individually near-worthless as alerts: admins and inventory
// agents run them constantly, so a per-command rule is almost pure false
// positive. Yet discovery is a real kill-chain stage — the "look around after
// landing" step every hands-on-keyboard intrusion performs. This file turns that
// weak, high-volume signal into value two ways WITHOUT raising a standalone alert
// per command:
//
//  1. classifyDiscoveryCommand maps a process command line to the Discovery
//     ATT&CK technique it represents (or ""). The engine feeds that technique into
//     the KillChainScorer, so a lone `whoami` contributes the "discovery" stage to
//     a host's chain. It can never fire on its own — the chain needs 4 DISTINCT
//     tactics — so this is false-positive-free by construction, and it lets
//     multi-stage intrusions that were stuck at 3 tactics (missing discovery)
//     finally correlate.
//
//  2. DiscoveryScorer raises ONE low-noise correlation alert only when a single
//     host runs several DISTINCT discovery techniques within a short window — the
//     rapid, broad enumeration that betrays interactive recon rather than a
//     one-off admin command. Mirrors KillChainScorer: sliding window, per-host
//     state, fire-on-first-crossing + re-fire on newly-seen techniques, deterministic clock.
package detection

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// discWindow is the sliding window over which distinct discovery techniques
	// from one host are counted. Short, because the signal we want is a rapid
	// enumeration burst, not discovery spread across a normal workday.
	discWindow = 5 * time.Minute
	// discMinTechniques is the number of DISTINCT discovery techniques from one
	// host within the window that raises a correlated "rapid enumeration" alert.
	// Set high enough that a normal admin one-liner (a single technique) or a
	// two-command check never fires; broad interactive recon touches many.
	discMinTechniques = 4
	// discCreditTTL is how long a technique stays "already reported" for a host.
	// Longer than the window so a single campaign is not re-announced technique by
	// technique forever, short enough that a fresh campaign hours later is reported
	// again rather than silently suppressed.
	discCreditTTL = 30 * time.Minute
	discMaxKeys   = 8192
)

// discoveryPattern maps an ATT&CK Discovery technique to the command-line
// substrings that indicate it. Substrings are matched case-insensitively against
// the full command line (same contains-semantics Sigma uses). Tokens are chosen
// to be specific enough to name the technique while avoiding the most generic
// forms (bare `id`, `ls`, `dir`, `ver`) that would misclassify ordinary use.
type discoveryPattern struct {
	technique string
	subs      []string
}

// discoveryPatterns is ordered most-specific-first so that, e.g., `net localgroup`
// classifies as Permission-Groups (T1069) rather than Account (T1087). The first
// pattern with a matching substring wins.
var discoveryPatterns = []discoveryPattern{
	// T1518.001 Security Software Discovery — checked BEFORE the generic software
	// and process patterns so `ps aux | grep falcon` is recognised for what it is:
	// an attacker looking for the EDR, not routine process listing. Keyed on
	// specific security-product names, which ordinary command lines do not contain.
	// (Classification alone raises nothing — a burst still needs discMinTechniques
	// distinct techniques — so an admin genuinely managing their agent is harmless.)
	{"T1518.001", []string{
		"crowdstrike", "falcon-sensor", "carbonblack", "cbagent", "sentinelone", "sentinelctl",
		"cylance", "cortex-xdr", "cortex_xdr", "traps", "sophos", "mcafee", "symantec",
		"trendmicro", "kaspersky", "eset", "clamav", "clamd", "windefend", "msmpeng",
		"defender", "auditd -s", "aide --check",
	}},
	// T1069 Permission Groups Discovery — check before T1087 (`net user`) so the
	// group forms of `net` win.
	{"T1069", []string{"net localgroup", "net group", "whoami /groups", "getent group", "id -gn", "id -gr", "dscl . -list /groups", "dscl . read /groups"}},
	// T1087 Account Discovery
	{"T1087", []string{"net user", "net accounts", "get-localuser", "getent passwd", "cat /etc/passwd", "dscacheutil -q user", "dscl . -list /users"}},
	// T1007 System Service Discovery — `net start` (list services) before other `net`.
	{"T1007", []string{"sc query", "sc.exe query", "net start", "systemctl list-unit", "service --status-all", "wmic service", "get-service"}},
	// T1033 System Owner/User Discovery
	{"T1033", []string{"whoami", "quser", "qwinsta"}},
	// T1082 System Information Discovery
	{"T1082", []string{"systeminfo", "uname -a", "uname -s", "uname -r", "hostnamectl", "sw_vers", "lscpu", "wmic os get", "wmic computersystem", "cat /etc/os-release", "cat /proc/version", "cat /proc/cpuinfo"}},
	// T1057 Process Discovery
	{"T1057", []string{"tasklist", "ps -ef", "ps aux", "ps -aux", "ps ax", "get-process", "wmic process"}},
	// T1018 Remote System Discovery — enumerating OTHER hosts (the host list, the
	// domain's controllers, previously-reached SSH hosts) as distinct from reading
	// this machine's own network configuration, which is T1016 below. `arp -a` is
	// deliberately left on T1016 where it already lives and is pinned by tests.
	{"T1018", []string{"net view", "nltest /dclist", "nltest /domain_trusts", "cat /etc/hosts", "getent hosts", "known_hosts", "get-adcomputer"}},
	// T1016 System Network Configuration Discovery
	{"T1016", []string{"ipconfig", "ifconfig", "ip addr", "ip a ", "ip -br", "ip route", "route print", "netsh interface", "arp -a", "nbtstat", "cat /etc/resolv.conf", "get-netipconfiguration"}},
	// T1049 System Network Connections Discovery
	{"T1049", []string{"netstat", "ss -", "lsof -i", "get-nettcpconnection"}},
	// T1518 Software Discovery
	{"T1518", []string{"wmic product get", "dpkg -l", "rpm -qa", "brew list", "get-package", "apt list --installed", "snap list", "yum list installed"}},
	// T1083 File and Directory Discovery — only broad/recursive forms; plain
	// `ls`/`dir` are far too common to classify.
	{"T1083", []string{"dir /s", "tree /f", "get-childitem -recurse", "gci -recurse", "find / -name", "find / -type", "where /r"}},
}

// classifyDiscoveryCommand returns the ATT&CK Discovery technique ID a command
// line represents, or "" if it is not a recognized discovery command. Pure and
// allocation-light so it is cheap to call on every process event.
func classifyDiscoveryCommand(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	lc := strings.ToLower(cmdline)
	for _, p := range discoveryPatterns {
		for _, s := range p.subs {
			if strings.Contains(lc, s) {
				return p.technique
			}
		}
	}
	return ""
}

type discState struct {
	techniques map[string]int64 // technique -> last-seen unix seconds
	// credited records techniques already named in an alert, so a burst re-fires
	// when the window takes in a technique nobody has been told about yet. Keyed
	// with its own timestamp and expired on discCreditTTL, so a later campaign on
	// the same host is reported again rather than suppressed forever.
	credited map[string]int64
}

// DiscoveryScorer is a stateful, concurrency-safe rapid-enumeration detector.
type DiscoveryScorer struct {
	mu       sync.Mutex
	entities map[string]*discState
}

func newDiscoveryScorer() *DiscoveryScorer {
	return &DiscoveryScorer{entities: make(map[string]*discState)}
}

// Observe classifies one process command line. It returns the recognized
// discovery technique ID (or "") for the caller to fold into the kill-chain, and
// a correlated alert when the host has run discMinTechniques distinct discovery
// techniques within the window. now is injected for deterministic tests.
func (d *DiscoveryScorer) Observe(agentID, cmdline string, now time.Time) (string, []*detectionrules.RuleMatch) {
	tech := classifyDiscoveryCommand(cmdline)
	if agentID == "" || tech == "" {
		return tech, nil
	}
	nu := now.Unix()
	winSec := int64(discWindow / time.Second)

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.entities) > discMaxKeys {
		d.evictStale(nu, winSec*2)
	}
	st := d.entities[agentID]
	if st == nil {
		st = &discState{techniques: make(map[string]int64), credited: make(map[string]int64)}
		d.entities[agentID] = st
	}
	if st.credited == nil {
		st.credited = make(map[string]int64)
	}
	// Expire techniques outside the window, and credits past their (longer) TTL.
	for t, ts := range st.techniques {
		if nu-ts > winSec {
			delete(st.techniques, t)
		}
	}
	for t, ts := range st.credited {
		if nu-ts > int64(discCreditTTL/time.Second) {
			delete(st.credited, t)
		}
	}
	st.techniques[tech] = nu

	n := len(st.techniques)
	if n < discMinTechniques {
		return tech, nil
	}
	// Re-fire when the window holds a technique that has not been reported yet —
	// NOT merely when the distinct count grows.
	//
	// Counting was the original rule, and it silently lost coverage during
	// deliberate, spaced-out reconnaissance: at a pace where the window holds only
	// about the threshold's worth of techniques, each new one arrives as an old one
	// expires, so the count plateaus and never "grows". The burst fired once and
	// every technique enumerated afterwards went unreported — and which techniques
	// landed on the credited side of that line depended purely on timing, making
	// coverage non-deterministic (measured live: T1082 credited in one run, missed
	// in the next, same build and pacing).
	//
	// Keying on unreported techniques instead makes a sustained campaign name all of
	// them, while keeping the property that matters: an isolated discovery command
	// still cannot fire anything, because the window must hold discMinTechniques
	// distinct techniques before any of this is reached.
	fresh := false
	for t := range st.techniques {
		if _, seen := st.credited[t]; !seen {
			fresh = true
			break
		}
	}
	if !fresh {
		return tech, nil
	}

	techs := make([]string, 0, len(st.techniques))
	for t := range st.techniques {
		techs = append(techs, t)
		st.credited[t] = nu
	}
	sort.Strings(techs)
	sev := 5
	if n >= 6 {
		sev = 6 // near-exhaustive host survey
	}
	return tech, []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "ホスト探索の連続実行（偵察の疑い）",
		RuleType: "correlation",
		Severity: sev,
		Title:    "[DISCOVERY] 短時間に複数種の探索コマンドを実行（偵察の疑い）",
		// The reported technique set IS this alert's identity. Without it the engine's
		// (agent, title) dedup collapsed every re-fire for 5 minutes, so a burst that
		// kept broadening was reported once with whatever handful of techniques had
		// arrived by then. Measured live: 11 discovery techniques executed over 165s
		// produced ONE alert naming 4 of them; the other 7 were never surfaced and the
		// credited-set re-fire logic above could not take effect. Keying on the set
		// lets a broadening campaign report each new stage while an unchanged set
		// still collapses.
		DedupKey: strings.Join(techs, ","),
		Description: fmt.Sprintf("単一ホストが%d分以内に%d種の異なるATT&CK探索(Discovery)技術を実行: %s。単発の探索は正常でも、多種を短時間に連続実行するのは着地後のハンズオンキーボード偵察の兆候。個別には誤検知になるため単発ではアラート化せず、バーストのみ相関検知。",
			int(discWindow/time.Minute), n, strings.Join(techs, ", ")),
		MITRETags: techs,
	}}
}

func (d *DiscoveryScorer) evictStale(nowUnix, maxAgeSec int64) {
	for key, st := range d.entities {
		var newest int64
		for _, ts := range st.techniques {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.entities, key)
		}
	}
}

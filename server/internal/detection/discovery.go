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
//     state, fire-on-first-crossing + escalate-on-growth, deterministic clock.
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
	discMaxKeys       = 8192
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
	// T1016 System Network Configuration Discovery
	{"T1016", []string{"ipconfig", "ifconfig", "ip addr", "ip a ", "ip -br", "ip route", "route print", "netsh interface", "arp -a", "nbtstat", "cat /etc/resolv.conf", "get-netipconfiguration"}},
	// T1049 System Network Connections Discovery
	{"T1049", []string{"netstat", "ss -", "lsof -i", "get-nettcpconnection"}},
	// T1518 Software Discovery
	{"T1518", []string{"wmic product get", "dpkg -l", "rpm -qa", "brew list", "get-package", "apt list --installed"}},
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
	lastAlertN int              // distinct-technique count at the last alert
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
		st = &discState{techniques: make(map[string]int64)}
		d.entities[agentID] = st
	}
	// Expire techniques outside the window.
	for t, ts := range st.techniques {
		if nu-ts > winSec {
			delete(st.techniques, t)
		}
	}
	st.techniques[tech] = nu

	n := len(st.techniques)
	if n < discMinTechniques {
		st.lastAlertN = 0
		return tech, nil
	}
	// Fire on first crossing and escalate as more distinct techniques appear;
	// re-firing only on growth dedups repeated same-size observations.
	if n <= st.lastAlertN {
		return tech, nil
	}
	st.lastAlertN = n

	techs := make([]string, 0, len(st.techniques))
	for t := range st.techniques {
		techs = append(techs, t)
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

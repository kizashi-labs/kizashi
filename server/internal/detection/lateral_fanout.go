// Package detection — lateral_fanout.go: lateral-movement fan-out detection
// (T1021 Remote Services).
//
// Lateral movement is a HORIZONTAL fan-out: one compromised host reaching many
// DISTINCT other hosts on remote-administration ports (SMB, RDP, WinRM, SSH, WMI)
// as the attacker spreads. This is distinct from NetworkScanDetector's VERTICAL
// view (one host, many ports) and from per-connection rules that see each remote
// session in isolation. This detector counts distinct destination hosts contacted
// on remote-service ports per source host over a window and fires T1021 when the
// spread crosses a threshold. Mirrors NetworkScanDetector's structure (sliding
// window, per-key state, fire-then-dedup, injected clock).
package detection

import (
	"fmt"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// lateralWindow is the sliding window over which distinct remote-service hosts
	// are counted per source host.
	lateralWindow = 2 * time.Minute
	// lateralMinHosts is the number of distinct destination hosts on remote-service
	// ports one source must contact within the window to trip the alert. A normal
	// workstation talks to a handful of servers; a spreading host fans out widely.
	lateralMinHosts = 8
	// lateralDedup suppresses repeat alerts for the same source after firing.
	lateralDedup = 10 * time.Minute
	// lateralMaxKeys bounds memory (tracked source hosts).
	lateralMaxKeys = 8192
)

// lateralServicePorts are the remote-administration ports whose fan-out indicates
// lateral movement: SMB(445/139), RDP(3389), WinRM(5985/5986), SSH(22),
// WMI/RPC(135), VNC(5900).
var lateralServicePorts = map[int]string{
	445: "SMB", 139: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM",
	22: "SSH", 135: "WMI/RPC", 5900: "VNC",
}

type lateralState struct {
	hosts     map[string]int64 // dstIP -> last-seen unix seconds
	ports     map[string]struct{}
	lastAlert int64
}

// LateralFanoutScorer is a stateful, concurrency-safe lateral-movement detector.
// Construct with newLateralFanoutScorer; feed every outbound network event to
// Observe.
type LateralFanoutScorer struct {
	mu   sync.Mutex
	keys map[string]*lateralState
}

func newLateralFanoutScorer() *LateralFanoutScorer {
	return &LateralFanoutScorer{keys: make(map[string]*lateralState)}
}

// Observe records one outbound connection and returns a T1021 match when the
// source host has contacted lateralMinHosts distinct destinations on remote-
// service ports within the window. Connections to non-service ports are ignored.
// now is injected for deterministic tests.
func (d *LateralFanoutScorer) Observe(agentID, dstIP string, dstPort int, now time.Time) []*detectionrules.RuleMatch {
	svc, ok := lateralServicePorts[dstPort]
	if !ok || dstIP == "" {
		return nil
	}
	nu := now.Unix()
	winSec := int64(lateralWindow / time.Second)

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.keys) > lateralMaxKeys {
		d.evictStale(nu, winSec*4)
	}
	st := d.keys[agentID]
	if st == nil {
		st = &lateralState{hosts: make(map[string]int64), ports: make(map[string]struct{})}
		d.keys[agentID] = st
	}
	for h, ts := range st.hosts {
		if nu-ts > winSec {
			delete(st.hosts, h)
		}
	}
	st.hosts[dstIP] = nu
	st.ports[svc] = struct{}{}

	if len(st.hosts) < lateralMinHosts {
		return nil
	}
	if nu-st.lastAlert < int64(lateralDedup/time.Second) {
		return nil
	}
	st.lastAlert = nu
	n := len(st.hosts)
	svcs := make([]string, 0, len(st.ports))
	for s := range st.ports {
		svcs = append(svcs, s)
	}
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "横展開の疑い: リモートサービスへの多数ホスト・ファンアウト",
		RuleType: "heuristic",
		Severity: 7,
		Title:    fmt.Sprintf("[HEURISTIC] 横展開の疑い: 単一ホストが%d分内に多数の異なるホストへリモートサービス接続", int(lateralWindow/time.Minute)),
		Description: fmt.Sprintf("単一ホストが%d分以内に%d個の異なる宛先ホストへリモート管理ポート(%s)で接続。1台が多数ホストへ横に広がる=横展開の疑い(単発のリモートセッションを見る個別ルールが取りこぼす広がり)。",
			int(lateralWindow/time.Minute), n, joinStrings(svcs)),
		MITRETags: []string{"T1021"},
	}}
}

func joinStrings(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func (d *LateralFanoutScorer) evictStale(nowUnix, maxAgeSec int64) {
	for k, st := range d.keys {
		var newest int64
		for _, ts := range st.hosts {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.keys, k)
		}
	}
}

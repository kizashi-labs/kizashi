// Package detection — network_scan.go: stateful port-scan / fan-out detection.
//
// Per-query and per-connection rules cannot see a *scan*: a scan is a rate/fan-out
// phenomenon — one source touching many distinct destination ports (or hosts) in a
// short window. This detector maintains a bounded, windowed count of distinct
// destination ports per source and fires T1046 when the fan-out crosses a
// threshold. It is deliberately TOOL-AGNOSTIC: it keys off the network telemetry,
// not the command line, so it fires the same for nmap, masscan, or a
// `bash /dev/tcp` loop — the exact evasion that slipped past process-string rules
// (see docs/results/live-20260702-linux-evasion-adversarial.md, T1046).
package detection

import (
	"fmt"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// scanWindow is the sliding window over which distinct destination ports are
	// counted for one source.
	scanWindow = 60 * time.Second
	// scanDistinctPorts is the number of distinct destination ports from a single
	// source within scanWindow that trips a port-scan alert. Normal applications
	// rarely fan out to this many distinct ports rapidly; set conservatively to
	// keep false positives low.
	scanDistinctPorts = 15
	// scanDedup suppresses repeat alerts for the same source after it fires.
	scanDedup = 5 * time.Minute
	// scanMaxKeys bounds memory (number of tracked sources).
	scanMaxKeys = 8192
)

// scanState tracks one source's recent distinct destination ports.
type scanState struct {
	ports     map[int]int64 // dstPort -> last-seen unix seconds
	refused   int
	lastAlert int64
}

// NetworkScanDetector is a stateful, concurrency-safe port-scan detector.
// Construct with newNetworkScanDetector; feed every outbound network event to
// Observe.
type NetworkScanDetector struct {
	mu   sync.Mutex
	keys map[string]*scanState
}

func newNetworkScanDetector() *NetworkScanDetector {
	return &NetworkScanDetector{keys: make(map[string]*scanState)}
}

// Observe records one outbound network connection and returns a T1046 match when
// the source has contacted scanDistinctPorts distinct destination ports within
// scanWindow. now is injected for deterministic tests (the engine passes
// time.Now()). Returns nil for inbound/invalid events and between the threshold
// crossing and the next dedup window.
func (d *NetworkScanDetector) Observe(agentID, procName, dstIP string, dstPort int, refused bool, now time.Time) []*detectionrules.RuleMatch {
	if dstPort <= 0 || dstPort > 65535 {
		return nil
	}
	src := procName
	if src == "" {
		src = "不明"
	}
	key := agentID + "|" + src
	nu := now.Unix()
	winSec := int64(scanWindow / time.Second)

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.keys) > scanMaxKeys {
		d.evictStale(nu, winSec*4)
	}

	st := d.keys[key]
	if st == nil {
		st = &scanState{ports: make(map[int]int64)}
		d.keys[key] = st
	}
	// Drop ports last seen outside the window (sliding window).
	for p, ts := range st.ports {
		if nu-ts > winSec {
			delete(st.ports, p)
		}
	}
	st.ports[dstPort] = nu
	if refused {
		st.refused++
	}

	if len(st.ports) < scanDistinctPorts {
		return nil
	}
	if nu-st.lastAlert < int64(scanDedup/time.Second) {
		return nil // already alerted this source recently
	}
	st.lastAlert = nu
	n := len(st.ports)
	refusedCount := st.refused
	st.refused = 0
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "ネットワーク・ポートスキャン/サービス列挙",
		RuleType: "heuristic",
		Severity: 6,
		Title:    fmt.Sprintf("[HEURISTIC] ポートスキャン検知: %s が%d秒内に多数の異なる宛先ポートへ接続", src, winSec),
		Description: fmt.Sprintf("単一ソース(process=%s, 直近host=%s)が%d秒以内に%d個の異なる宛先ポートへ接続(接続拒否=%d)。ポートスキャン/サービス列挙の疑い。ネットワーク挙動で判定するためツール非依存(nmap/masscan だけでなく `bash /dev/tcp` ループ等のプロセス文字列を回避する手口にも反応)。",
			src, dstIP, winSec, n, refusedCount),
		MITRETags: []string{"T1046"}, // Network Service Discovery
	}}
}

// evictStale drops sources whose most-recent activity is older than maxAgeSec.
func (d *NetworkScanDetector) evictStale(nowUnix, maxAgeSec int64) {
	for k, st := range d.keys {
		var newest int64
		for _, ts := range st.ports {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.keys, k)
		}
	}
}

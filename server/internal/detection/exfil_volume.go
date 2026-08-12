// Package detection — exfil_volume.go: data-exfiltration-by-volume detection
// (T1048 Exfiltration Over Alternative Protocol).
//
// The final kill-chain stage — bulk data leaving the endpoint — is a VOLUME
// phenomenon no per-connection rule sees: each packet/flow looks ordinary; only
// the CUMULATIVE outbound bytes to one external destination over a window reveal
// the theft. Signature and beacon rules miss it (a large HTTPS PUT to a
// paste/cloud host has no distinctive command line and no periodicity). This
// detector accumulates outbound bytes per (endpoint, external destination) over a
// window and fires T1048 when the total crosses a threshold.
//
// Internal destinations (RFC1918/loopback/link-local/CGNAT/IPv6 ULA) are excluded
// so ordinary internal backups and file-server traffic never trip it — exfil, by
// definition, leaves the network. Mirrors NetworkScanDetector's structure
// (sliding window, per-key state, fire-then-dedup, injected clock).
package detection

import (
	"fmt"
	"net"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// exfilWindow is the sliding window over which outbound bytes to one external
	// destination are accumulated.
	exfilWindow = 10 * time.Minute
	// exfilMinBytes is the cumulative outbound byte total to a single external
	// destination within the window that trips an exfiltration alert. Set high
	// enough that ordinary web/API traffic stays under it while a bulk upload of
	// stolen data crosses it.
	exfilMinBytes = 500 << 20 // 500 MiB
	// exfilDedup suppresses repeat alerts for the same destination after firing.
	exfilDedup = 15 * time.Minute
	// exfilMaxKeys bounds memory (tracked endpoint→destination pairs).
	exfilMaxKeys = 16384
)

// isExternalIP reports whether ip is a routable, non-private address — i.e. a
// plausible exfiltration destination. Returns false for anything internal or
// unparseable so internal traffic and malformed telemetry never trip the
// detector.
func isExternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	// Carrier-grade NAT 100.64.0.0/10 (RFC 6598) — not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
}

type exfilState struct {
	events    []exfilSample // outbound byte samples within the window
	total     int64         // cached sum of events' bytes
	lastAlert int64
}

type exfilSample struct {
	ts    int64
	bytes int64
}

// ExfilVolumeDetector is a stateful, concurrency-safe bulk-exfiltration detector.
// Construct with newExfilVolumeDetector; feed every outbound network event to
// Observe.
type ExfilVolumeDetector struct {
	mu   sync.Mutex
	keys map[string]*exfilState
}

func newExfilVolumeDetector() *ExfilVolumeDetector {
	return &ExfilVolumeDetector{keys: make(map[string]*exfilState)}
}

// Observe records one outbound connection's sent-byte count and returns a T1048
// match when cumulative outbound bytes to a single external destination cross
// exfilMinBytes within the window. Internal destinations, non-positive byte
// counts, and empty IPs are ignored. now is injected for deterministic tests.
func (d *ExfilVolumeDetector) Observe(agentID, dstIP string, bytesSent int64, now time.Time) []*detectionrules.RuleMatch {
	if bytesSent <= 0 || !isExternalIP(dstIP) {
		return nil
	}
	key := agentID + "|" + dstIP
	nu := now.Unix()
	winSec := int64(exfilWindow / time.Second)

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.keys) > exfilMaxKeys {
		d.evictStale(nu, winSec*4)
	}
	st := d.keys[key]
	if st == nil {
		st = &exfilState{}
		d.keys[key] = st
	}
	// Drop samples outside the window and recompute the running total.
	cutoff := nu - winSec
	kept := st.events[:0]
	var total int64
	for _, s := range st.events {
		if s.ts > cutoff {
			kept = append(kept, s)
			total += s.bytes
		}
	}
	st.events = append(kept, exfilSample{ts: nu, bytes: bytesSent})
	total += bytesSent
	st.total = total

	if total < exfilMinBytes {
		return nil
	}
	if nu-st.lastAlert < int64(exfilDedup/time.Second) {
		return nil
	}
	st.lastAlert = nu
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "データ持ち出しの疑い: 外部宛先への大量送信",
		RuleType: "heuristic",
		Severity: 7,
		Title:    fmt.Sprintf("[HEURISTIC] データ持ち出しの疑い: 外部 %s へ%d分内に大量のデータを送信", dstIP, int(exfilWindow/time.Minute)),
		Description: fmt.Sprintf("単一エンドポイントが外部宛先 %s へ%d分以内に累積 %s を送信。個々の接続は正常でも、外部への大量送信は持ち出しの兆候(T1048)。内部(RFC1918)宛は除外済み。閾値超のためレビュー推奨。",
			dstIP, int(exfilWindow/time.Minute), humanBytes(total)),
		MITRETags: []string{"T1048"},
	}}
}

// humanBytes renders a byte count as a compact human-readable string.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (d *ExfilVolumeDetector) evictStale(nowUnix, maxAgeSec int64) {
	for k, st := range d.keys {
		var newest int64
		for _, s := range st.events {
			if s.ts > newest {
				newest = s.ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.keys, k)
		}
	}
}

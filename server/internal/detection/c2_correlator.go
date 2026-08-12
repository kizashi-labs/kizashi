// Package detection — c2_correlator.go: multi-signal C2 target correlation.
//
// Each network C2 detector is individually heuristic and errs medium/high to keep
// false positives down. They split across two target spaces:
//
//   - by destination IP: beacon periodicity (regular call-home), JA3/JA3S blocklist
//     (known C2 TLS stack), agent threat-intel (known-bad infra); and
//   - by registrable domain: DGA (algorithmic rendezvous name), fast-flux (rotating
//     IP infrastructure), DNS tunneling (encoded C2/exfil over DNS).
//
// Any single axis can be a false positive. But when the SAME target (one IP, or one
// domain) is independently flagged by two or more orthogonal axes within a window, the
// C2 hypothesis becomes near-certain — a beacon whose TLS also fingerprints as Cobalt
// Strike, or a DGA-looking domain that also fast-fluxes, is not a coincidence. This
// stateful correlator keys per (agent,target) and escalates to a critical, optionally
// auto-isolating alert on ≥2 distinct signals. IP targets and domain targets live in
// disjoint key spaces, so they never cross-correlate.
//
// Mirrors KillChainScorer (windowed, bounded-key, injectable clock). The kill-chain
// scorer correlates ACROSS tactics on one host; this correlates ACROSS network axes on
// one target — complementary views of the same intrusion.
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
	// c2Window is the sliding window over which distinct signals for one destination
	// are counted. Wider than the kill-chain window because beacon periodicity itself
	// needs many minutes to establish, and JA3/threat-intel may land well before/after.
	c2Window      = 30 * time.Minute
	c2MinSignals  = 2
	c2MaxKeys     = 8192
	c2IsolateFrom = 3 // ≥ this many independent axes → recommend auto-isolate
)

// C2 signal classes — the orthogonal axes we correlate. IP-space and domain-space.
const (
	// Destination-IP axes.
	c2SigBeacon      = "beacon"       // periodic call-home (BeaconDetector)
	c2SigJA3         = "ja3"          // known C2 TLS fingerprint (ja3_blocklist)
	c2SigThreatIntel = "threat_intel" // agent threat-intel infra match
	// Registrable-domain axes.
	c2SigDGA       = "dga"        // algorithmic rendezvous domain (AnalyzeDGA)
	c2SigFastFlux  = "fastflux"   // rotating-IP infrastructure (DNSFastFluxDetector)
	c2SigDNSTunnel = "dns_tunnel" // DNS tunneling / exfil (dns_exfil / dns_aggregate)
)

// c2SignalLabels renders signal classes for the analyst-facing description.
var c2SignalLabels = map[string]string{
	c2SigBeacon:      "ビーコン周期性",
	c2SigJA3:         "既知C2のJA3/JA3S指紋",
	c2SigThreatIntel: "脅威インテリ一致",
	c2SigDGA:         "DGA(生成ドメイン)",
	c2SigFastFlux:    "Fast-Flux",
	c2SigDNSTunnel:   "DNSトンネリング",
}

// c2DomainAxisSignals is the subset of signal classes keyed by registrable domain
// (the rest are keyed by destination IP). Used by engine.go to route each signal to
// the correct target key space.
var c2DomainAxisSignals = map[string]bool{
	c2SigDGA:       true,
	c2SigFastFlux:  true,
	c2SigDNSTunnel: true,
}

// isDomainAxisSignal reports whether a signal class is correlated by domain (vs IP).
func isDomainAxisSignal(sig string) bool { return c2DomainAxisSignals[sig] }

// classifyC2Signal maps a RuleMatch to a C2 signal class, or "" if it is not one of the
// correlated axes. Keyed on stable RuleName substrings / rule types the network and DNS
// detectors in this package (and the beacon detector) emit.
func classifyC2Signal(m *detectionrules.RuleMatch) string {
	if m == nil {
		return ""
	}
	switch {
	case strings.Contains(m.RuleName, "ビーコン"):
		return c2SigBeacon
	case strings.Contains(m.RuleName, "フィンガープリント"):
		return c2SigJA3
	case m.RuleType == "ioc" && strings.Contains(m.RuleName, "脅威インテリ"):
		return c2SigThreatIntel
	case strings.Contains(m.RuleName, "Fast-Flux"):
		return c2SigFastFlux
	case strings.Contains(m.RuleName, "DGA"):
		return c2SigDGA
	case strings.Contains(m.RuleName, "トンネリング"):
		return c2SigDNSTunnel
	}
	return ""
}

// c2DestIP extracts the destination IP from a flattened network/tls event, tolerating the
// field-name variants ingestion and the alias layer produce. Returns "" when absent (e.g.
// DNS events, which are correlated by domain elsewhere, not here).
func c2DestIP(flat map[string]interface{}) string {
	for _, k := range []string{"dst_ip", "dstIp", "DestinationIp", "destinationIp"} {
		if s, ok := flat[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

type c2State struct {
	signals    map[string]int64 // signal class -> last-seen unix seconds
	lastAlertN int              // distinct-signal count at the last alert (for escalation)
}

// C2Correlator is a stateful, concurrency-safe multi-signal C2 correlator keyed by
// (agentID, destIP).
type C2Correlator struct {
	mu       sync.Mutex
	entities map[string]*c2State
}

func newC2Correlator() *C2Correlator {
	return &C2Correlator{entities: make(map[string]*c2State)}
}

// ObserveSignal records that target (a destination IP or a registrable domain) was
// flagged by signalClass for agentID, and returns a correlated C2 alert when the target
// has been independently flagged by ≥c2MinSignals distinct axes within the window. now is
// injected for deterministic tests. Empty inputs or an unknown signal class are ignored.
func (c *C2Correlator) ObserveSignal(agentID, target, signalClass string, now time.Time) []*detectionrules.RuleMatch {
	if agentID == "" || target == "" || signalClass == "" {
		return nil
	}
	if _, ok := c2SignalLabels[signalClass]; !ok {
		return nil
	}
	nu := now.Unix()
	winSec := int64(c2Window / time.Second)
	key := agentID + "|" + target

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entities) > c2MaxKeys {
		c.evictStale(nu, winSec*2)
	}
	st := c.entities[key]
	if st == nil {
		st = &c2State{signals: make(map[string]int64)}
		c.entities[key] = st
	}
	// Expire signals outside the window.
	for sig, ts := range st.signals {
		if nu-ts > winSec {
			delete(st.signals, sig)
		}
	}
	st.signals[signalClass] = nu

	n := len(st.signals)
	if n < c2MinSignals {
		st.lastAlertN = 0
		return nil
	}
	// Fire on first crossing and escalate as more distinct axes confirm. Re-firing
	// only on growth dedups repeated same-set observations.
	if n <= st.lastAlertN {
		return nil
	}
	st.lastAlertN = n

	sigs := make([]string, 0, len(st.signals))
	for sig := range st.signals {
		sigs = append(sigs, c2SignalLabels[sig])
	}
	sort.Strings(sigs)

	sev := 9
	autoIsolate := false
	if n >= c2IsolateFrom {
		sev = 10
		autoIsolate = true
	}
	return []*detectionrules.RuleMatch{{
		RuleID:      "",
		RuleName:    "C2相関: 複数軸で確証された指令統制通信",
		RuleType:    "correlation",
		Severity:    sev,
		AutoIsolate: autoIsolate,
		Title:       fmt.Sprintf("[C2-CORRELATION] ターゲット %s が%d軸で確証されたC2通信", target, n),
		Description: fmt.Sprintf("ターゲット %s が%d分以内に%d個の独立したC2信号で該当: %s。直交する複数軸の一致はほぼ確実にC2であり、単一軸の誤検知可能性を排除する高信頼相関。",
			target, int(c2Window/time.Minute), n, strings.Join(sigs, " + ")),
		MITRETags: []string{"T1071"}, // Application Layer Protocol (C2)
	}}
}

func (c *C2Correlator) evictStale(nowUnix, maxAgeSec int64) {
	for key, st := range c.entities {
		var newest int64
		for _, ts := range st.signals {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(c.entities, key)
		}
	}
}

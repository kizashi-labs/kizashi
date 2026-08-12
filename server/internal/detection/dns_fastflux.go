// Package detection — dns_fastflux.go: fast-flux DNS infrastructure detection.
//
// dns_aggregate.go counts distinct SUBDOMAINS under one parent (the tunneling shape).
// Fast-flux is the opposite shape: ONE domain that resolves to a rapidly-rotating set
// of many distinct A-record IPs scattered across unrelated networks — the load-balancing
// trick botnets and resilient C2 use to keep a rendezvous name alive as individual bots
// are taken down (T1568.001). A legitimate service load-balances across a handful of IPs
// in one or two netblocks; fast-flux sprays across many /16s. This detector aggregates the
// distinct answer IPs (and their network diversity) per registrable domain per host over a
// window and fires when both the IP count and the network spread cross thresholds — the
// network-spread gate is what separates fast-flux from an ordinary multi-homed service.
package detection

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	fastFluxWindow  = 10 * time.Minute
	fastFluxMinIPs  = 8 // distinct answer IPs for one domain within the window
	fastFluxMinNets = 5 // distinct networks (IPv4 /16, IPv6 /32) — the fast-flux tell
	fastFluxDedup   = 30 * time.Minute
	fastFluxMaxKeys = 8192
)

type fastFluxState struct {
	ips       map[string]int64 // ip string -> last-seen unix seconds
	lastAlert int64
}

// DNSFastFluxDetector is a stateful, concurrency-safe fast-flux detector keyed by
// (agentID, registrable domain).
type DNSFastFluxDetector struct {
	mu   sync.Mutex
	keys map[string]*fastFluxState
}

func newDNSFastFluxDetector() *DNSFastFluxDetector {
	return &DNSFastFluxDetector{keys: make(map[string]*fastFluxState)}
}

// dnsAnswers extracts a DNS event's answer list, tolerating both the native []string
// (in-process) and the []interface{} that a JSON round-trip through ingestion produces.
func dnsAnswers(flat map[string]interface{}) []string {
	switch v := flat["answers"].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ipNetworkKey returns a coarse network grouping for an IP: the first two octets for
// IPv4 (/16) and the first four bytes for IPv6 (/32). Fast-flux scatters IPs across many
// such groups; a legitimate multi-homed service clusters within a few.
func ipNetworkKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d", v4[0], v4[1])
	}
	if len(ip) == net.IPv6len {
		return fmt.Sprintf("%02x%02x:%02x%02x", ip[0], ip[1], ip[2], ip[3])
	}
	return ip.String()
}

// Observe folds a DNS response's answer IPs into the domain's rotating-IP set and returns
// a fast-flux alert when the domain has resolved to ≥fastFluxMinIPs distinct IPs spanning
// ≥fastFluxMinNets distinct networks within the window. now is injected for tests.
func (d *DNSFastFluxDetector) Observe(agentID, query string, answers []string, now time.Time) []*detectionrules.RuleMatch {
	if len(answers) == 0 {
		return nil
	}
	// Key on the FULL name, not the registrable domain. Fast-flux is a property of
	// ONE rendezvous name rotating its address set; it is not a property of an
	// organisation. Aggregating by registrable domain makes any org with enough
	// distinct hosts look like fast-flux, because dc01/dc02/fs01/wks-… each
	// legitimately resolve to their own address in their own netblock. Measured:
	// the 2026-08-02 soak fired on the fleet's own corp domain across all 20 hosts,
	// and on google.com / microsoft.com / bing.com / jsdelivr.net, whose many
	// subdomains pooled the same way.
	//
	// The benign-parent allowlist still applies at the registrable-domain level so
	// one entry keeps covering a whole CDN's subdomains.
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	if name == "" {
		return nil
	}
	reg, _ := registrableAndSub(name)
	if reg == "" || isBenignDNSParent(reg) {
		return nil
	}
	nu := now.Unix()
	winSec := int64(fastFluxWindow / time.Second)
	key := agentID + "|" + name

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.keys) > fastFluxMaxKeys {
		d.evictStale(nu, winSec*3)
	}
	st := d.keys[key]
	if st == nil {
		st = &fastFluxState{ips: make(map[string]int64)}
		d.keys[key] = st
	}
	// Expire IPs outside the window.
	for ip, ts := range st.ips {
		if nu-ts > winSec {
			delete(st.ips, ip)
		}
	}
	// Record each answer that parses as an IP (skip CNAMEs and other RR data).
	for _, a := range answers {
		if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
			st.ips[ip.String()] = nu
		}
	}

	if len(st.ips) < fastFluxMinIPs {
		return nil
	}
	// Network-diversity gate: distinct /16 (or IPv6 /32) groups.
	nets := map[string]struct{}{}
	for ipStr := range st.ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			nets[ipNetworkKey(ip)] = struct{}{}
		}
	}
	if len(nets) < fastFluxMinNets {
		return nil
	}
	if nu-st.lastAlert < int64(fastFluxDedup/time.Second) {
		return nil
	}
	st.lastAlert = nu

	sample := make([]string, 0, len(st.ips))
	for ipStr := range st.ips {
		sample = append(sample, ipStr)
	}
	sort.Strings(sample)
	if len(sample) > 6 {
		sample = sample[:6]
	}
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "Fast-Flux DNS（高速循環IPインフラ）",
		RuleType: "heuristic",
		Severity: 7,
		Title:    fmt.Sprintf("[HEURISTIC] Fast-Flux疑い: '%s' が%d分内に%dIP/%dネットワークへ解決", reg, int(fastFluxWindow/time.Minute), len(st.ips), len(nets)),
		Description: fmt.Sprintf("登録ドメイン '%s' が%d分以内に%d個の異なるIP(%d個の異なる/16ネットワークに分散)へ解決。多数ネットワークへの分散は正規の多重化と異なり、ボットネット/耐障害C2のfast-flux(T1568.001)の特徴。例: %s …",
			reg, int(fastFluxWindow/time.Minute), len(st.ips), len(nets), strings.Join(sample, ", ")),
		MITRETags: []string{"T1568.001", "T1071"}, // Fast Flux DNS / Application Layer C2
	}}
}

func (d *DNSFastFluxDetector) evictStale(nowUnix, maxAgeSec int64) {
	for k, st := range d.keys {
		var newest int64
		for _, ts := range st.ips {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.keys, k)
		}
	}
}

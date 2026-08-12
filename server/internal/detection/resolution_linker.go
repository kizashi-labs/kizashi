// Package detection — resolution_linker.go: DNS-resolution bridge between the C2
// correlator's IP and domain key spaces.
//
// The C2 correlator keys IP-axis signals (beacon/JA3/threat-intel) by destination IP and
// domain-axis signals (DGA/fast-flux/DNS tunnel) by registrable domain — disjoint spaces,
// so a beacon to 1.2.3.4 and a DGA verdict on evil.example never combine, even when
// evil.example resolved TO 1.2.3.4. That is the same infrastructure. This linker records
// the answer IPs of suspicious domains and lets the engine re-key an IP-axis signal onto
// the domain it resolved from, so the two axes correlate into one high-confidence C2 alert
// (a DGA domain whose resolved IP also beacons is not a coincidence).
package detection

import (
	"sync"
	"time"
)

const (
	resLinkWindow  = 30 * time.Minute // must cover the C2 correlator's window
	resLinkMaxKeys = 16384
)

// ResolutionLinker maps (agentID, answer IP) → registrable domain for recently-resolved
// suspicious domains. Concurrency-safe, windowed, bounded.
type ResolutionLinker struct {
	mu  sync.Mutex
	ips map[string]resLink // key: agentID|ip
}

type resLink struct {
	domain string
	ts     int64
}

func newResolutionLinker() *ResolutionLinker {
	return &ResolutionLinker{ips: make(map[string]resLink)}
}

// Record links each answer IP to the domain it resolved from. Call it for domains that
// were themselves flagged by a DNS-axis signal, so only suspicious resolutions are kept.
func (r *ResolutionLinker) Record(agentID, domain string, answerIPs []string, now time.Time) {
	if agentID == "" || domain == "" || len(answerIPs) == 0 {
		return
	}
	nu := now.Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ips) > resLinkMaxKeys {
		r.evictStale(nu)
	}
	for _, ip := range answerIPs {
		if ip == "" {
			continue
		}
		r.ips[agentID+"|"+ip] = resLink{domain: domain, ts: nu}
	}
}

// Domain returns the registrable domain a destination IP was recently resolved from for
// this agent, or "" if there is no fresh link.
func (r *ResolutionLinker) Domain(agentID, ip string, now time.Time) string {
	if agentID == "" || ip == "" {
		return ""
	}
	nu := now.Unix()
	winSec := int64(resLinkWindow / time.Second)
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.ips[agentID+"|"+ip]
	if !ok || nu-l.ts > winSec {
		return ""
	}
	return l.domain
}

func (r *ResolutionLinker) evictStale(nowUnix int64) {
	winSec := int64(resLinkWindow / time.Second)
	for k, l := range r.ips {
		if nowUnix-l.ts > winSec {
			delete(r.ips, k)
		}
	}
}

// Package detection — IOCMatcher provides real-time indicator-of-compromise matching
// against a memory-cached copy of the ioc_entries table.
//
// Cache is refreshed every 5 minutes from DB; individual entries can be invalidated
// via the RefreshNow() method (called on NATS ioc.invalidate signal).
//
// Matched event types and IOC types:
//
//	network → ip   (destination IP)
//	dns     → domain (query name, suffix match)
//	process → hash  (image SHA-256 or MD5, when agent sends hashes)
//	file    → hash  (file SHA-256 or MD5)
package detection

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// IOCRecord is the minimal IOC data held in the cache.
type IOCRecord struct {
	ID          string
	Type        string // ip | domain | hash | url
	Value       string
	Description string
	Severity    int
	Confidence  int // 0-100。多ソース合意で上昇(feed取込時に集計)。アラートに露出。
}

// IOCMatch is returned when an event field matches a known IOC.
type IOCMatch struct {
	IOC       IOCRecord
	MatchedOn string // field name that triggered the match, e.g. "dstIp"
	Value     string // the actual matched value
}

// IOCLoader abstracts the DB query needed to populate the cache.
type IOCLoader interface {
	ListActiveIOCs(ctx context.Context) ([]IOCRecord, error)
}

// cidrEntry is a network-range IP IOC (value like "185.220.101.0/24"), matched by
// containment rather than exact string equality so the whole known-bad block is covered.
type cidrEntry struct {
	net *net.IPNet
	rec *IOCRecord
}

// IOCMatcher maintains an in-memory cache of active IOCs and evaluates events.
type IOCMatcher struct {
	loader   IOCLoader
	mu       sync.RWMutex
	byType   map[string]map[string]*IOCRecord // type → lowercase(value) → record
	cidrs    []cidrEntry                      // "ip" IOCs expressed as CIDR ranges
	loadedAt time.Time
}

func NewIOCMatcher(loader IOCLoader) *IOCMatcher {
	return &IOCMatcher{
		loader: loader,
		byType: make(map[string]map[string]*IOCRecord),
	}
}

// Start loads the initial cache and schedules periodic refreshes.
func (m *IOCMatcher) Start(ctx context.Context) {
	m.refresh(ctx)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refresh(ctx)
			}
		}
	}()
}

// RefreshNow performs an immediate synchronous reload (call after IOC changes).
func (m *IOCMatcher) RefreshNow(ctx context.Context) {
	m.refresh(ctx)
}

func (m *IOCMatcher) refresh(ctx context.Context) {
	entries, err := m.loader.ListActiveIOCs(ctx)
	if err != nil {
		slog.Warn("IOCキャッシュのリフレッシュに失敗しました", "error", err)
		return
	}

	byType := make(map[string]map[string]*IOCRecord, 4)
	var cidrs []cidrEntry
	for i := range entries {
		e := &entries[i]
		// An "ip" IOC whose value is a CIDR range is matched by containment, not by
		// exact string, so a whole known-bad /24 is covered rather than one address.
		if e.Type == "ip" && strings.Contains(e.Value, "/") {
			if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(e.Value)); err == nil {
				cidrs = append(cidrs, cidrEntry{net: ipnet, rec: e})
				continue
			}
		}
		if byType[e.Type] == nil {
			byType[e.Type] = make(map[string]*IOCRecord)
		}
		byType[e.Type][strings.ToLower(e.Value)] = e
	}

	m.mu.Lock()
	m.byType = byType
	m.cidrs = cidrs
	m.loadedAt = time.Now()
	m.mu.Unlock()

	slog.Info("IOCキャッシュをリフレッシュしました", "total", len(entries))
}

// matchCIDR returns the record for the first CIDR-range IP IOC that contains ipStr, or nil.
// Caller holds the read lock.
func (m *IOCMatcher) matchCIDR(ipStr string) *IOCRecord {
	if len(m.cidrs) == 0 {
		return nil
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil
	}
	for i := range m.cidrs {
		if m.cidrs[i].net.Contains(ip) {
			return m.cidrs[i].rec
		}
	}
	return nil
}

// CheckEvent inspects a flattened event map for IOC hits.
// Returns all matches (may be empty).
func (m *IOCMatcher) CheckEvent(flat map[string]interface{}) []IOCMatch {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.byType) == 0 && len(m.cidrs) == 0 {
		return nil
	}

	var matches []IOCMatch

	// ── IP: network events (exact, then CIDR-range containment) ──
	ips := m.byType["ip"]
	if len(ips) > 0 || len(m.cidrs) > 0 {
		for _, field := range []string{"dstIp", "dst_ip", "DestinationIp", "srcIp", "src_ip"} {
			val, ok := stringVal(flat, field)
			if !ok {
				continue
			}
			if rec, hit := ips[strings.ToLower(val)]; hit {
				matches = append(matches, IOCMatch{IOC: *rec, MatchedOn: field, Value: val})
				continue
			}
			if rec := m.matchCIDR(val); rec != nil {
				matches = append(matches, IOCMatch{IOC: *rec, MatchedOn: field, Value: val})
			}
		}
	}

	// ── Domain: DNS events ────────────────────────────────────
	if domains := m.byType["domain"]; len(domains) > 0 {
		for _, field := range []string{"query", "QueryName", "hostname", "Hostname"} {
			if val, ok := stringVal(flat, field); ok {
				lower := strings.ToLower(strings.TrimSuffix(val, "."))
				// Exact match
				if rec, hit := domains[lower]; hit {
					matches = append(matches, IOCMatch{IOC: *rec, MatchedOn: field, Value: val})
					continue
				}
				// Suffix match: ioc="evil.com" matches "sub.evil.com"
				for domain, rec := range domains {
					if strings.HasSuffix(lower, "."+domain) {
						matches = append(matches, IOCMatch{IOC: *rec, MatchedOn: field, Value: val})
						break
					}
				}
			}
		}
	}

	// ── Hash: process / file events ───────────────────────────
	if hashes := m.byType["hash"]; len(hashes) > 0 {
		for _, field := range []string{
			"sha256", "sha256Hash", "md5", "md5Hash",
			"fileSha256", "fileHash", "imageSha256",
		} {
			if val, ok := stringVal(flat, field); ok && val != "" {
				if rec, hit := hashes[strings.ToLower(val)]; hit {
					matches = append(matches, IOCMatch{IOC: *rec, MatchedOn: field, Value: val})
				}
			}
		}
	}

	// ── URL: network / HTTP events ────────────────────────────
	if urls := m.byType["url"]; len(urls) > 0 {
		for _, field := range []string{"url", "URL", "requestUrl"} {
			if val, ok := stringVal(flat, field); ok {
				lower := strings.ToLower(val)
				for urlPattern, rec := range urls {
					if strings.Contains(lower, urlPattern) {
						matches = append(matches, IOCMatch{IOC: *rec, MatchedOn: field, Value: val})
						break
					}
				}
			}
		}
	}

	return matches
}

// CacheSize returns the number of IOCs currently cached (for metrics/health).
func (m *IOCMatcher) CacheSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total := len(m.cidrs)
	for _, m := range m.byType {
		total += len(m)
	}
	return total
}

// LoadedAt returns when the cache was last refreshed.
func (m *IOCMatcher) LoadedAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadedAt
}

func stringVal(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}

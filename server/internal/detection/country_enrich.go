package detection

import (
	"sync"
	"time"

	"github.com/edr-platform/server/internal/geoip"
)

// geoLookup is the slice of *geoip.Locator this package needs; an interface so the
// enricher is unit-testable without real ip-api.com calls.
type geoLookup interface {
	Lookup(ip string) *geoip.Location
}

// countryEnricher populates flatEvent["country_code"] for external destinations
// WITHOUT ever blocking the detection hot path on an external lookup. The backing
// geoip.Locator does a synchronous, un-cached HTTP GET per call (and ip-api.com is
// rate-limited), so calling it inline per network event would add latency and burn
// the quota. Instead Enrich serves cache hits immediately and enqueues cold IPs for
// a bounded, rate-limited background worker to resolve; the cache warms over time so
// country-based rules fire on subsequent events to the same destination.
//
// Opt-in: only constructed when EngineConfig.GeoIPEnrichEnabled is set, because it
// sends destination IPs to an external service — a dependency/privacy choice the
// operator must make explicitly.
type countryEnricher struct {
	lookup      geoLookup
	minInterval time.Duration // spacing between external lookups (rate limit)
	cache       sync.Map      // ip(string) -> country code(string)
	inflight    sync.Map      // ip(string) -> struct{} (dedup pending lookups)
	pending     chan string
}

// newCountryEnricher starts the background worker. minInterval spaces external
// lookups (e.g. 1500ms keeps ip-api.com's free tier of ~45/min happy); pass 0 in
// tests. queue bounds the pending backlog — a full queue drops the enrichment for
// that event rather than blocking or growing unboundedly.
func newCountryEnricher(lookup geoLookup, minInterval time.Duration, queue int) *countryEnricher {
	if queue <= 0 {
		queue = 4096
	}
	c := &countryEnricher{
		lookup:      lookup,
		minInterval: minInterval,
		pending:     make(chan string, queue),
	}
	go c.run()
	return c
}

// Enrich sets flat["country_code"] from cache for an external dst_ip. On a cache
// miss it enqueues an async lookup (deduped) and leaves the field unset for this
// event. Never performs I/O itself, so it is safe on the detection hot path.
func (c *countryEnricher) Enrich(flat map[string]interface{}) {
	if c == nil {
		return
	}
	if _, ok := flat["country_code"]; ok {
		return
	}
	dst, _ := flat["dst_ip"].(string)
	if dst == "" || !isExternalIP(dst) {
		return
	}
	if v, ok := c.cache.Load(dst); ok {
		flat["country_code"] = v
		return
	}
	// Cold: enqueue once. LoadOrStore dedups concurrent misses for the same IP.
	if _, loaded := c.inflight.LoadOrStore(dst, struct{}{}); loaded {
		return
	}
	select {
	case c.pending <- dst:
	default:
		// Queue full — drop this enrichment (best-effort), clear the dedup marker
		// so a later event can retry.
		c.inflight.Delete(dst)
	}
}

func (c *countryEnricher) run() {
	for ip := range c.pending {
		code := "XX"
		if loc := c.lookup.Lookup(ip); loc != nil && loc.CountryCode != "" {
			code = loc.CountryCode
		}
		c.cache.Store(ip, code)
		c.inflight.Delete(ip)
		if c.minInterval > 0 {
			time.Sleep(c.minInterval)
		}
	}
}

// maybeCountryEnricher returns an async country enricher when GeoIP enrichment is
// enabled in the engine config, else nil. The enricher's Enrich method is nil-safe,
// so callers may invoke it unconditionally.
func maybeCountryEnricher(config EngineConfig) *countryEnricher {
	if !config.GeoIPEnrichEnabled {
		return nil
	}
	return newCountryEnricher(geoip.NewLocator(), 1500*time.Millisecond, 4096)
}

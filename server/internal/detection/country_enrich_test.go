package detection

import (
	"sync"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/geoip"
)

type fakeGeo struct {
	mu    sync.Mutex
	calls map[string]int
	code  string
}

func (f *fakeGeo) Lookup(ip string) *geoip.Location {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[ip]++
	return &geoip.Location{IP: ip, CountryCode: f.code}
}

func (f *fakeGeo) count(ip string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[ip]
}

// TestCountryEnricher verifies the enricher never blocks the hot path (cold miss
// leaves the field unset and enqueues), warms the cache asynchronously, serves
// subsequent events from cache, dedups repeated lookups, and skips internal IPs.
func TestCountryEnricher(t *testing.T) {
	f := &fakeGeo{code: "RU"}
	c := newCountryEnricher(f, 0, 16)

	// Cold miss: does not block, does not set country_code yet.
	ev := map[string]interface{}{"dst_ip": "203.0.113.9"}
	c.Enrich(ev)
	if _, ok := ev["country_code"]; ok {
		t.Fatalf("cold miss must not set country_code inline, got %v", ev["country_code"])
	}

	// Background worker warms the cache; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := c.cache.Load("203.0.113.9"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cache was not warmed by the background worker")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Subsequent event to the same external dst is served from cache.
	ev2 := map[string]interface{}{"dst_ip": "203.0.113.9"}
	c.Enrich(ev2)
	if ev2["country_code"] != "RU" {
		t.Errorf("warm cache must set country_code=RU, got %v", ev2["country_code"])
	}

	// Internal IPs are skipped entirely (no lookup, no field).
	evInt := map[string]interface{}{"dst_ip": "10.0.0.5"}
	c.Enrich(evInt)
	if _, ok := evInt["country_code"]; ok {
		t.Error("internal dst_ip must not be enriched")
	}
	if f.count("10.0.0.5") != 0 {
		t.Error("internal dst_ip must not trigger a lookup")
	}

	// Dedup: the single cold miss resulted in exactly one external lookup.
	if got := f.count("203.0.113.9"); got != 1 {
		t.Errorf("expected exactly 1 lookup for the external IP, got %d", got)
	}

	// Already-set country_code is left untouched.
	evPre := map[string]interface{}{"dst_ip": "203.0.113.9", "country_code": "US"}
	c.Enrich(evPre)
	if evPre["country_code"] != "US" {
		t.Errorf("pre-set country_code must be preserved, got %v", evPre["country_code"])
	}
}

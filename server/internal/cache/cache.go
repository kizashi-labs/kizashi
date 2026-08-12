// Package cache provides a simple in-memory TTL cache for expensive queries.
// It intentionally has no imports from the rest of the project to avoid cycles.
package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// entry is a single cached value with an expiry timestamp.
type entry struct {
	value     any
	expiresAt time.Time
}

// CacheStats holds hit/miss counters and derived rate.
type CacheStats struct {
	Items   int     `json:"items"`
	Hits    int64   `json:"hits"`
	Misses  int64   `json:"misses"`
	HitRate float64 `json:"hit_rate"`
}

// Cache is a concurrent in-memory TTL cache.
type Cache struct {
	data   sync.Map
	hits   atomic.Int64
	misses atomic.Int64
}

// New creates a Cache and starts a background goroutine that removes
// expired entries at the given cleanupInterval.
func New(cleanupInterval time.Duration) *Cache {
	c := &Cache{}
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			c.evictExpired()
		}
	}()
	return c
}

// Set stores value under key with the given TTL.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.data.Store(key, &entry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	})
}

// Get retrieves the value for key. Returns (value, true) on a cache hit.
func (c *Cache) Get(key string) (any, bool) {
	v, ok := c.data.Load(key)
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	e, _ := v.(*entry)
	if e == nil || time.Now().After(e.expiresAt) {
		c.data.Delete(key)
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return e.value, true
}

// Delete removes a single key from the cache.
func (c *Cache) Delete(key string) {
	c.data.Delete(key)
}

// Flush removes all entries from the cache.
func (c *Cache) Flush() {
	c.data.Range(func(k, _ any) bool {
		c.data.Delete(k)
		return true
	})
}

// Stats returns current hit/miss counters and item count.
func (c *Cache) Stats() CacheStats {
	var items int
	c.data.Range(func(_, _ any) bool {
		items++
		return true
	})
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	return CacheStats{
		Items:   items,
		Hits:    hits,
		Misses:  misses,
		HitRate: hitRate,
	}
}

// evictExpired removes entries whose TTL has passed.
func (c *Cache) evictExpired() {
	now := time.Now()
	c.data.Range(func(k, v any) bool {
		if e, ok := v.(*entry); ok && now.After(e.expiresAt) {
			c.data.Delete(k)
		}
		return true
	})
}

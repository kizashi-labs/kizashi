package middleware

import (
	"bytes"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type cacheEntry struct {
	body        []byte
	contentType string
	statusCode  int
	expiresAt   time.Time
	createdAt   time.Time
}

type responseCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	maxSize int
	hits    int64
	misses  int64
}

var globalCache = &responseCache{
	entries: make(map[string]*cacheEntry),
	maxSize: 1000,
}

// responseRecorder captures the response written by downstream handlers.
type responseRecorder struct {
	gin.ResponseWriter
	body   *bytes.Buffer
	status int
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) WriteString(s string) (int, error) {
	r.body.WriteString(s)
	return r.ResponseWriter.WriteString(s)
}

// CacheMiddleware returns a gin middleware that caches GET responses for the given TTL.
func CacheMiddleware(ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only cache GET requests
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}

		key := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			key = key + "?" + c.Request.URL.RawQuery
		}

		// Check cache for a hit
		globalCache.mu.RLock()
		entry, ok := globalCache.entries[key]
		globalCache.mu.RUnlock()

		if ok && time.Now().Before(entry.expiresAt) {
			// Cache HIT
			globalCache.mu.Lock()
			globalCache.hits++
			globalCache.mu.Unlock()

			c.Header("X-Cache", "HIT")
			c.Data(entry.statusCode, entry.contentType, entry.body)
			c.Abort()
			return
		}

		// Cache MISS — record the response
		globalCache.mu.Lock()
		globalCache.misses++
		globalCache.mu.Unlock()

		c.Header("X-Cache", "MISS")

		rec := &responseRecorder{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
			status:         http.StatusOK,
		}
		c.Writer = rec

		c.Next()

		// Only cache successful responses
		if rec.status >= 200 && rec.status < 300 {
			newEntry := &cacheEntry{
				body:        rec.body.Bytes(),
				contentType: rec.Header().Get("Content-Type"),
				statusCode:  rec.status,
				expiresAt:   time.Now().Add(ttl),
				createdAt:   time.Now(),
			}

			globalCache.mu.Lock()
			// Evict oldest entry if at capacity
			if len(globalCache.entries) >= globalCache.maxSize {
				var oldestKey string
				var oldestTime time.Time
				for k, e := range globalCache.entries {
					if oldestKey == "" || e.createdAt.Before(oldestTime) {
						oldestKey = k
						oldestTime = e.createdAt
					}
				}
				if oldestKey != "" {
					delete(globalCache.entries, oldestKey)
				}
			}
			globalCache.entries[key] = newEntry
			globalCache.mu.Unlock()
		}
	}
}

// CacheStats returns a handler that reports cache statistics.
func CacheStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		globalCache.mu.RLock()
		size := len(globalCache.entries)
		hits := globalCache.hits
		misses := globalCache.misses
		globalCache.mu.RUnlock()

		total := hits + misses
		var hitRate float64
		if total > 0 {
			hitRate = float64(hits) / float64(total)
		}

		c.JSON(http.StatusOK, gin.H{
			"size":     size,
			"max_size": globalCache.maxSize,
			"hits":     hits,
			"misses":   misses,
			"hit_rate": hitRate,
		})
	}
}

// CacheClear returns a handler that clears all cache entries.
func CacheClear() gin.HandlerFunc {
	return func(c *gin.Context) {
		globalCache.mu.Lock()
		cleared := len(globalCache.entries)
		globalCache.entries = make(map[string]*cacheEntry)
		globalCache.mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"cleared": cleared,
		})
	}
}

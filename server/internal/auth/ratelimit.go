package auth

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimitDisabled bypasses the auth-endpoint rate limiter when set. Intended
// ONLY for E2E/CI where many auth requests originate from a single shared IP.
// Never enable in production. Shares the DISABLE_LOGIN_RATE_LIMIT flag with the
// brute-force login lockout in the handlers package.
var rateLimitDisabled = os.Getenv("DISABLE_LOGIN_RATE_LIMIT") == "true"

type windowEntry struct {
	count   int
	resetAt time.Time
}

// RateLimiter is a fixed-window in-memory IP-based rate limiter.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*windowEntry
	limit   int
	window  time.Duration
}

// NewRateLimiter creates a RateLimiter allowing at most limit requests per window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*windowEntry),
		limit:   limit,
		window:  window,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow returns true if the key is within the rate limit.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.entries[key]
	if !ok || now.After(e.resetAt) {
		rl.entries[key] = &windowEntry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if e.count >= rl.limit {
		return false
	}
	e.count++
	return true
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, e := range rl.entries {
			if now.After(e.resetAt) {
				delete(rl.entries, k)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns a Gin handler that rate-limits by client IP.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if rateLimitDisabled {
			c.Next()
			return
		}
		if !rl.Allow(c.ClientIP()) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "リクエストが多すぎます。しばらく待ってから再試行してください。",
			})
			return
		}
		c.Next()
	}
}

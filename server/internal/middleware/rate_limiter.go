package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// tokenBucket implements the token bucket rate limiting algorithm.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newTokenBucket(capacity, refillRate float64) *tokenBucket {
	return &tokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = minFloat64(b.capacity, b.tokens+elapsed*b.refillRate)
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens--
		return true
	}
	return false
}

func minFloat64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// RateLimiter holds per-IP token buckets.
type RateLimiter struct {
	mu        sync.RWMutex
	buckets   map[string]*tokenBucket
	capacity  float64
	rate      float64
	lastClean time.Time
}

// NewRateLimiter creates a rate limiter.
// capacity: max burst (e.g. 60)
// ratePerSecond: steady-state rate (e.g. 1.0 = 60/min)
func NewRateLimiter(capacity, ratePerSecond float64) *RateLimiter {
	return &RateLimiter{
		buckets:   make(map[string]*tokenBucket),
		capacity:  capacity,
		rate:      ratePerSecond,
		lastClean: time.Now(),
	}
}

// Middleware returns a Gin middleware that rate-limits by IP.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		rl.mu.Lock()
		bucket, ok := rl.buckets[ip]
		if !ok {
			bucket = newTokenBucket(rl.capacity, rl.rate)
			rl.buckets[ip] = bucket
		}
		// Periodic cleanup of old buckets
		if time.Since(rl.lastClean) > 10*time.Minute {
			rl.cleanup()
		}
		rl.mu.Unlock()

		if !bucket.allow() {
			c.Header("Retry-After", "1")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":               "rate limit exceeded",
				"retry_after_seconds": 1,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// StrictMiddleware is a stricter rate limiter for auth endpoints.
func (rl *RateLimiter) StrictMiddleware() gin.HandlerFunc {
	strict := NewRateLimiter(10, 0.1) // 10 burst, 6/min
	return strict.Middleware()
}

func (rl *RateLimiter) cleanup() {
	// Remove buckets not used in last 10 minutes
	// (simplified: just clear all — buckets will be recreated on demand)
	rl.buckets = make(map[string]*tokenBucket)
	rl.lastClean = time.Now()
}

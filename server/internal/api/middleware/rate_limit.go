package middleware

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimitDisabled bypasses all token-bucket rate limiters when set. Intended
// ONLY for E2E/CI, where the whole suite hits the API from a single shared IP
// and would otherwise exhaust the per-IP buckets (StrictRateLimit on /auth in
// particular). Never enable in production. Shares the DISABLE_LOGIN_RATE_LIMIT
// flag used by the auth package limiters.
var rateLimitDisabled = os.Getenv("DISABLE_LOGIN_RATE_LIMIT") == "true"

// tokenBucket is a simple token bucket rate limiter.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func newTokenBucket(maxTokens, refillRate float64) *tokenBucket {
	return &tokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = minFloat(b.maxTokens, b.tokens+elapsed*b.refillRate)
	b.lastRefill = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ipRateLimiter manages per-IP token buckets.
type ipRateLimiter struct {
	buckets    map[string]*tokenBucket
	mu         sync.Mutex
	maxTokens  float64
	refillRate float64
}

func newIPRateLimiter(maxTokens, refillRate float64) *ipRateLimiter {
	rl := &ipRateLimiter{
		buckets:    make(map[string]*tokenBucket),
		maxTokens:  maxTokens,
		refillRate: refillRate,
	}
	go rl.cleanup()
	return rl
}

func (rl *ipRateLimiter) getBucket(ip string) *tokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok {
		b = newTokenBucket(rl.maxTokens, rl.refillRate)
		rl.buckets[ip] = b
	}
	return b
}

func (rl *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			b.mu.Lock()
			// Remove buckets that are full (idle clients)
			if b.tokens >= b.maxTokens {
				delete(rl.buckets, ip)
			}
			b.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// RateLimit returns a gin middleware that rate-limits by client IP.
// maxTokens: burst size, refillRate: tokens per second (e.g. 10 = 10 req/sec steady state)
func RateLimit(maxTokens, refillRate float64) gin.HandlerFunc {
	limiter := newIPRateLimiter(maxTokens, refillRate)
	return func(c *gin.Context) {
		if rateLimitDisabled {
			c.Next()
			return
		}
		ip := c.ClientIP()
		if !limiter.getBucket(ip).allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "リクエスト制限を超えました。しばらく待ってから再試行してください。",
				"retry_after": "1",
			})
			c.Header("Retry-After", "1")
			c.Abort()
			return
		}
		c.Next()
	}
}

// StrictRateLimit is a stricter limiter for sensitive endpoints (auth, etc.)
func StrictRateLimit() gin.HandlerFunc {
	return RateLimit(5, 0.1) // 5 burst, 1 req/10sec steady
}

// APIRateLimit is for general API endpoints.
func APIRateLimit() gin.HandlerFunc {
	return RateLimit(100, 10) // 100 burst, 10 req/sec steady
}

// HeavyOperationRateLimit limits CPU/IO-intensive operations such as report
// generation, data exports, and forensics collection.
// Allows 3 concurrent bursts, refilling at 1 request per minute.
func HeavyOperationRateLimit() gin.HandlerFunc {
	return RateLimit(3, 1.0/60) // 3 burst, 1 req/min steady
}

// LiveResponseRateLimit limits live-response command submission to prevent
// accidental or malicious command flooding against managed endpoints.
// Allows 10 burst, refilling at 2 requests per second.
func LiveResponseRateLimit() gin.HandlerFunc {
	return RateLimit(10, 2) // 10 burst, 2 req/sec steady
}

// BulkWriteRateLimit limits bulk write operations (mass alert updates, bulk
// quarantine, batch tag assignment, etc.).
// Allows 20 burst, refilling at 5 requests per second.
func BulkWriteRateLimit() gin.HandlerFunc {
	return RateLimit(20, 5) // 20 burst, 5 req/sec steady
}

// Package auth provides JWT token management utilities.
package auth

import (
	"sync"
	"time"
)

// TokenBlocklist tracks revoked JWT IDs (JTI) in memory.
// Entries auto-expire when the original token would have expired,
// so the list stays bounded even without explicit cleanup.
//
// Thread-safe. The cleanup goroutine should be started once at startup via StartCleanup.
type TokenBlocklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti → token expiry
}

// NewTokenBlocklist creates an empty blocklist.
func NewTokenBlocklist() *TokenBlocklist {
	return &TokenBlocklist{
		entries: make(map[string]time.Time),
	}
}

// Revoke adds a JTI to the blocklist until its natural expiry.
func (b *TokenBlocklist) Revoke(jti string, expiry time.Time) {
	b.mu.Lock()
	b.entries[jti] = expiry
	b.mu.Unlock()
}

// IsRevoked reports whether the JTI has been revoked and the revocation is still active.
func (b *TokenBlocklist) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	b.mu.RLock()
	exp, ok := b.entries[jti]
	b.mu.RUnlock()
	if !ok {
		return false
	}
	// If the token has naturally expired anyway, it's not a concern —
	// but return true to be consistent (expired tokens are also rejected by JWT validation).
	return time.Now().Before(exp)
}

// StartCleanup starts a background goroutine that removes expired entries every minute.
// Call once at application startup.
func (b *TokenBlocklist) StartCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			b.pruneExpired()
		}
	}()
}

func (b *TokenBlocklist) pruneExpired() {
	now := time.Now()
	b.mu.Lock()
	for jti, exp := range b.entries {
		if now.After(exp) {
			delete(b.entries, jti)
		}
	}
	b.mu.Unlock()
}

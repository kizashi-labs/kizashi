package auth

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const userCacheTTL = 5 * time.Minute

type userStatusEntry struct {
	active   bool
	loadedAt time.Time
}

// UserStatusCache provides a short-lived in-memory cache of user active status.
// This lets the auth middleware avoid a DB hit on every request while still
// reflecting account deactivation within ~5 minutes.
type UserStatusCache struct {
	mu   sync.Map // userID → *userStatusEntry
	pool *pgxpool.Pool
}

// NewUserStatusCache creates a UserStatusCache backed by the given DB pool.
func NewUserStatusCache(pool *pgxpool.Pool) *UserStatusCache {
	return &UserStatusCache{pool: pool}
}

// IsActive returns true if the user account is currently active.
// Uses a 5-minute TTL in-memory cache to avoid per-request DB queries.
// Returns true on DB errors to avoid inadvertent lockouts.
func (c *UserStatusCache) IsActive(ctx context.Context, userID string) bool {
	if v, ok := c.mu.Load(userID); ok {
		entry := v.(*userStatusEntry)
		if time.Since(entry.loadedAt) < userCacheTTL {
			return entry.active
		}
	}

	// Cache miss or expired — load from DB
	var active bool
	err := c.pool.QueryRow(ctx,
		"SELECT is_active FROM users WHERE id = $1", userID,
	).Scan(&active)
	if err != nil {
		// Unknown user or DB error: allow through to avoid false lockouts.
		// JWT expiry still protects against indefinitely stale tokens.
		return true
	}

	c.mu.Store(userID, &userStatusEntry{active: active, loadedAt: time.Now()})
	return active
}

// Invalidate removes a user from the cache, forcing a DB check on the next request.
// Call this immediately after deactivating a user.
func (c *UserStatusCache) Invalidate(userID string) {
	c.mu.Delete(userID)
}

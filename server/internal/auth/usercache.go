package auth

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
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
	if errors.Is(err, pgx.ErrNoRows) {
		// そのユーザーがもう存在しない。トークンは通しません。
		// 以前はここも DB 障害と同じ「通す」でした。削除したユーザーの
		// トークンが、期限切れまで有効なままになります。
		slog.Warn("usercache: 存在しないユーザーのトークンを拒否しました", "user", userID)
		return false
	}
	if err != nil {
		// DB 障害のときは通します。ここは意図した fail-open です ——
		// データベースが落ちている間、全員を締め出すほうが被害が大きい。
		// ただし黙って通すのはやめました。無効化したはずの利用者が通り
		// 続けている時間帯が、ログにも何にも残らないからです。
		// JWT の期限は依然として効きます。
		slog.Error("usercache: 利用者の状態を確認できないまま通しました（fail-open）",
			"user", userID, "error", err)
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

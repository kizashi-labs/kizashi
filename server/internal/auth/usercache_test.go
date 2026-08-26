package auth

import (
	"context"
	"testing"
	"time"
)

// ─── UserStatusCache ────────────────────────────────────────────────────────

func TestNewUserStatusCache_NotNil(t *testing.T) {
	c := NewUserStatusCache(nil)
	if c == nil {
		t.Fatal("NewUserStatusCache は nil を返すべきではありません")
	}
}

func TestUserStatusCache_IsActive_FreshCacheHit_ReturnsActiveTrue(t *testing.T) {
	// pool=nil: a DB hit would panic, so a non-panicking true result proves the
	// fresh cache entry was used and the DB was never touched.
	c := NewUserStatusCache(nil)
	c.mu.Store("user-1", &userStatusEntry{active: true, loadedAt: time.Now()})

	if !c.IsActive(context.Background(), "user-1") {
		t.Error("有効なキャッシュエントリーは active=true を返すべきです")
	}
}

func TestUserStatusCache_IsActive_FreshCacheHit_ReturnsActiveFalse(t *testing.T) {
	c := NewUserStatusCache(nil)
	c.mu.Store("user-2", &userStatusEntry{active: false, loadedAt: time.Now()})

	if c.IsActive(context.Background(), "user-2") {
		t.Error("無効化済みユーザーのキャッシュエントリーは active=false を返すべきです（アカウント無効化の反映）")
	}
}

func TestUserStatusCache_IsActive_JustWithinTTL_UsesCachedValue(t *testing.T) {
	c := NewUserStatusCache(nil)
	// TTLぎりぎり手前（まだ有効なキャッシュ）
	c.mu.Store("user-3", &userStatusEntry{active: false, loadedAt: time.Now().Add(-(userCacheTTL - time.Second))})

	if c.IsActive(context.Background(), "user-3") {
		t.Error("TTL内のキャッシュエントリーはDBに問い合わせず、キャッシュ値を返すべきです")
	}
}

func TestUserStatusCache_IsActive_ExpiredCache_DoesNotTrustStaleEntry(t *testing.T) {
	// SECURITY: once the TTL has elapsed, a deactivated (or any changed) account
	// must be re-verified against the DB rather than trusting a stale in-memory
	// entry indefinitely. With pool=nil, that re-verification attempt panics —
	// which is exactly what proves the stale entry was NOT trusted blindly.
	c := NewUserStatusCache(nil)
	c.mu.Store("user-4", &userStatusEntry{active: true, loadedAt: time.Now().Add(-userCacheTTL - time.Minute)})

	defer func() {
		if r := recover(); r == nil {
			t.Error("TTL失効後は再度DB照会を試みるべきです（キャッシュを無条件に信頼してはいけません）")
		}
	}()
	c.IsActive(context.Background(), "user-4")
}

func TestUserStatusCache_Invalidate_RemovesEntryFromCache(t *testing.T) {
	c := NewUserStatusCache(nil)
	c.mu.Store("user-5", &userStatusEntry{active: true, loadedAt: time.Now()})

	c.Invalidate("user-5")

	if _, ok := c.mu.Load("user-5"); ok {
		t.Error("Invalidate 後はキャッシュにエントリーが残っていてはいけません")
	}
}

func TestUserStatusCache_Invalidate_ForcesRecheckOnNextIsActive(t *testing.T) {
	// SECURITY: after deactivating a user, callers invoke Invalidate so the very
	// next IsActive check re-verifies against the DB immediately, instead of
	// waiting out the remainder of the TTL window. Panic (nil pool) proves the
	// DB path was actually attempted.
	c := NewUserStatusCache(nil)
	c.mu.Store("user-6", &userStatusEntry{active: true, loadedAt: time.Now()})
	c.Invalidate("user-6")

	defer func() {
		if r := recover(); r == nil {
			t.Error("Invalidate 後は次回の IsActive が必ずDB照会を試みるべきです")
		}
	}()
	c.IsActive(context.Background(), "user-6")
}

func TestUserStatusCache_Invalidate_UnknownUser_NoPanic(t *testing.T) {
	c := NewUserStatusCache(nil)
	// キャッシュされていないユーザーの Invalidate はパニックしてはいけません。
	c.Invalidate("never-cached")
}

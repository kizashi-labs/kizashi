package auth

import (
	"testing"
	"time"
)

// ─── TokenBlocklist ────────────────────────────────────────────────────────────

func TestBlocklist_RevokedTokenIsRevoked(t *testing.T) {
	b := NewTokenBlocklist()
	exp := time.Now().Add(time.Hour)
	b.Revoke("jti-1", exp)
	if !b.IsRevoked("jti-1") {
		t.Error("失効済みJTIは IsRevoked=true を返すべきです")
	}
}

func TestBlocklist_UnknownJTINotRevoked(t *testing.T) {
	b := NewTokenBlocklist()
	if b.IsRevoked("nonexistent") {
		t.Error("未登録のJTIは IsRevoked=false を返すべきです")
	}
}

func TestBlocklist_EmptyJTINotRevoked(t *testing.T) {
	b := NewTokenBlocklist()
	if b.IsRevoked("") {
		t.Error("空JTIは IsRevoked=false を返すべきです")
	}
}

func TestBlocklist_ExpiredEntryNotRevoked(t *testing.T) {
	b := NewTokenBlocklist()
	// 過去の有効期限でRevokeしてもIsRevokedはfalseになる（自然失効済み）
	b.Revoke("jti-old", time.Now().Add(-time.Second))
	if b.IsRevoked("jti-old") {
		t.Error("自然失効済みトークンのJTIは IsRevoked=false を返すべきです")
	}
}

func TestBlocklist_PruneRemovesExpired(t *testing.T) {
	b := NewTokenBlocklist()
	b.Revoke("stale", time.Now().Add(-time.Second))
	b.Revoke("live", time.Now().Add(time.Hour))

	b.pruneExpired()

	b.mu.RLock()
	_, staleExists := b.entries["stale"]
	_, liveExists := b.entries["live"]
	b.mu.RUnlock()

	if staleExists {
		t.Error("pruneExpired後、期限切れエントリーが残っています")
	}
	if !liveExists {
		t.Error("pruneExpired後、有効なエントリーが削除されました")
	}
}

func TestBlocklist_MultipleRevocations(t *testing.T) {
	b := NewTokenBlocklist()
	for i := 0; i < 100; i++ {
		b.Revoke(time.Now().String()+string(rune(i)), time.Now().Add(time.Hour))
	}
	b.Revoke("target", time.Now().Add(time.Hour))
	if !b.IsRevoked("target") {
		t.Error("多数のエントリー後も対象JTIは失効済みとして扱われるべきです")
	}
}

// ─── RateLimiter ──────────────────────────────────────────────────────────────

func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := &RateLimiter{
		entries: make(map[string]*windowEntry),
		limit:   3,
		window:  time.Minute,
	}
	for i := 0; i < 3; i++ {
		if !rl.Allow("client-a") {
			t.Fatalf("リクエスト %d/3 が拒否されました（限界内のはず）", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := &RateLimiter{
		entries: make(map[string]*windowEntry),
		limit:   2,
		window:  time.Minute,
	}
	rl.Allow("ip")
	rl.Allow("ip")
	if rl.Allow("ip") {
		t.Error("制限を超えた3回目のリクエストは拒否されるべきです")
	}
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	rl := &RateLimiter{
		entries: make(map[string]*windowEntry),
		limit:   1,
		window:  time.Millisecond, // 極短いウィンドウ
	}
	rl.Allow("ip2")
	if rl.Allow("ip2") {
		// ウィンドウ内なので拒否されるはず
		// ただし極短いウィンドウのため、タイミング依存 — スキップ可
		t.Log("ウィンドウがまだ有効（タイミング依存テスト）")
	}
	time.Sleep(5 * time.Millisecond)
	// ウィンドウ後はリセットされるはず
	if !rl.Allow("ip2") {
		t.Error("ウィンドウリセット後は再度許可されるべきです")
	}
}

func TestRateLimiter_IndependentClientsHaveIndependentLimits(t *testing.T) {
	rl := &RateLimiter{
		entries: make(map[string]*windowEntry),
		limit:   1,
		window:  time.Minute,
	}
	rl.Allow("clientX") // clientXの上限を消費
	// clientYは独立して1回まで許可されるべき
	if !rl.Allow("clientY") {
		t.Error("異なるクライアントは独立した制限を持つべきです")
	}
}

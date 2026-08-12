package middleware

import (
	"testing"
	"time"
)

// ─── minFloat64 ───────────────────────────────────────────────────────────────

func TestMinFloat64_ASmaller(t *testing.T) {
	if got := minFloat64(1.0, 2.0); got != 1.0 {
		t.Errorf("minFloat64(1,2): got %f, want 1.0", got)
	}
}

func TestMinFloat64_BSmaller(t *testing.T) {
	if got := minFloat64(3.0, 2.5); got != 2.5 {
		t.Errorf("minFloat64(3,2.5): got %f, want 2.5", got)
	}
}

func TestMinFloat64_Equal(t *testing.T) {
	if got := minFloat64(5.0, 5.0); got != 5.0 {
		t.Errorf("minFloat64(5,5): got %f, want 5.0", got)
	}
}

func TestMinFloat64_Negative(t *testing.T) {
	if got := minFloat64(-1.0, -2.0); got != -2.0 {
		t.Errorf("minFloat64(-1,-2): got %f, want -2.0", got)
	}
}

// ─── newTokenBucket ───────────────────────────────────────────────────────────

func TestNewTokenBucket_NotNil(t *testing.T) {
	b := newTokenBucket(10, 1.0)
	if b == nil {
		t.Fatal("newTokenBucket は nil を返すべきではありません")
	}
}

func TestNewTokenBucket_InitialTokensEqualCapacity(t *testing.T) {
	b := newTokenBucket(20, 2.0)
	if b.tokens != 20 {
		t.Errorf("初期 tokens: got %f, want 20", b.tokens)
	}
}

func TestNewTokenBucket_CapacitySet(t *testing.T) {
	b := newTokenBucket(15, 1.0)
	if b.capacity != 15 {
		t.Errorf("capacity: got %f, want 15", b.capacity)
	}
}

func TestNewTokenBucket_RefillRateSet(t *testing.T) {
	b := newTokenBucket(10, 2.5)
	if b.refillRate != 2.5 {
		t.Errorf("refillRate: got %f, want 2.5", b.refillRate)
	}
}

func TestNewTokenBucket_LastRefillIsRecent(t *testing.T) {
	before := time.Now()
	b := newTokenBucket(10, 1.0)
	after := time.Now()
	if b.lastRefill.Before(before) || b.lastRefill.After(after) {
		t.Error("lastRefill は現在時刻付近に設定されるべきです")
	}
}

// ─── tokenBucket.allow ────────────────────────────────────────────────────────

func TestAllow_WithinCapacity_ReturnsTrue(t *testing.T) {
	b := newTokenBucket(5, 1.0)
	for i := 0; i < 5; i++ {
		if !b.allow() {
			t.Errorf("allow [%d]: 容量内なので true を返すべきです", i)
		}
	}
}

func TestAllow_ExceedsCapacity_ReturnsFalse(t *testing.T) {
	b := newTokenBucket(3, 0.0) // 補充なし
	b.allow()
	b.allow()
	b.allow()
	// 4回目は false
	if b.allow() {
		t.Error("容量超過: false を返すべきです")
	}
}

func TestAllow_EmptyBucket_ReturnsFalse(t *testing.T) {
	b := newTokenBucket(1, 0.0)
	b.allow() // トークン消費
	if b.allow() {
		t.Error("空のバケット: false を返すべきです")
	}
}

func TestAllow_AfterRefill_ReturnsTrue(t *testing.T) {
	// refillRate=1000/sec → 1ms で十分なトークンが補充される
	b := newTokenBucket(1, 1000.0)
	b.allow() // 1トークン消費
	time.Sleep(2 * time.Millisecond)
	if !b.allow() {
		t.Error("補充後: true を返すべきです")
	}
}

func TestAllow_TokensDoNotExceedCapacity(t *testing.T) {
	b := newTokenBucket(5, 100.0)
	// 長時間待っても capacity を超えないことを確認
	time.Sleep(10 * time.Millisecond) // 1秒 * 100 = 100トークン相当経過
	b.allow()                         // allow() 内でリフィル計算が走る
	if b.tokens > b.capacity {
		t.Errorf("tokens が capacity を超えています: tokens=%f, capacity=%f", b.tokens, b.capacity)
	}
}

// ─── NewRateLimiter ───────────────────────────────────────────────────────────

func TestNewRateLimiter_NotNil(t *testing.T) {
	rl := NewRateLimiter(60, 1.0)
	if rl == nil {
		t.Fatal("NewRateLimiter は nil を返すべきではありません")
	}
}

func TestNewRateLimiter_CapacitySet(t *testing.T) {
	rl := NewRateLimiter(60, 1.0)
	if rl.capacity != 60 {
		t.Errorf("capacity: got %f, want 60", rl.capacity)
	}
}

func TestNewRateLimiter_RateSet(t *testing.T) {
	rl := NewRateLimiter(60, 2.0)
	if rl.rate != 2.0 {
		t.Errorf("rate: got %f, want 2.0", rl.rate)
	}
}

func TestNewRateLimiter_BucketsMapInitialized(t *testing.T) {
	rl := NewRateLimiter(60, 1.0)
	if rl.buckets == nil {
		t.Error("buckets マップが初期化されていません")
	}
}

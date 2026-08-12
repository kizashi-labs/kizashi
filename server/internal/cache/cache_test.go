package cache

import (
	"testing"
	"time"
)

// ─── Set / Get ────────────────────────────────────────────────────────────────

func TestCache_SetAndGet(t *testing.T) {
	c := &Cache{}
	c.Set("key1", "value1", time.Minute)

	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("SetしたキーはGetで取得できるべきです")
	}
	if val != "value1" {
		t.Errorf("Get: got %v, want value1", val)
	}
}

func TestCache_GetMiss_UnknownKey(t *testing.T) {
	c := &Cache{}
	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("存在しないキーはok=falseを返すべきです")
	}
}

func TestCache_GetExpired_ReturnsMiss(t *testing.T) {
	c := &Cache{}
	c.Set("exp-key", "value", -time.Second) // 即時期限切れ

	_, ok := c.Get("exp-key")
	if ok {
		t.Error("期限切れエントリーはok=falseを返すべきです")
	}
}

func TestCache_OverwriteKey(t *testing.T) {
	c := &Cache{}
	c.Set("k", "first", time.Minute)
	c.Set("k", "second", time.Minute)

	val, ok := c.Get("k")
	if !ok {
		t.Fatal("上書き後もキーは取得できるべきです")
	}
	if val != "second" {
		t.Errorf("上書き後: got %v, want second", val)
	}
}

func TestCache_StoresAnyType(t *testing.T) {
	c := &Cache{}
	c.Set("int-key", 42, time.Minute)
	c.Set("map-key", map[string]int{"a": 1}, time.Minute)

	v1, ok1 := c.Get("int-key")
	v2, ok2 := c.Get("map-key")

	if !ok1 || v1.(int) != 42 {
		t.Errorf("int値: ok=%v, val=%v", ok1, v1)
	}
	if !ok2 {
		t.Error("map値が取得できません")
	}
	_ = v2
}

// ─── Delete ───────────────────────────────────────────────────────────────────

func TestCache_Delete_RemovesKey(t *testing.T) {
	c := &Cache{}
	c.Set("del-key", "val", time.Minute)
	c.Delete("del-key")

	_, ok := c.Get("del-key")
	if ok {
		t.Error("Deleteしたキーはもう取得できないべきです")
	}
}

func TestCache_Delete_NonexistentKey_NoError(t *testing.T) {
	c := &Cache{}
	// パニックしないことを確認
	c.Delete("ghost-key")
}

// ─── Flush ────────────────────────────────────────────────────────────────────

func TestCache_Flush_ClearsAll(t *testing.T) {
	c := &Cache{}
	for i := 0; i < 5; i++ {
		c.Set(string(rune('a'+i)), "v", time.Minute)
	}
	c.Flush()

	stats := c.Stats()
	if stats.Items != 0 {
		t.Errorf("Flush後のItems: got %d, want 0", stats.Items)
	}
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func TestCache_Stats_InitialState(t *testing.T) {
	c := &Cache{}
	s := c.Stats()
	if s.Items != 0 || s.Hits != 0 || s.Misses != 0 {
		t.Errorf("初期状態: Items=%d Hits=%d Misses=%d (全て0のはず)", s.Items, s.Hits, s.Misses)
	}
}

func TestCache_Stats_HitCount(t *testing.T) {
	c := &Cache{}
	c.Set("k", "v", time.Minute)
	c.Get("k") // hit
	c.Get("k") // hit
	c.Get("x") // miss

	s := c.Stats()
	if s.Hits != 2 {
		t.Errorf("Hits: got %d, want 2", s.Hits)
	}
	if s.Misses != 1 {
		t.Errorf("Misses: got %d, want 1", s.Misses)
	}
}

func TestCache_Stats_HitRate(t *testing.T) {
	c := &Cache{}
	c.Set("k", "v", time.Minute)
	c.Get("k") // hit
	c.Get("x") // miss

	s := c.Stats()
	if s.HitRate != 50.0 {
		t.Errorf("HitRate: got %.1f, want 50.0", s.HitRate)
	}
}

func TestCache_Stats_HitRate_ZeroWhenNoRequests(t *testing.T) {
	c := &Cache{}
	s := c.Stats()
	if s.HitRate != 0 {
		t.Errorf("リクエストなしのHitRate: got %.1f, want 0", s.HitRate)
	}
}

func TestCache_Stats_ItemCount(t *testing.T) {
	c := &Cache{}
	c.Set("a", 1, time.Minute)
	c.Set("b", 2, time.Minute)
	c.Set("c", 3, -time.Second) // 期限切れ（Statsでは含まれる可能性あり）

	s := c.Stats()
	// 有効なキー2つ以上が存在すること（期限切れエントリーはevict前は残る場合あり）
	if s.Items < 2 {
		t.Errorf("Items: got %d, want >= 2", s.Items)
	}
}

// ─── evictExpired ─────────────────────────────────────────────────────────────

func TestCache_EvictExpired_RemovesExpiredEntries(t *testing.T) {
	c := &Cache{}
	c.Set("stale", "v", -time.Second)
	c.Set("fresh", "v", time.Minute)

	c.evictExpired()

	_, staleOK := c.Get("stale")
	_, freshOK := c.Get("fresh")

	if staleOK {
		t.Error("evictExpired後、期限切れエントリーは取得できないべきです")
	}
	if !freshOK {
		t.Error("evictExpired後、有効なエントリーは取得できるべきです")
	}
}

package threatintel

import (
	"context"
	"testing"
)

// ─── NewFeedManager ───────────────────────────────────────────────────────────

func TestNewFeedManager_NotNil(t *testing.T) {
	m := NewFeedManager(nil)
	if m == nil {
		t.Fatal("NewFeedManager は nil を返すべきではありません")
	}
}

func TestNewFeedManager_FeedsMapInitialized(t *testing.T) {
	m := NewFeedManager(nil)
	if m.feeds == nil {
		t.Error("feeds マップが初期化されていません")
	}
}

// ─── AddFeed ──────────────────────────────────────────────────────────────────

func TestAddFeed_NilFeed_ReturnsError(t *testing.T) {
	m := NewFeedManager(nil)
	if err := m.AddFeed(nil); err == nil {
		t.Error("nil フィードはエラーを返すべきです")
	}
}

func TestAddFeed_ValidFeed_NoError(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "Test Feed", Type: "JSON", URL: "https://example.com/feed"}
	if err := m.AddFeed(feed); err != nil {
		t.Fatalf("AddFeed: 予期しないエラー: %v", err)
	}
}

func TestAddFeed_AutoGeneratesID(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{Name: "No ID Feed", URL: "https://example.com/feed"}
	_ = m.AddFeed(feed)
	if feed.ID == "" {
		t.Error("AddFeed: 空 ID は自動生成されるべきです")
	}
}

func TestAddFeed_DefaultFetchInterval(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{Name: "Feed", URL: "https://example.com"}
	_ = m.AddFeed(feed)
	if feed.FetchIntervalMin != 60 {
		t.Errorf("AddFeed: デフォルト FetchIntervalMin got %d, want 60", feed.FetchIntervalMin)
	}
}

func TestAddFeed_PreservesExplicitInterval(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "Feed", FetchIntervalMin: 120}
	_ = m.AddFeed(feed)
	if feed.FetchIntervalMin != 120 {
		t.Errorf("AddFeed: FetchIntervalMin got %d, want 120", feed.FetchIntervalMin)
	}
}

// ─── GetAllFeeds / GetFeed ────────────────────────────────────────────────────

func TestGetAllFeeds_Empty(t *testing.T) {
	m := NewFeedManager(nil)
	feeds := m.GetAllFeeds()
	if len(feeds) != 0 {
		t.Errorf("GetAllFeeds (空): got %d, want 0", len(feeds))
	}
}

func TestGetAllFeeds_AfterAdd(t *testing.T) {
	m := NewFeedManager(nil)
	_ = m.AddFeed(&Feed{ID: "a", Name: "A"})
	_ = m.AddFeed(&Feed{ID: "b", Name: "B"})
	if len(m.GetAllFeeds()) != 2 {
		t.Errorf("GetAllFeeds: got %d, want 2", len(m.GetAllFeeds()))
	}
}

func TestGetFeed_Found(t *testing.T) {
	m := NewFeedManager(nil)
	_ = m.AddFeed(&Feed{ID: "f1", Name: "Feed1"})
	feed, ok := m.GetFeed("f1")
	if !ok {
		t.Fatal("GetFeed: 追加したフィードが見つかりません")
	}
	if feed.Name != "Feed1" {
		t.Errorf("GetFeed: Name got %q, want Feed1", feed.Name)
	}
}

func TestGetFeed_NotFound(t *testing.T) {
	m := NewFeedManager(nil)
	_, ok := m.GetFeed("nonexistent")
	if ok {
		t.Error("GetFeed (存在しない): false を返すべきです")
	}
}

// ─── storeBuiltinIOC / Lookup* ────────────────────────────────────────────────

func TestStoreBuiltinIOC_LookupIP_ReturnsIOC(t *testing.T) {
	m := NewFeedManager(nil)
	ioc := &IOC{ID: "1", Type: "ip", Value: "1.2.3.4", Source: "builtin"}
	m.storeBuiltinIOC(ioc)
	got := m.LookupIP("1.2.3.4")
	if got == nil {
		t.Fatal("LookupIP: 格納した IOC が見つかりません")
	}
	if got.Value != "1.2.3.4" {
		t.Errorf("LookupIP: Value got %q, want 1.2.3.4", got.Value)
	}
}

func TestLookupIP_NotFound_ReturnsNil(t *testing.T) {
	m := NewFeedManager(nil)
	if m.LookupIP("9.9.9.9") != nil {
		t.Error("LookupIP: 存在しない IP は nil を返すべきです")
	}
}

func TestStoreBuiltinIOC_LookupDomain(t *testing.T) {
	m := NewFeedManager(nil)
	ioc := &IOC{ID: "2", Type: "domain", Value: "evil.example.com", Source: "builtin"}
	m.storeBuiltinIOC(ioc)
	got := m.LookupDomain("evil.example.com")
	if got == nil {
		t.Fatal("LookupDomain: 格納した IOC が見つかりません")
	}
}

func TestLookupDomain_NotFound_ReturnsNil(t *testing.T) {
	m := NewFeedManager(nil)
	if m.LookupDomain("safe.example.com") != nil {
		t.Error("LookupDomain: 存在しないドメインは nil を返すべきです")
	}
}

func TestStoreBuiltinIOC_LookupHash(t *testing.T) {
	m := NewFeedManager(nil)
	hash := "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	ioc := &IOC{ID: "3", Type: "hash", Value: hash, Source: "builtin"}
	m.storeBuiltinIOC(ioc)
	got := m.LookupHash(hash)
	if got == nil {
		t.Fatal("LookupHash: 格納した IOC が見つかりません")
	}
}

func TestStoreBuiltinIOC_LookupURL(t *testing.T) {
	m := NewFeedManager(nil)
	ioc := &IOC{ID: "4", Type: "url", Value: "http://evil.example.com/payload", Source: "builtin"}
	m.storeBuiltinIOC(ioc)
	got := m.LookupURL("http://evil.example.com/payload")
	if got == nil {
		t.Fatal("LookupURL: 格納した IOC が見つかりません")
	}
}

// ─── GetStats ─────────────────────────────────────────────────────────────────

func TestGetStats_EmptyManager(t *testing.T) {
	m := NewFeedManager(nil)
	stats := m.GetStats()
	if stats.TotalIOCs != 0 {
		t.Errorf("空 Manager: TotalIOCs got %d, want 0", stats.TotalIOCs)
	}
}

func TestGetStats_AfterStoreBuiltinIOC(t *testing.T) {
	m := NewFeedManager(nil)
	m.storeBuiltinIOC(&IOC{ID: "1", Type: "ip", Value: "1.2.3.4", Source: "builtin"})
	m.storeBuiltinIOC(&IOC{ID: "2", Type: "domain", Value: "evil.com", Source: "builtin"})
	stats := m.GetStats()
	if stats.TotalIOCs != 2 {
		t.Errorf("GetStats: TotalIOCs got %d, want 2", stats.TotalIOCs)
	}
}

func TestGetStats_IOCsByTypeGrouped(t *testing.T) {
	m := NewFeedManager(nil)
	m.storeBuiltinIOC(&IOC{ID: "1", Type: "ip", Value: "1.1.1.1"})
	m.storeBuiltinIOC(&IOC{ID: "2", Type: "ip", Value: "2.2.2.2"})
	m.storeBuiltinIOC(&IOC{ID: "3", Type: "domain", Value: "evil.com"})
	stats := m.GetStats()
	if stats.IOCsByType["ip"] != 2 {
		t.Errorf("IOCsByType[ip]: got %d, want 2", stats.IOCsByType["ip"])
	}
	if stats.IOCsByType["domain"] != 1 {
		t.Errorf("IOCsByType[domain]: got %d, want 1", stats.IOCsByType["domain"])
	}
}

// ─── LoadBuiltinIOCs ─────────────────────────────────────────────────────────

func TestLoadBuiltinIOCs_LoadsKnownC2IP(t *testing.T) {
	m := NewFeedManager(nil)
	LoadBuiltinIOCs(m)
	// 192.0.2.10 は builtins.go に定義された既知 C2 IP
	ioc := m.LookupIP("192.0.2.10")
	if ioc == nil {
		t.Fatal("LoadBuiltinIOCs: 既知 C2 IP 192.0.2.10 が見つかりません")
	}
	if ioc.Source != "builtin" {
		t.Errorf("Source: got %q, want builtin", ioc.Source)
	}
}

func TestLoadBuiltinIOCs_LoadsKnownDomain(t *testing.T) {
	m := NewFeedManager(nil)
	LoadBuiltinIOCs(m)
	ioc := m.LookupDomain("malware-c2.example")
	if ioc == nil {
		t.Fatal("LoadBuiltinIOCs: malware-c2.example が見つかりません")
	}
}

func TestLoadBuiltinIOCs_TotalCountPositive(t *testing.T) {
	m := NewFeedManager(nil)
	LoadBuiltinIOCs(m)
	stats := m.GetStats()
	if stats.TotalIOCs <= 0 {
		t.Errorf("LoadBuiltinIOCs: TotalIOCs got %d, want > 0", stats.TotalIOCs)
	}
}

// ─── FetchFeed (エラーケース) ─────────────────────────────────────────────────

func TestFetchFeed_UnknownFeedID_ReturnsError(t *testing.T) {
	m := NewFeedManager(nil)
	_, err := m.FetchFeed(context.Background(), "nonexistent-feed-id")
	if err == nil {
		t.Error("存在しないフィード ID は エラーを返すべきです")
	}
}

// ─── parseAndStoreIOCs ────────────────────────────────────────────────────────

func TestParseAndStoreIOCs_ValidJSONArray(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "TestFeed"}
	body := []byte(`[{"type":"ip","value":"10.0.0.1","confidence":80,"severity":7}]`)
	count, err := m.parseAndStoreIOCs(context.Background(), body, feed)
	if err != nil {
		t.Fatalf("parseAndStoreIOCs: 予期しないエラー: %v", err)
	}
	if count != 1 {
		t.Errorf("parseAndStoreIOCs: count got %d, want 1", count)
	}
	if m.LookupIP("10.0.0.1") == nil {
		t.Error("parseAndStoreIOCs: 格納した IOC が見つかりません")
	}
}

func TestParseAndStoreIOCs_WrappedFormat(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "TestFeed"}
	body := []byte(`{"iocs":[{"type":"domain","value":"evil.test"}]}`)
	count, err := m.parseAndStoreIOCs(context.Background(), body, feed)
	if err != nil {
		t.Fatalf("parseAndStoreIOCs wrapped: 予期しないエラー: %v", err)
	}
	if count != 1 {
		t.Errorf("parseAndStoreIOCs wrapped: count got %d, want 1", count)
	}
}

func TestParseAndStoreIOCs_InvalidJSON_ReturnsError(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "TestFeed"}
	_, err := m.parseAndStoreIOCs(context.Background(), []byte("not-json"), feed)
	if err == nil {
		t.Error("不正 JSON はエラーを返すべきです")
	}
}

func TestParseAndStoreIOCs_SkipsEntryWithoutTypeOrValue(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "TestFeed"}
	body := []byte(`[{"type":"ip"},{"value":"2.2.2.2"},{"type":"ip","value":"3.3.3.3"}]`)
	count, _ := m.parseAndStoreIOCs(context.Background(), body, feed)
	if count != 1 {
		t.Errorf("type/value 欠損はスキップ: count got %d, want 1", count)
	}
}

func TestParseAndStoreIOCs_DefaultConfidenceAndSeverity(t *testing.T) {
	m := NewFeedManager(nil)
	feed := &Feed{ID: "f1", Name: "TestFeed"}
	body := []byte(`[{"type":"ip","value":"5.5.5.5"}]`)
	_, _ = m.parseAndStoreIOCs(context.Background(), body, feed)
	ioc := m.LookupIP("5.5.5.5")
	if ioc == nil {
		t.Fatal("IOC が格納されていません")
	}
	if ioc.Confidence != 50 {
		t.Errorf("デフォルト Confidence: got %d, want 50", ioc.Confidence)
	}
	if ioc.Severity != 5 {
		t.Errorf("デフォルト Severity: got %d, want 5", ioc.Severity)
	}
}

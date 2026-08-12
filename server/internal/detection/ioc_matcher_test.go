package detection

import (
	"context"
	"testing"
	"time"
)

// ─── Mock Loader ──────────────────────────────────────────────────────────────

type mockLoader struct {
	records []IOCRecord
	err     error
	calls   int
}

func (l *mockLoader) ListActiveIOCs(_ context.Context) ([]IOCRecord, error) {
	l.calls++
	return l.records, l.err
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func newMatcherWithRecords(records []IOCRecord) *IOCMatcher {
	loader := &mockLoader{records: records}
	m := NewIOCMatcher(loader)
	m.refresh(context.Background())
	return m
}

// ─── Cache tests ──────────────────────────────────────────────────────────────

func TestIOCMatcher_CacheSize_Empty(t *testing.T) {
	m := newMatcherWithRecords(nil)
	if m.CacheSize() != 0 {
		t.Fatalf("空のキャッシュサイズは 0 であるべきです")
	}
}

func TestIOCMatcher_CacheSize_AfterLoad(t *testing.T) {
	records := []IOCRecord{
		{ID: "1", Type: "ip", Value: "1.2.3.4"},
		{ID: "2", Type: "ip", Value: "5.6.7.8"},
		{ID: "3", Type: "domain", Value: "evil.com"},
	}
	m := newMatcherWithRecords(records)
	if got := m.CacheSize(); got != 3 {
		t.Fatalf("CacheSize = %d, want 3", got)
	}
}

func TestIOCMatcher_LoadedAt_SetAfterRefresh(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{{ID: "1", Type: "ip", Value: "1.2.3.4"}})
	before := time.Now()
	if m.LoadedAt().Before(before.Add(-time.Second)) || m.LoadedAt().IsZero() {
		t.Fatal("LoadedAt がリフレッシュ後に更新されていません")
	}
}

func TestIOCMatcher_RefreshNow_ReloadsCache(t *testing.T) {
	loader := &mockLoader{records: []IOCRecord{
		{ID: "1", Type: "ip", Value: "1.1.1.1"},
	}}
	m := NewIOCMatcher(loader)
	m.refresh(context.Background())
	if m.CacheSize() != 1 {
		t.Fatal("最初のリフレッシュ後のキャッシュサイズが誤っています")
	}

	// Add more records and refresh
	loader.records = append(loader.records, IOCRecord{ID: "2", Type: "ip", Value: "2.2.2.2"})
	m.RefreshNow(context.Background())

	if m.CacheSize() != 2 {
		t.Fatalf("RefreshNow後のキャッシュサイズ = %d, want 2", m.CacheSize())
	}
}

// ─── IP matching tests ────────────────────────────────────────────────────────

func TestIOCMatcher_CheckEvent_IPHit(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "ip", Value: "10.0.0.1", Description: "C2 server", Severity: 9},
	})

	hits := m.CheckEvent(map[string]interface{}{
		"dstIp": "10.0.0.1",
	})

	if len(hits) != 1 {
		t.Fatalf("IPヒット数 = %d, want 1", len(hits))
	}
	if hits[0].IOC.Severity != 9 {
		t.Fatalf("Severity = %d, want 9", hits[0].IOC.Severity)
	}
	if hits[0].MatchedOn != "dstIp" {
		t.Fatalf("MatchedOn = %q, want dstIp", hits[0].MatchedOn)
	}
}

func TestIOCMatcher_CheckEvent_IPCaseInsensitive(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "ip", Value: "10.0.0.1"},
	})
	// IPv4 is case-insensitive (lower stored)
	hits := m.CheckEvent(map[string]interface{}{"dstIp": "10.0.0.1"})
	if len(hits) != 1 {
		t.Fatalf("IPマッチが失敗しました")
	}
}

func TestIOCMatcher_CheckEvent_IPMiss(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "ip", Value: "10.0.0.1"},
	})
	hits := m.CheckEvent(map[string]interface{}{"dstIp": "192.168.1.1"})
	if len(hits) != 0 {
		t.Fatalf("IPミスマッチがヒットとして扱われました")
	}
}

func TestIOCMatcher_CheckEvent_SrcIPField(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "ip", Value: "10.0.0.2"},
	})
	hits := m.CheckEvent(map[string]interface{}{"src_ip": "10.0.0.2"})
	if len(hits) != 1 {
		t.Fatalf("src_ip フィールドのマッチに失敗しました")
	}
}

// ─── Domain matching tests ────────────────────────────────────────────────────

func TestIOCMatcher_CheckEvent_DomainExactMatch(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "domain", Value: "malware.example.com"},
	})
	hits := m.CheckEvent(map[string]interface{}{"query": "malware.example.com"})
	if len(hits) != 1 {
		t.Fatalf("ドメイン完全一致が失敗しました")
	}
}

func TestIOCMatcher_CheckEvent_DomainSuffixMatch(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "domain", Value: "evil.com"},
	})
	// Subdomain should match
	hits := m.CheckEvent(map[string]interface{}{"query": "sub.evil.com"})
	if len(hits) != 1 {
		t.Fatalf("ドメインサフィックスマッチが失敗しました: sub.evil.com should match evil.com")
	}
}

func TestIOCMatcher_CheckEvent_DomainNoMatch(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "domain", Value: "evil.com"},
	})
	// notevil.com should NOT match evil.com
	hits := m.CheckEvent(map[string]interface{}{"query": "notevil.com"})
	if len(hits) != 0 {
		t.Fatalf("notevil.com は evil.com にマッチするべきではありません")
	}
}

func TestIOCMatcher_CheckEvent_DomainTrailingDot(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "domain", Value: "evil.com"},
	})
	// DNS often returns trailing dot
	hits := m.CheckEvent(map[string]interface{}{"query": "evil.com."})
	if len(hits) != 1 {
		t.Fatalf("末尾ドットのドメインマッチが失敗しました")
	}
}

// ─── Hash matching tests ──────────────────────────────────────────────────────

func TestIOCMatcher_CheckEvent_HashHit(t *testing.T) {
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "hash", Value: hash},
	})
	hits := m.CheckEvent(map[string]interface{}{"sha256": hash})
	if len(hits) != 1 {
		t.Fatalf("ハッシュマッチが失敗しました")
	}
}

func TestIOCMatcher_CheckEvent_HashCaseInsensitive(t *testing.T) {
	hash := "AABBCC112233"
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "hash", Value: "aabbcc112233"},
	})
	hits := m.CheckEvent(map[string]interface{}{"sha256": hash})
	if len(hits) != 1 {
		t.Fatalf("ハッシュは大文字小文字を区別しないべきです")
	}
}

// ─── URL matching tests ───────────────────────────────────────────────────────

func TestIOCMatcher_CheckEvent_URLContainsMatch(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "url", Value: "malware.example.com/payload"},
	})
	hits := m.CheckEvent(map[string]interface{}{
		"url": "http://malware.example.com/payload/stage2.exe",
	})
	if len(hits) != 1 {
		t.Fatalf("URL部分マッチが失敗しました")
	}
}

// ─── Multi-match tests ────────────────────────────────────────────────────────

func TestIOCMatcher_CheckEvent_MultipleHits(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "ip", Value: "10.0.0.1"},
		{ID: "2", Type: "domain", Value: "evil.com"},
	})
	hits := m.CheckEvent(map[string]interface{}{
		"dstIp": "10.0.0.1",
		"query": "evil.com",
	})
	if len(hits) != 2 {
		t.Fatalf("複数ヒット数 = %d, want 2", len(hits))
	}
}

func TestIOCMatcher_CheckEvent_EmptyEvent(t *testing.T) {
	m := newMatcherWithRecords([]IOCRecord{
		{ID: "1", Type: "ip", Value: "10.0.0.1"},
	})
	hits := m.CheckEvent(map[string]interface{}{})
	if len(hits) != 0 {
		t.Fatalf("空のイベントでヒットが発生するべきではありません")
	}
}

func TestIOCMatcher_CheckEvent_EmptyCache(t *testing.T) {
	m := newMatcherWithRecords(nil)
	hits := m.CheckEvent(map[string]interface{}{"dstIp": "1.2.3.4"})
	if hits != nil {
		t.Fatalf("空のキャッシュでは nil を返すべきです")
	}
}

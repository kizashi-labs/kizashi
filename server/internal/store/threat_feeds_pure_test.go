package store

import (
	"strings"
	"testing"
	"time"
)

// ─── ThreatFeed 構造体フィールドテスト ────────────────────────────────────────

// TestThreatFeed_DefaultIsActiveIsFalse は ThreatFeed のゼロ値で IsActive が false であることを確認する
func TestThreatFeed_DefaultIsActiveIsFalse(t *testing.T) {
	var f ThreatFeed
	if f.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
}

// TestThreatFeed_DefaultLastSyncAtIsNil は ThreatFeed のゼロ値で LastSyncAt が nil であることを確認する
func TestThreatFeed_DefaultLastSyncAtIsNil(t *testing.T) {
	var f ThreatFeed
	if f.LastSyncAt != nil {
		t.Errorf("LastSyncAt のデフォルトは nil であるべき: got %v", f.LastSyncAt)
	}
}

// TestThreatFeed_LastSyncAtCanBeSet は LastSyncAt に time.Time ポインタを設定できることを確認する
func TestThreatFeed_LastSyncAtCanBeSet(t *testing.T) {
	now := time.Now()
	f := ThreatFeed{LastSyncAt: &now}
	if f.LastSyncAt == nil {
		t.Fatal("LastSyncAt に値を設定後は nil でないべき")
	}
	if !f.LastSyncAt.Equal(now) {
		t.Errorf("LastSyncAt = %v, want %v", f.LastSyncAt, now)
	}
}

// TestThreatFeed_DefaultHeadersIsNil は ThreatFeed のゼロ値で Headers が nil であることを確認する
func TestThreatFeed_DefaultHeadersIsNil(t *testing.T) {
	var f ThreatFeed
	if f.Headers != nil {
		t.Errorf("Headers のデフォルトは nil であるべき: got %v", f.Headers)
	}
}

// TestThreatFeed_HeadersCanBeSet は Headers に文字列マップを設定できることを確認する
func TestThreatFeed_HeadersCanBeSet(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer token123",
		"X-API-Key":     "secret-key",
	}
	f := ThreatFeed{Headers: headers}
	if len(f.Headers) != 2 {
		t.Errorf("Headers の長さ = %d, want 2", len(f.Headers))
	}
	if f.Headers["Authorization"] != "Bearer token123" {
		t.Errorf("Authorization ヘッダー = %q, want 'Bearer token123'", f.Headers["Authorization"])
	}
}

// ─── フィードタイプ検証テスト ─────────────────────────────────────────────────

// isValidFeedType は既知のフィードタイプかどうかを検証する純粋関数
func isValidFeedType(feedType string) bool {
	switch feedType {
	case "txt", "csv", "misp", "otx":
		return true
	}
	return false
}

// TestIsValidFeedType_KnownTypesAreValid は既知のフィードタイプが有効であることを確認する
func TestIsValidFeedType_KnownTypesAreValid(t *testing.T) {
	validTypes := []string{"txt", "csv", "misp", "otx"}
	for _, ft := range validTypes {
		if !isValidFeedType(ft) {
			t.Errorf("フィードタイプ %q は有効であるべき", ft)
		}
	}
}

// TestIsValidFeedType_UnknownTypesAreInvalid は不明なフィードタイプが無効であることを確認する
func TestIsValidFeedType_UnknownTypesAreInvalid(t *testing.T) {
	invalidTypes := []string{"json", "xml", "yaml", "", "TXT", "CSV"}
	for _, ft := range invalidTypes {
		if isValidFeedType(ft) {
			t.Errorf("フィードタイプ %q は無効であるべき", ft)
		}
	}
}

// TestIsValidFeedType_CaseSensitive はフィードタイプ判定が大文字小文字を区別することを確認する
func TestIsValidFeedType_CaseSensitive(t *testing.T) {
	if isValidFeedType("TXT") {
		t.Error("フィードタイプ判定は大文字小文字を区別するべき ('TXT' は無効)")
	}
	if isValidFeedType("Misp") {
		t.Error("フィードタイプ判定は大文字小文字を区別するべき ('Misp' は無効)")
	}
}

// ─── IOC タイプ検証テスト ──────────────────────────────────────────────────────

// isValidIOCType は既知の IOC タイプかどうかを検証する純粋関数
func isValidIOCType(iocType string) bool {
	switch iocType {
	case "ip", "domain", "hash", "url":
		return true
	}
	return false
}

// TestIsValidIOCType_KnownTypesAreValid は既知の IOC タイプが有効であることを確認する
func TestIsValidIOCType_KnownTypesAreValid(t *testing.T) {
	validTypes := []string{"ip", "domain", "hash", "url"}
	for _, it := range validTypes {
		if !isValidIOCType(it) {
			t.Errorf("IOC タイプ %q は有効であるべき", it)
		}
	}
}

// TestIsValidIOCType_UnknownTypesAreInvalid は不明な IOC タイプが無効であることを確認する
func TestIsValidIOCType_UnknownTypesAreInvalid(t *testing.T) {
	invalidTypes := []string{"email", "file", "certificate", "", "IP", "Domain"}
	for _, it := range invalidTypes {
		if isValidIOCType(it) {
			t.Errorf("IOC タイプ %q は無効であるべき", it)
		}
	}
}

// ─── ソースフォーマット検証テスト ─────────────────────────────────────────────

// isValidSourceFormat は既知のソースフォーマットかどうかを検証する純粋関数
func isValidSourceFormat(format string) bool {
	// 空文字列は「フォーマット未指定」として有効
	if format == "" {
		return true
	}
	switch format {
	case "otx_reputation", "urlhaus_csv", "malwarebazaar_csv", "feodo_csv", "misp_json":
		return true
	}
	return false
}

// TestIsValidSourceFormat_EmptyFormatIsValid は空のソースフォーマットが有効（省略可）であることを確認する
func TestIsValidSourceFormat_EmptyFormatIsValid(t *testing.T) {
	if !isValidSourceFormat("") {
		t.Error("空のソースフォーマットは有効（省略可）であるべき")
	}
}

// TestIsValidSourceFormat_KnownFormatsAreValid は既知のソースフォーマットが有効であることを確認する
func TestIsValidSourceFormat_KnownFormatsAreValid(t *testing.T) {
	validFormats := []string{
		"otx_reputation",
		"urlhaus_csv",
		"malwarebazaar_csv",
		"feodo_csv",
		"misp_json",
	}
	for _, sf := range validFormats {
		if !isValidSourceFormat(sf) {
			t.Errorf("ソースフォーマット %q は有効であるべき", sf)
		}
	}
}

// TestIsValidSourceFormat_UnknownFormatsAreInvalid は不明なソースフォーマットが無効であることを確認する
func TestIsValidSourceFormat_UnknownFormatsAreInvalid(t *testing.T) {
	invalidFormats := []string{"custom_format", "json_v2", "stix2", "taxii"}
	for _, sf := range invalidFormats {
		if isValidSourceFormat(sf) {
			t.Errorf("ソースフォーマット %q は無効であるべき", sf)
		}
	}
}

// ─── headersJSON 純粋関数テスト ───────────────────────────────────────────────

// TestHeadersJSON_EmptyMapReturnsEmptyJSONString は空マップが "{}" を返すことを確認する
func TestHeadersJSON_EmptyMapReturnsEmptyJSONString(t *testing.T) {
	result := headersJSON(map[string]string{})
	str, ok := result.(string)
	if !ok {
		t.Fatalf("headersJSON(空マップ) は string を返すべき: got %T", result)
	}
	if str != "{}" {
		t.Errorf("headersJSON(空マップ) = %q, want \"{}\"", str)
	}
}

// TestHeadersJSON_NilMapReturnsEmptyJSONString は nil マップが "{}" を返すことを確認する
func TestHeadersJSON_NilMapReturnsEmptyJSONString(t *testing.T) {
	result := headersJSON(nil)
	str, ok := result.(string)
	if !ok {
		t.Fatalf("headersJSON(nil) は string を返すべき: got %T", result)
	}
	if str != "{}" {
		t.Errorf("headersJSON(nil) = %q, want \"{}\"", str)
	}
}

// TestHeadersJSON_NonEmptyMapReturnsMap は非空マップがそのマップ自身を返すことを確認する
func TestHeadersJSON_NonEmptyMapReturnsMap(t *testing.T) {
	headers := map[string]string{"X-API-Key": "key123"}
	result := headersJSON(headers)
	m, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("headersJSON(非空マップ) は map[string]string を返すべき: got %T", result)
	}
	if m["X-API-Key"] != "key123" {
		t.Errorf("map[\"X-API-Key\"] = %q, want \"key123\"", m["X-API-Key"])
	}
}

// ─── URL 形式検証テスト ───────────────────────────────────────────────────────

// threatFeedURLIsValid は ThreatFeed URL の基本的な形式を検証する純粋関数
// http:// または https:// で始まるかどうかを確認する
func threatFeedURLIsValid(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// TestThreatFeedURLIsValid_HTTPSUrlsAreValid は HTTPS URL が有効であることを確認する
func TestThreatFeedURLIsValid_HTTPSUrlsAreValid(t *testing.T) {
	validURLs := []string{
		"https://example.com/feed.txt",
		"https://feeds.alienvault.com/api/v1/pulses",
		"https://urlhaus.abuse.ch/downloads/csv/",
	}
	for _, u := range validURLs {
		if !threatFeedURLIsValid(u) {
			t.Errorf("URL %q は有効であるべき", u)
		}
	}
}

// TestThreatFeedURLIsValid_HTTPUrlsAreValid は HTTP URL が有効であることを確認する
func TestThreatFeedURLIsValid_HTTPUrlsAreValid(t *testing.T) {
	if !threatFeedURLIsValid("http://example.com/feed.csv") {
		t.Error("HTTP URL は有効であるべき")
	}
}

// TestThreatFeedURLIsValid_InvalidURLsAreRejected は無効な URL が拒否されることを確認する
func TestThreatFeedURLIsValid_InvalidURLsAreRejected(t *testing.T) {
	invalidURLs := []string{
		"ftp://example.com/feed.txt",
		"example.com/feed",
		"",
		"not-a-url",
		"//relative-url.com",
	}
	for _, u := range invalidURLs {
		if threatFeedURLIsValid(u) {
			t.Errorf("URL %q は無効として拒否されるべき", u)
		}
	}
}

// TestThreatFeed_SyncIntervalHoursIsNonNegative は SyncIntervalHours がゼロ以上であることを確認する
func TestThreatFeed_SyncIntervalHoursIsNonNegative(t *testing.T) {
	// syncIntervalHours の有効範囲: 0以上（0は「手動のみ」を意味する場合が多い）
	f := ThreatFeed{SyncIntervalHours: 0}
	if f.SyncIntervalHours < 0 {
		t.Error("SyncIntervalHours は 0 以上であるべき")
	}

	f2 := ThreatFeed{SyncIntervalHours: 24}
	if f2.SyncIntervalHours != 24 {
		t.Errorf("SyncIntervalHours = %d, want 24", f2.SyncIntervalHours)
	}
}

// TestThreatFeed_AllFieldsCanBeSet は全フィールドを設定できることを確認する
func TestThreatFeed_AllFieldsCanBeSet(t *testing.T) {
	now := time.Now()
	f := ThreatFeed{
		ID:                "feed-001",
		Name:              "OTX Reputation Feed",
		URL:               "https://otx.alienvault.com/api/v1/indicators",
		FeedType:          "otx",
		IOCType:           "ip",
		SourceFormat:      "otx_reputation",
		APIKey:            "secret-api-key",
		Description:       "AlienVault OTX IP reputation feed",
		IsActive:          true,
		LastSyncAt:        &now,
		LastCount:         15000,
		SyncIntervalHours: 6,
		Headers:           map[string]string{"X-OTX-API-KEY": "key123"},
	}
	if f.ID != "feed-001" {
		t.Errorf("ID = %q, want 'feed-001'", f.ID)
	}
	if f.FeedType != "otx" {
		t.Errorf("FeedType = %q, want 'otx'", f.FeedType)
	}
	if f.IOCType != "ip" {
		t.Errorf("IOCType = %q, want 'ip'", f.IOCType)
	}
	if !f.IsActive {
		t.Error("IsActive は true であるべき")
	}
	if f.LastCount != 15000 {
		t.Errorf("LastCount = %d, want 15000", f.LastCount)
	}
}

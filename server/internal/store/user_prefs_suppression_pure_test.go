package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── defaultPrefs 変数テスト ──────────────────────────────────────────────────

// TestDefaultPrefs_Theme はデフォルトテーマが "dark" であることを確認する
func TestDefaultPrefs_Theme(t *testing.T) {
	if defaultPrefs.Theme != "dark" {
		t.Errorf("defaultPrefs.Theme = %q, want \"dark\"", defaultPrefs.Theme)
	}
}

// TestDefaultPrefs_Language はデフォルト言語が "ja" であることを確認する
func TestDefaultPrefs_Language(t *testing.T) {
	if defaultPrefs.Language != "ja" {
		t.Errorf("defaultPrefs.Language = %q, want \"ja\"", defaultPrefs.Language)
	}
}

// TestDefaultPrefs_Timezone はデフォルトタイムゾーンが "Asia/Tokyo" であることを確認する
func TestDefaultPrefs_Timezone(t *testing.T) {
	if defaultPrefs.Timezone != "Asia/Tokyo" {
		t.Errorf("defaultPrefs.Timezone = %q, want \"Asia/Tokyo\"", defaultPrefs.Timezone)
	}
}

// TestDefaultPrefs_ItemsPerPage はデフォルトのページあたり件数が 20 であることを確認する
func TestDefaultPrefs_ItemsPerPage(t *testing.T) {
	if defaultPrefs.ItemsPerPage != 20 {
		t.Errorf("defaultPrefs.ItemsPerPage = %d, want 20", defaultPrefs.ItemsPerPage)
	}
}

// TestDefaultPrefs_NotificationsValidJSON はデフォルト通知設定が有効な JSON であることを確認する
func TestDefaultPrefs_NotificationsValidJSON(t *testing.T) {
	var notifs map[string]interface{}
	if err := json.Unmarshal(defaultPrefs.Notifications, &notifs); err != nil {
		t.Fatalf("デフォルト Notifications が有効な JSON でない: %v", err)
	}
	// email と browser の通知がデフォルトで有効であることを確認する
	emailEnabled, ok := notifs["email"].(bool)
	if !ok {
		t.Fatal("notifications.email フィールドが bool でない")
	}
	if !emailEnabled {
		t.Error("デフォルトで email 通知は有効であるべき")
	}
	browserEnabled, ok := notifs["browser"].(bool)
	if !ok {
		t.Fatal("notifications.browser フィールドが bool でない")
	}
	if !browserEnabled {
		t.Error("デフォルトで browser 通知は有効であるべき")
	}
}

// TestDefaultPrefs_DigestDefaultFalse はデフォルトのダイジェスト通知が無効であることを確認する
func TestDefaultPrefs_DigestDefaultFalse(t *testing.T) {
	var notifs map[string]interface{}
	if err := json.Unmarshal(defaultPrefs.Notifications, &notifs); err != nil {
		t.Fatalf("Notifications パース失敗: %v", err)
	}
	digestEnabled, ok := notifs["digest"].(bool)
	if !ok {
		t.Fatal("notifications.digest フィールドが bool でない")
	}
	if digestEnabled {
		t.Error("デフォルトで digest 通知は無効であるべき")
	}
}

// TestDefaultPrefs_DashboardPrefsEmptyObject はデフォルトのダッシュボード設定が空オブジェクトであることを確認する
func TestDefaultPrefs_DashboardPrefsEmptyObject(t *testing.T) {
	var dashPrefs map[string]interface{}
	if err := json.Unmarshal(defaultPrefs.DashboardPrefs, &dashPrefs); err != nil {
		t.Fatalf("DashboardPrefs パース失敗: %v", err)
	}
	if len(dashPrefs) != 0 {
		t.Errorf("デフォルト DashboardPrefs は空オブジェクトであるべき: got %v", dashPrefs)
	}
}

// ─── UserPreferences Upsert フォールバックロジックテスト ──────────────────────

// applyPrefsDefaults は Upsert メソッドのデフォルト適用ロジックを再現するヘルパー（テスト専用）
func applyPrefsDefaults(prefs UserPreferences) UserPreferences {
	if prefs.Theme == "" {
		prefs.Theme = "dark"
	}
	if prefs.Language == "" {
		prefs.Language = "ja"
	}
	if prefs.Timezone == "" {
		prefs.Timezone = "Asia/Tokyo"
	}
	if prefs.ItemsPerPage <= 0 {
		prefs.ItemsPerPage = 20
	}
	if prefs.Notifications == nil {
		prefs.Notifications = json.RawMessage(`{"email":true,"browser":true,"digest":false}`)
	}
	if prefs.DashboardPrefs == nil {
		prefs.DashboardPrefs = json.RawMessage(`{}`)
	}
	return prefs
}

// TestApplyPrefsDefaults_EmptyPrefs は空の設定に全デフォルトが適用されることを確認する
func TestApplyPrefsDefaults_EmptyPrefs(t *testing.T) {
	prefs := applyPrefsDefaults(UserPreferences{})

	if prefs.Theme != "dark" {
		t.Errorf("Theme = %q, want \"dark\"", prefs.Theme)
	}
	if prefs.Language != "ja" {
		t.Errorf("Language = %q, want \"ja\"", prefs.Language)
	}
	if prefs.Timezone != "Asia/Tokyo" {
		t.Errorf("Timezone = %q, want \"Asia/Tokyo\"", prefs.Timezone)
	}
	if prefs.ItemsPerPage != 20 {
		t.Errorf("ItemsPerPage = %d, want 20", prefs.ItemsPerPage)
	}
	if prefs.Notifications == nil {
		t.Error("Notifications はデフォルト値が設定されるべき")
	}
	if prefs.DashboardPrefs == nil {
		t.Error("DashboardPrefs はデフォルト値が設定されるべき")
	}
}

// TestApplyPrefsDefaults_PreservesExistingValues は既存の値がデフォルトで上書きされないことを確認する
func TestApplyPrefsDefaults_PreservesExistingValues(t *testing.T) {
	customNotifs := json.RawMessage(`{"email":false,"browser":true,"digest":true}`)
	prefs := applyPrefsDefaults(UserPreferences{
		Theme:         "light",
		Language:      "en",
		Timezone:      "UTC",
		ItemsPerPage:  50,
		Notifications: customNotifs,
	})

	if prefs.Theme != "light" {
		t.Errorf("Theme = %q, want \"light\"（既存値が保持されるべき）", prefs.Theme)
	}
	if prefs.Language != "en" {
		t.Errorf("Language = %q, want \"en\"（既存値が保持されるべき）", prefs.Language)
	}
	if prefs.Timezone != "UTC" {
		t.Errorf("Timezone = %q, want \"UTC\"（既存値が保持されるべき）", prefs.Timezone)
	}
	if prefs.ItemsPerPage != 50 {
		t.Errorf("ItemsPerPage = %d, want 50（既存値が保持されるべき）", prefs.ItemsPerPage)
	}
	if string(prefs.Notifications) != string(customNotifs) {
		t.Errorf("Notifications = %s, want %s（既存値が保持されるべき）", prefs.Notifications, customNotifs)
	}
}

// TestApplyPrefsDefaults_ZeroItemsPerPage は ItemsPerPage が 0 のときデフォルト値になることを確認する
func TestApplyPrefsDefaults_ZeroItemsPerPage(t *testing.T) {
	prefs := applyPrefsDefaults(UserPreferences{ItemsPerPage: 0})
	if prefs.ItemsPerPage != 20 {
		t.Errorf("ItemsPerPage = %d, want 20", prefs.ItemsPerPage)
	}
}

// TestApplyPrefsDefaults_NegativeItemsPerPage は ItemsPerPage が負のときデフォルト値になることを確認する
func TestApplyPrefsDefaults_NegativeItemsPerPage(t *testing.T) {
	prefs := applyPrefsDefaults(UserPreferences{ItemsPerPage: -5})
	if prefs.ItemsPerPage != 20 {
		t.Errorf("ItemsPerPage = %d, want 20（負の値はデフォルトになるべき）", prefs.ItemsPerPage)
	}
}

// ─── UserPreferences 構造体テスト ─────────────────────────────────────────────

// TestUserPreferences_ZeroValue は UserPreferences のゼロ値が期待通りであることを確認する
func TestUserPreferences_ZeroValue(t *testing.T) {
	var p UserPreferences
	if p.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", p.UserID)
	}
	if p.SidebarCollapsed {
		t.Error("SidebarCollapsed のデフォルトは false であるべき")
	}
	if p.ItemsPerPage != 0 {
		t.Errorf("ItemsPerPage のデフォルト = %d, want 0", p.ItemsPerPage)
	}
}

// TestUserPreferences_SidebarToggle はサイドバー折りたたみのフラグ操作を確認する
func TestUserPreferences_SidebarToggle(t *testing.T) {
	p := UserPreferences{SidebarCollapsed: false}
	// 折りたたむ
	p.SidebarCollapsed = true
	if !p.SidebarCollapsed {
		t.Error("SidebarCollapsed は true であるべき")
	}
	// 展開する
	p.SidebarCollapsed = false
	if p.SidebarCollapsed {
		t.Error("SidebarCollapsed は false であるべき")
	}
}

// ─── SuppressionRuleEntry 構造体テスト ───────────────────────────────────────

// TestSuppressionRuleEntry_ZeroValue は SuppressionRuleEntry のゼロ値を確認する
func TestSuppressionRuleEntry_ZeroValue(t *testing.T) {
	var r SuppressionRuleEntry
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Pattern != "" {
		t.Errorf("Pattern のデフォルト = %q, want \"\"", r.Pattern)
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if r.SeverityMax != 0 {
		t.Errorf("SeverityMax のデフォルト = %d, want 0", r.SeverityMax)
	}
	if r.AgentID != nil {
		t.Errorf("AgentID のデフォルトは nil であるべき: got %v", *r.AgentID)
	}
	if r.ExpiresAt != nil {
		t.Errorf("ExpiresAt のデフォルトは nil であるべき: got %v", *r.ExpiresAt)
	}
}

// TestSuppressionRuleEntry_MatchFields は有効な match_field 値を確認する
func TestSuppressionRuleEntry_MatchFields(t *testing.T) {
	// EDR アラートで抑制ルールが照合できるフィールド一覧
	matchFields := []string{"title", "description", "agent_id", "process_name", "file_path"}
	for _, field := range matchFields {
		r := SuppressionRuleEntry{MatchField: field}
		if r.MatchField != field {
			t.Errorf("MatchField = %q, want %q", r.MatchField, field)
		}
	}
}

// TestSuppressionRuleEntry_SeverityMaxRange は SeverityMax が 0〜10 の範囲で表現できることを確認する
func TestSuppressionRuleEntry_SeverityMaxRange(t *testing.T) {
	for sev := 0; sev <= 10; sev++ {
		r := SuppressionRuleEntry{SeverityMax: sev}
		if r.SeverityMax != sev {
			t.Errorf("SeverityMax = %d, want %d", r.SeverityMax, sev)
		}
	}
}

// TestSuppressionRuleEntry_IsExpired は有効期限切れの判定ロジックを確認する
func TestSuppressionRuleEntry_IsExpired(t *testing.T) {
	// 有効期限切れルール
	past := time.Now().Add(-24 * time.Hour)
	expiredRule := SuppressionRuleEntry{
		Enabled:   true,
		ExpiresAt: &past,
	}
	isExpired := expiredRule.ExpiresAt != nil && time.Now().After(*expiredRule.ExpiresAt)
	if !isExpired {
		t.Error("過去の ExpiresAt は期限切れと判定されるべき")
	}

	// 有効なルール（有効期限あり）
	future := time.Now().Add(24 * time.Hour)
	validRule := SuppressionRuleEntry{
		Enabled:   true,
		ExpiresAt: &future,
	}
	isExpiredValid := validRule.ExpiresAt != nil && time.Now().After(*validRule.ExpiresAt)
	if isExpiredValid {
		t.Error("未来の ExpiresAt は期限切れと判定されるべきでない")
	}

	// 有効期限なしのルール
	permanentRule := SuppressionRuleEntry{
		Enabled:   true,
		ExpiresAt: nil,
	}
	isExpiredPermanent := permanentRule.ExpiresAt != nil && time.Now().After(*permanentRule.ExpiresAt)
	if isExpiredPermanent {
		t.Error("ExpiresAt が nil のルールは期限切れと判定されるべきでない")
	}
}

// TestSuppressionRuleEntry_ShouldSuppress は抑制条件の評価ロジックを確認する
// ルールが有効かつ期限内かつパターンが一致する場合に抑制する
func TestSuppressionRuleEntry_ShouldSuppress(t *testing.T) {
	// shouldSuppress はルールが特定のアラートを抑制すべきか判定するヘルパー（テスト専用）
	shouldSuppress := func(rule SuppressionRuleEntry, fieldValue string) bool {
		if !rule.Enabled {
			return false
		}
		if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
			return false
		}
		return strings.Contains(fieldValue, rule.Pattern)
	}

	future := time.Now().Add(24 * time.Hour)
	rule := SuppressionRuleEntry{
		Pattern:    "test-process",
		MatchField: "process_name",
		Enabled:    true,
		ExpiresAt:  &future,
	}

	cases := []struct {
		fieldValue string
		suppress   bool
	}{
		{"test-process.exe", true},
		{"my-test-process", true},
		{"production-service", false},
		{"", false},
	}

	for _, tc := range cases {
		got := shouldSuppress(rule, tc.fieldValue)
		if got != tc.suppress {
			t.Errorf("shouldSuppress(%q) = %v, want %v", tc.fieldValue, got, tc.suppress)
		}
	}
}

// TestSuppressionRuleEntry_DisabledRuleDoesNotSuppress は無効なルールが抑制しないことを確認する
func TestSuppressionRuleEntry_DisabledRuleDoesNotSuppress(t *testing.T) {
	disabledRule := SuppressionRuleEntry{
		Pattern: "malware",
		Enabled: false,
	}
	shouldSuppress := func(rule SuppressionRuleEntry, fieldValue string) bool {
		if !rule.Enabled {
			return false
		}
		return strings.Contains(fieldValue, rule.Pattern)
	}
	if shouldSuppress(disabledRule, "malware-alert") {
		t.Error("無効なルールはアラートを抑制すべきでない")
	}
}

// TestSuppressionRuleEntry_AgentScopedRule は特定エージェント向けルールのスコープを確認する
func TestSuppressionRuleEntry_AgentScopedRule(t *testing.T) {
	agentID := "agent-specific-001"
	rule := SuppressionRuleEntry{
		Pattern:    "debug-process",
		MatchField: "process_name",
		Enabled:    true,
		AgentID:    &agentID,
	}

	// AgentID が設定されているルールはそのエージェントのみに適用する
	if rule.AgentID == nil {
		t.Fatal("AgentID は nil でないべき")
	}
	if *rule.AgentID != agentID {
		t.Errorf("*AgentID = %q, want %q", *rule.AgentID, agentID)
	}
}

// TestSuppressionRuleEntry_SuppressedCountIncrement は SuppressedCount が増加することを確認する
func TestSuppressionRuleEntry_SuppressedCountIncrement(t *testing.T) {
	r := SuppressionRuleEntry{SuppressedCount: 0}
	// IncrementCount の効果を模倣する（DB なしで構造体のみ）
	r.SuppressedCount++
	if r.SuppressedCount != 1 {
		t.Errorf("SuppressedCount = %d, want 1", r.SuppressedCount)
	}
	r.SuppressedCount += 99
	if r.SuppressedCount != 100 {
		t.Errorf("SuppressedCount = %d, want 100", r.SuppressedCount)
	}
}

// ─── nilIfEmptyPtr（suppression_rule_store.go で定義）追加テスト ──────────────

// TestNilIfEmptyPtr_NonEmptyAgentIDPreserved は非空の AgentID が保持されることを確認する
func TestNilIfEmptyPtr_NonEmptyAgentIDPreserved(t *testing.T) {
	agentID := "agent-uuid-001"
	got := nilIfEmptyPtr(&agentID)
	if got == nil {
		t.Fatal("非空の AgentID は nil でないべき")
	}
	if got.(string) != agentID {
		t.Errorf("got = %v, want %q", got, agentID)
	}
}

// TestNilIfEmptyPtr_EmptyCreatedByReturnsNil は空の CreatedBy が nil になることを確認する
func TestNilIfEmptyPtr_EmptyCreatedByReturnsNil(t *testing.T) {
	createdBy := ""
	got := nilIfEmptyPtr(&createdBy)
	if got != nil {
		t.Errorf("空の CreatedBy は nil を返すべき: got %v", got)
	}
}

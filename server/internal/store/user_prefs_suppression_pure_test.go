package store

import (
	"encoding/json"
	"testing"
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

// applyPrefsDefaults は **本物を呼びます。**
//
// 以前ここには `Upsert` の既定値をそのまま書き写したものが置いてありました。
// 製品側の "dark" を "light" に変えても、落ちる検査はありません ——
// 試していたのは、検査自身の写しです。

// TestApplyPrefsDefaults_EmptyPrefs は空の設定に全デフォルトが適用されることを確認する
func TestApplyPrefsDefaults_EmptyPrefs(t *testing.T) {
	prefs := applyPreferenceDefaults(UserPreferences{})

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
	prefs := applyPreferenceDefaults(UserPreferences{
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
	prefs := applyPreferenceDefaults(UserPreferences{ItemsPerPage: 0})
	if prefs.ItemsPerPage != 20 {
		t.Errorf("ItemsPerPage = %d, want 20", prefs.ItemsPerPage)
	}
}

// TestApplyPrefsDefaults_NegativeItemsPerPage は ItemsPerPage が負のときデフォルト値になることを確認する
func TestApplyPrefsDefaults_NegativeItemsPerPage(t *testing.T) {
	prefs := applyPreferenceDefaults(UserPreferences{ItemsPerPage: -5})
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

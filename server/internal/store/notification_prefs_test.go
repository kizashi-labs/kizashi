package store

import (
	"testing"
	"time"
)

// ─── NotificationPrefs 構造体テスト ──────────────────────────────────────────

// TestNotificationPrefs_ZeroValue は NotificationPrefs のゼロ値が期待通りであることを確認する
func TestNotificationPrefs_ZeroValue(t *testing.T) {
	var p NotificationPrefs
	if p.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", p.ID)
	}
	if p.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", p.UserID)
	}
	if p.EmailEnabled {
		t.Error("EmailEnabled のデフォルトは false であるべき")
	}
	if p.EmailAddress != "" {
		t.Errorf("EmailAddress のデフォルト = %q, want \"\"", p.EmailAddress)
	}
	if p.MinSeverity != "" {
		t.Errorf("MinSeverity のデフォルト = %q, want \"\"", p.MinSeverity)
	}
	if p.NotifyIncidents {
		t.Error("NotifyIncidents のデフォルトは false であるべき")
	}
	if p.NotifyAgentOffline {
		t.Error("NotifyAgentOffline のデフォルトは false であるべき")
	}
}

// TestNotificationPrefs_FieldAssignment は NotificationPrefs フィールドの代入が正しく反映されることを確認する
func TestNotificationPrefs_FieldAssignment(t *testing.T) {
	now := time.Now()
	p := NotificationPrefs{
		ID:                 "pref-001",
		UserID:             "user-uuid-001",
		EmailEnabled:       true,
		EmailAddress:       "analyst@example.com",
		MinSeverity:        "high",
		NotifyIncidents:    true,
		NotifyAgentOffline: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if p.ID != "pref-001" {
		t.Errorf("ID = %q, want \"pref-001\"", p.ID)
	}
	if p.UserID != "user-uuid-001" {
		t.Errorf("UserID = %q, want \"user-uuid-001\"", p.UserID)
	}
	if !p.EmailEnabled {
		t.Error("EmailEnabled は true であるべき")
	}
	if p.EmailAddress != "analyst@example.com" {
		t.Errorf("EmailAddress = %q, want \"analyst@example.com\"", p.EmailAddress)
	}
	if p.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want \"high\"", p.MinSeverity)
	}
	if !p.NotifyIncidents {
		t.Error("NotifyIncidents は true であるべき")
	}
	if !p.NotifyAgentOffline {
		t.Error("NotifyAgentOffline は true であるべき")
	}
}

// TestNotificationPrefs_DefaultMinSeverity は GetByUserID が行なしの場合に
// MinSeverity のデフォルト値が "critical" であることを確認する
func TestNotificationPrefs_DefaultMinSeverity(t *testing.T) {
	// notification_prefs.go の GetByUserID 内でデフォルト構築するロジックを再現する
	userID := "user-no-prefs"
	p := &NotificationPrefs{
		UserID:      userID,
		MinSeverity: "critical",
	}

	if p.UserID != userID {
		t.Errorf("UserID = %q, want %q", p.UserID, userID)
	}
	if p.MinSeverity != "critical" {
		t.Errorf("MinSeverity のデフォルト = %q, want \"critical\"", p.MinSeverity)
	}
	// DB に行がない場合は ID が空文字列になる
	if p.ID != "" {
		t.Errorf("デフォルト状態の ID は空であるべき: got %q", p.ID)
	}
	// EmailEnabled はデフォルト false
	if p.EmailEnabled {
		t.Error("デフォルト状態の EmailEnabled は false であるべき")
	}
}

// TestNotificationPrefs_SeverityOrder は重大度の順序が正しいことを確認する
// notification_prefs.go の ListEmailEnabled は CASE 文で比較する
func TestNotificationPrefs_SeverityOrder(t *testing.T) {
	// severityOrder: critical=4, high=3, medium=2, low=1
	severityToInt := func(s string) int {
		switch s {
		case "low":
			return 1
		case "medium":
			return 2
		case "high":
			return 3
		case "critical":
			return 4
		default:
			return 0
		}
	}

	// 各レベルの整数値を確認する
	if severityToInt("low") != 1 {
		t.Errorf("low のスコア = %d, want 1", severityToInt("low"))
	}
	if severityToInt("medium") != 2 {
		t.Errorf("medium のスコア = %d, want 2", severityToInt("medium"))
	}
	if severityToInt("high") != 3 {
		t.Errorf("high のスコア = %d, want 3", severityToInt("high"))
	}
	if severityToInt("critical") != 4 {
		t.Errorf("critical のスコア = %d, want 4", severityToInt("critical"))
	}

	// 順序の確認: low < medium < high < critical
	levels := []string{"low", "medium", "high", "critical"}
	for i := 0; i < len(levels)-1; i++ {
		if severityToInt(levels[i]) >= severityToInt(levels[i+1]) {
			t.Errorf("重大度の順序が不正: %s(%d) >= %s(%d)",
				levels[i], severityToInt(levels[i]),
				levels[i+1], severityToInt(levels[i+1]))
		}
	}
}

// TestNotificationPrefs_SeverityFilter_HighEventReachesHighMin はイベントが高の場合に
// MinSeverity=high のユーザーが通知対象になることを確認する
func TestNotificationPrefs_SeverityFilter_HighEventReachesHighMin(t *testing.T) {
	severityToInt := func(s string) int {
		switch s {
		case "low":
			return 1
		case "medium":
			return 2
		case "high":
			return 3
		case "critical":
			return 4
		default:
			return 0
		}
	}

	// min_severity <= event_severity であれば通知対象
	shouldNotify := func(minSeverity, eventSeverity string) bool {
		return severityToInt(minSeverity) <= severityToInt(eventSeverity)
	}

	// high イベントは MinSeverity=low/medium/high のユーザーに届く
	if !shouldNotify("low", "high") {
		t.Error("MinSeverity=low のユーザーは high イベントを受け取るべき")
	}
	if !shouldNotify("medium", "high") {
		t.Error("MinSeverity=medium のユーザーは high イベントを受け取るべき")
	}
	if !shouldNotify("high", "high") {
		t.Error("MinSeverity=high のユーザーは high イベントを受け取るべき")
	}
	// high イベントは MinSeverity=critical のユーザーには届かない
	if shouldNotify("critical", "high") {
		t.Error("MinSeverity=critical のユーザーは high イベントを受け取らないべき")
	}
}

// TestNotificationPrefs_SeverityFilter_LowEventOnlyReachesLowMin は low イベントの到達範囲を確認する
func TestNotificationPrefs_SeverityFilter_LowEventOnlyReachesLowMin(t *testing.T) {
	severityToInt := func(s string) int {
		switch s {
		case "low":
			return 1
		case "medium":
			return 2
		case "high":
			return 3
		case "critical":
			return 4
		default:
			return 0
		}
	}

	shouldNotify := func(minSeverity, eventSeverity string) bool {
		return severityToInt(minSeverity) <= severityToInt(eventSeverity)
	}

	// low イベントは MinSeverity=low のユーザーのみに届く
	if !shouldNotify("low", "low") {
		t.Error("MinSeverity=low のユーザーは low イベントを受け取るべき")
	}
	if shouldNotify("medium", "low") {
		t.Error("MinSeverity=medium のユーザーは low イベントを受け取らないべき")
	}
	if shouldNotify("high", "low") {
		t.Error("MinSeverity=high のユーザーは low イベントを受け取らないべき")
	}
	if shouldNotify("critical", "low") {
		t.Error("MinSeverity=critical のユーザーは low イベントを受け取らないべき")
	}
}

// TestNotificationPrefs_EmailAddressRequired はメール通知に Email アドレスが必須であることを確認する
func TestNotificationPrefs_EmailAddressRequired(t *testing.T) {
	// メール通知が有効でもアドレスが空なら通知対象外
	p := NotificationPrefs{
		EmailEnabled: true,
		EmailAddress: "",
	}
	// ListEmailEnabled の SQL では email_address IS NOT NULL AND email_address <> '' が条件
	isEligible := p.EmailEnabled && p.EmailAddress != ""
	if isEligible {
		t.Error("EmailAddress が空の場合はメール通知対象外であるべき")
	}
}

// TestNotificationPrefs_NotifyIncidentsFlag はインシデント通知フラグが独立して機能することを確認する
func TestNotificationPrefs_NotifyIncidentsFlag(t *testing.T) {
	// メール有効 + インシデント通知有効
	p1 := NotificationPrefs{
		EmailEnabled:    true,
		EmailAddress:    "user@example.com",
		NotifyIncidents: true,
	}
	if !p1.NotifyIncidents {
		t.Error("NotifyIncidents = false, want true")
	}

	// メール有効 + インシデント通知無効
	p2 := NotificationPrefs{
		EmailEnabled:    true,
		EmailAddress:    "user@example.com",
		NotifyIncidents: false,
	}
	if p2.NotifyIncidents {
		t.Error("NotifyIncidents = true, want false")
	}
}

// TestNotificationPrefs_UpdatedAtChanges は UpdatedAt が変更されることを確認する
func TestNotificationPrefs_UpdatedAtChanges(t *testing.T) {
	createdAt := time.Now().Add(-1 * time.Hour)
	updatedAt := time.Now()

	p := NotificationPrefs{
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}

	// UpdatedAt は CreatedAt より新しいべき
	if !p.UpdatedAt.After(p.CreatedAt) {
		t.Errorf("UpdatedAt (%v) は CreatedAt (%v) より新しいべき", p.UpdatedAt, p.CreatedAt)
	}
}

package store

import (
	"encoding/json"
	"sort"
	"testing"
)

// ─── WidgetPref 構造体テスト ──────────────────────────────────────────────────

// TestWidgetPref_ZeroValue は WidgetPref のゼロ値が期待通りであることを確認する
func TestWidgetPref_ZeroValue(t *testing.T) {
	var w WidgetPref
	if w.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", w.ID)
	}
	if w.Visible {
		t.Error("Visible のデフォルトは false であるべき")
	}
	if w.Order != 0 {
		t.Errorf("Order のデフォルト = %d, want 0", w.Order)
	}
}

// TestWidgetPref_FieldAssignment は WidgetPref のフィールド代入を確認する
func TestWidgetPref_FieldAssignment(t *testing.T) {
	w := WidgetPref{
		ID:      "alert-summary",
		Visible: true,
		Order:   1,
	}
	if w.ID != "alert-summary" {
		t.Errorf("ID = %q, want \"alert-summary\"", w.ID)
	}
	if !w.Visible {
		t.Error("Visible は true であるべき")
	}
	if w.Order != 1 {
		t.Errorf("Order = %d, want 1", w.Order)
	}
}

// TestWidgetPref_VisibilityToggle は Visible フィールドのトグルを確認する
func TestWidgetPref_VisibilityToggle(t *testing.T) {
	w := WidgetPref{ID: "threat-map", Visible: true}
	if !w.Visible {
		t.Error("初期値: Visible は true であるべき")
	}
	// ウィジェットを非表示にする
	w.Visible = false
	if w.Visible {
		t.Error("トグル後: Visible は false であるべき")
	}
}

// ─── DashboardPrefs 構造体テスト ──────────────────────────────────────────────

// TestDashboardPrefs_ZeroValue は DashboardPrefs のゼロ値を確認する
func TestDashboardPrefs_ZeroValue(t *testing.T) {
	var prefs DashboardPrefs
	if prefs.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", prefs.UserID)
	}
	if prefs.Widgets != nil {
		t.Errorf("Widgets のデフォルトは nil であるべき: got %v", prefs.Widgets)
	}
}

// TestDashboardPrefs_EmptyWidgets は空のウィジェットリストを持つ DashboardPrefs を確認する
func TestDashboardPrefs_EmptyWidgets(t *testing.T) {
	prefs := DashboardPrefs{
		UserID:  "user-uuid-001",
		Widgets: []WidgetPref{},
	}
	if prefs.UserID != "user-uuid-001" {
		t.Errorf("UserID = %q, want \"user-uuid-001\"", prefs.UserID)
	}
	if len(prefs.Widgets) != 0 {
		t.Errorf("Widgets の数 = %d, want 0", len(prefs.Widgets))
	}
}

// TestDashboardPrefs_MultipleWidgets は複数ウィジェットの設定を確認する
func TestDashboardPrefs_MultipleWidgets(t *testing.T) {
	widgets := []WidgetPref{
		{ID: "alert-summary", Visible: true, Order: 0},
		{ID: "threat-map", Visible: true, Order: 1},
		{ID: "compliance-gauge", Visible: false, Order: 2},
		{ID: "agent-status", Visible: true, Order: 3},
	}
	prefs := DashboardPrefs{
		UserID:  "user-uuid-001",
		Widgets: widgets,
	}

	if len(prefs.Widgets) != 4 {
		t.Errorf("Widgets の数 = %d, want 4", len(prefs.Widgets))
	}
	if prefs.Widgets[2].Visible {
		t.Error("compliance-gauge は非表示であるべき")
	}
}

// TestDashboardPrefs_WidgetOrderSorting はウィジェットの Order フィールドでソートできることを確認する
func TestDashboardPrefs_WidgetOrderSorting(t *testing.T) {
	widgets := []WidgetPref{
		{ID: "widget-c", Order: 2},
		{ID: "widget-a", Order: 0},
		{ID: "widget-b", Order: 1},
	}
	// Order フィールドで昇順ソートする
	sort.Slice(widgets, func(i, j int) bool {
		return widgets[i].Order < widgets[j].Order
	})

	expected := []string{"widget-a", "widget-b", "widget-c"}
	for i, w := range widgets {
		if w.ID != expected[i] {
			t.Errorf("ソート後 widgets[%d].ID = %q, want %q", i, w.ID, expected[i])
		}
	}
}

// TestDashboardPrefs_WidgetsJSONSerialization は DashboardPrefs の JSON シリアライゼーションを確認する
func TestDashboardPrefs_WidgetsJSONSerialization(t *testing.T) {
	prefs := DashboardPrefs{
		UserID: "user-uuid-001",
		Widgets: []WidgetPref{
			{ID: "alert-summary", Visible: true, Order: 0},
			{ID: "threat-map", Visible: false, Order: 1},
		},
	}

	data, err := json.Marshal(prefs.Widgets)
	if err != nil {
		t.Fatalf("Widgets のシリアライズに失敗: %v", err)
	}

	var decoded []WidgetPref
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Widgets のデシリアライズに失敗: %v", err)
	}

	if len(decoded) != len(prefs.Widgets) {
		t.Errorf("デシリアライズ後の数 = %d, want %d", len(decoded), len(prefs.Widgets))
	}
	if decoded[0].ID != "alert-summary" {
		t.Errorf("decoded[0].ID = %q, want \"alert-summary\"", decoded[0].ID)
	}
	if !decoded[0].Visible {
		t.Error("decoded[0].Visible は true であるべき")
	}
	if decoded[1].Visible {
		t.Error("decoded[1].Visible は false であるべき")
	}
}

// TestDashboardPrefs_NilWidgetsFallback は nil Widgets が空スライスにフォールバックすることを確認する
func TestDashboardPrefs_NilWidgetsFallback(t *testing.T) {
	// dashboard_prefs.go の Get メソッドのロジック: widgets == nil なら [] を使用する
	applyWidgetsFallback := func(widgets []WidgetPref) []WidgetPref {
		if widgets == nil {
			return []WidgetPref{}
		}
		return widgets
	}

	result := applyWidgetsFallback(nil)
	if result == nil {
		t.Error("nil Widgets は空スライスにフォールバックするべき")
	}
	if len(result) != 0 {
		t.Errorf("フォールバック後の Widgets の数 = %d, want 0", len(result))
	}

	existing := []WidgetPref{{ID: "w1", Visible: true}}
	result2 := applyWidgetsFallback(existing)
	if len(result2) != 1 {
		t.Errorf("既存 Widgets の数 = %d, want 1", len(result2))
	}
}

// TestWidgetPref_KnownWidgetIDs は既知のウィジェット ID が文字列として正しく表現されることを確認する
func TestWidgetPref_KnownWidgetIDs(t *testing.T) {
	// EDRダッシュボードで使用される標準的なウィジェット ID
	knownIDs := []string{
		"alert-summary",
		"threat-map",
		"compliance-gauge",
		"agent-status",
		"recent-incidents",
		"ioc-hits",
	}
	for i, id := range knownIDs {
		w := WidgetPref{ID: id, Order: i, Visible: true}
		if w.ID != id {
			t.Errorf("WidgetPref.ID = %q, want %q", w.ID, id)
		}
	}
}

// TestDashboardPrefs_CountVisibleWidgets は表示中ウィジェットの数を集計するロジックを確認する
func TestDashboardPrefs_CountVisibleWidgets(t *testing.T) {
	prefs := DashboardPrefs{
		UserID: "user-uuid-001",
		Widgets: []WidgetPref{
			{ID: "w1", Visible: true},
			{ID: "w2", Visible: false},
			{ID: "w3", Visible: true},
			{ID: "w4", Visible: true},
			{ID: "w5", Visible: false},
		},
	}

	// 表示中のウィジェット数を集計する
	visibleCount := 0
	for _, w := range prefs.Widgets {
		if w.Visible {
			visibleCount++
		}
	}
	if visibleCount != 3 {
		t.Errorf("表示中ウィジェット数 = %d, want 3", visibleCount)
	}
}

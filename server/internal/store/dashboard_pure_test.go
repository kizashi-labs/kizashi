package store

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── DashboardLayout 構造体テスト ─────────────────────────────────────────────

// TestDashboardLayout_ZeroValue は DashboardLayout のゼロ値が期待通りであることを確認する
func TestDashboardLayout_ZeroValue(t *testing.T) {
	var d DashboardLayout
	if d.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", d.ID)
	}
	if d.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", d.UserID)
	}
	if d.Widgets != nil {
		t.Errorf("Widgets のデフォルトは nil であるべき: got %v", d.Widgets)
	}
	if !d.CreatedAt.IsZero() {
		t.Errorf("CreatedAt のデフォルトはゼロ時刻であるべき: got %v", d.CreatedAt)
	}
}

// TestDashboardLayout_FieldAssignment は DashboardLayout のフィールド代入を確認する
func TestDashboardLayout_FieldAssignment(t *testing.T) {
	now := time.Now()
	widgets := json.RawMessage(`[{"id":"w1","type":"alert_count"}]`)
	d := DashboardLayout{
		ID:        "layout-001",
		UserID:    "user-abc",
		Widgets:   widgets,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if d.ID != "layout-001" {
		t.Errorf("ID = %q, want \"layout-001\"", d.ID)
	}
	if d.UserID != "user-abc" {
		t.Errorf("UserID = %q, want \"user-abc\"", d.UserID)
	}
	if string(d.Widgets) != string(widgets) {
		t.Errorf("Widgets = %s, want %s", d.Widgets, widgets)
	}
	if !d.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", d.CreatedAt, now)
	}
}

// TestDashboardLayout_WidgetTypesParseable はウィジェット JSON が正しくパースできることを確認する
func TestDashboardLayout_WidgetTypesParseable(t *testing.T) {
	// EDR ダッシュボードで使用される標準ウィジェットタイプを確認する
	widgetTypes := []string{
		"alert_count",
		"agent_status",
		"ioc_matches",
		"threat_map",
		"severity_chart",
		"recent_events",
	}

	for _, wType := range widgetTypes {
		raw := json.RawMessage(`[{"id":"w1","type":"` + wType + `","position":{"x":0,"y":0},"size":{"w":4,"h":3}}]`)
		var widgets []map[string]interface{}
		if err := json.Unmarshal(raw, &widgets); err != nil {
			t.Errorf("ウィジェットタイプ %q のJSONパースに失敗: %v", wType, err)
			continue
		}
		if len(widgets) != 1 {
			t.Errorf("ウィジェット数 = %d, want 1", len(widgets))
			continue
		}
		gotType, ok := widgets[0]["type"].(string)
		if !ok {
			t.Errorf("type フィールドが string でない: %v", widgets[0]["type"])
			continue
		}
		if gotType != wType {
			t.Errorf("type = %q, want %q", gotType, wType)
		}
	}
}

// TestDashboardLayout_WidgetsRawMessagePreservesContent は json.RawMessage が内容を保持することを確認する
func TestDashboardLayout_WidgetsRawMessagePreservesContent(t *testing.T) {
	original := `[{"id":"widget-1","type":"alert_count","config":{"refresh":30}}]`
	d := DashboardLayout{
		Widgets: json.RawMessage(original),
	}
	if string(d.Widgets) != original {
		t.Errorf("Widgets = %s, want %s", string(d.Widgets), original)
	}
}

// TestDashboardLayout_EmptyWidgetsArray は空のウィジェット配列が有効な JSON であることを確認する
func TestDashboardLayout_EmptyWidgetsArray(t *testing.T) {
	d := DashboardLayout{
		ID:      "layout-empty",
		UserID:  "user-1",
		Widgets: json.RawMessage(`[]`),
	}
	var widgets []interface{}
	if err := json.Unmarshal(d.Widgets, &widgets); err != nil {
		t.Errorf("空の Widgets 配列のパースに失敗: %v", err)
	}
	if len(widgets) != 0 {
		t.Errorf("空の Widgets の長さ = %d, want 0", len(widgets))
	}
}

// TestDashboardLayout_MultipleWidgets は複数ウィジェットを持つレイアウトを確認する
func TestDashboardLayout_MultipleWidgets(t *testing.T) {
	raw := json.RawMessage(`[
		{"id":"w1","type":"alert_count","position":{"x":0,"y":0}},
		{"id":"w2","type":"agent_status","position":{"x":4,"y":0}},
		{"id":"w3","type":"ioc_matches","position":{"x":0,"y":3}}
	]`)
	d := DashboardLayout{Widgets: raw}

	var widgets []map[string]interface{}
	if err := json.Unmarshal(d.Widgets, &widgets); err != nil {
		t.Fatalf("複数ウィジェットのパースに失敗: %v", err)
	}
	if len(widgets) != 3 {
		t.Errorf("ウィジェット数 = %d, want 3", len(widgets))
	}
	// 各ウィジェットに id と type フィールドがあることを確認する
	for i, w := range widgets {
		if _, ok := w["id"]; !ok {
			t.Errorf("ウィジェット[%d] に id フィールドがない", i)
		}
		if _, ok := w["type"]; !ok {
			t.Errorf("ウィジェット[%d] に type フィールドがない", i)
		}
	}
}

// TestDashboardLayout_WidgetPositionValidation はウィジェット位置情報が正の整数であることを確認する
func TestDashboardLayout_WidgetPositionValidation(t *testing.T) {
	cases := []struct {
		name    string
		rawJSON string
		wantX   float64
		wantY   float64
	}{
		{"原点", `{"id":"w1","type":"alert_count","position":{"x":0,"y":0}}`, 0, 0},
		{"中央付近", `{"id":"w2","type":"agent_status","position":{"x":4,"y":3}}`, 4, 3},
		{"右下端", `{"id":"w3","type":"severity_chart","position":{"x":8,"y":6}}`, 8, 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w map[string]interface{}
			if err := json.Unmarshal([]byte(tc.rawJSON), &w); err != nil {
				t.Fatalf("パース失敗: %v", err)
			}
			pos, ok := w["position"].(map[string]interface{})
			if !ok {
				t.Fatal("position フィールドがない")
			}
			if x, ok := pos["x"].(float64); !ok || x != tc.wantX {
				t.Errorf("x = %v, want %v", pos["x"], tc.wantX)
			}
			if y, ok := pos["y"].(float64); !ok || y != tc.wantY {
				t.Errorf("y = %v, want %v", pos["y"], tc.wantY)
			}
		})
	}
}

// TestDashboardLayout_WidgetSizeValidation はウィジェットサイズが正のgrid単位であることを確認する
func TestDashboardLayout_WidgetSizeValidation(t *testing.T) {
	raw := `{"id":"w1","type":"alert_count","size":{"w":4,"h":3}}`
	var w map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		t.Fatalf("パース失敗: %v", err)
	}
	size, ok := w["size"].(map[string]interface{})
	if !ok {
		t.Fatal("size フィールドがない")
	}
	width, ok := size["w"].(float64)
	if !ok || width <= 0 {
		t.Errorf("width は正の値であるべき: got %v", size["w"])
	}
	height, ok := size["h"].(float64)
	if !ok || height <= 0 {
		t.Errorf("height は正の値であるべき: got %v", size["h"])
	}
}

// ─── ダッシュボード WHERE 句ビルダーテスト ─────────────────────────────────────

// ダッシュボードの絞り込みには、**製品側に対応する組み立てがありません。**
//
// ここには `buildDashboardFilter` という「WHERE 1=1 + user_id」の
// ヘルパーが置いてあり、それ自身を試していました。`dashboard.go` を
// 探しても、その形の組み立ては見つかりません —— **製品にない約束を
// 確かめていた**ことになります。
//
// 消すだけにします。**繋ぐ先がないものを繋いだふりはしません。**
// ダッシュボードの利用者ごとの絞り込みが要るなら、それは製品側に
// 足す話で、判断待ちの一覧に書いてあります。

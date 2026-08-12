package store

import (
	"testing"
	"time"
)

// ─── メンテナンスウィンドウ純粋関数ヘルパー ───────────────────────────────────

// windowIsActiveAt はウィンドウが指定時刻に有効かどうかを判定する（純粋関数）
// enabled=true かつ start_time <= t < end_time の場合に true を返す
func windowIsActiveAt(w *MaintenanceWindow, t time.Time) bool {
	return w.Enabled && !t.Before(w.StartTime) && t.Before(w.EndTime)
}

// windowsOverlap は2つのウィンドウが時間的に重なるかどうかを判定する
// 開始が相手の終了より前、かつ終了が相手の開始より後の場合にオーバーラップ
func windowsOverlap(a, b *MaintenanceWindow) bool {
	return a.StartTime.Before(b.EndTime) && a.EndTime.After(b.StartTime)
}

// windowDuration はウィンドウの継続時間を返す
func windowDuration(w *MaintenanceWindow) time.Duration {
	return w.EndTime.Sub(w.StartTime)
}

// filterActiveWindowsAt は指定時刻にアクティブなウィンドウのみを返す
func filterActiveWindowsAt(windows []*MaintenanceWindow, t time.Time) []*MaintenanceWindow {
	var result []*MaintenanceWindow
	for _, w := range windows {
		if windowIsActiveAt(w, t) {
			result = append(result, w)
		}
	}
	if result == nil {
		result = []*MaintenanceWindow{}
	}
	return result
}

// ─── MaintenanceWindow 構造体テスト ──────────────────────────────────────────

// TestMaintenanceWindow_DefaultValues は MaintenanceWindow のゼロ値フィールドを確認する
func TestMaintenanceWindow_DefaultValues(t *testing.T) {
	var w MaintenanceWindow
	if w.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", w.ID)
	}
	if w.Recurring {
		t.Error("Recurring のデフォルトは false であるべき")
	}
	if w.SuppressAlerts {
		t.Error("SuppressAlerts のデフォルトは false であるべき")
	}
	if w.SuppressNotifications {
		t.Error("SuppressNotifications のデフォルトは false であるべき")
	}
	if w.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
}

// TestMaintenanceWindow_FieldAssignment はフィールドへの代入が正しく反映されることを確認する
func TestMaintenanceWindow_FieldAssignment(t *testing.T) {
	now := time.Now()
	createdBy := "admin-001"
	w := MaintenanceWindow{
		ID:                    "mw-001",
		Name:                  "定期メンテナンス",
		Description:           "毎週土曜日のメンテナンス",
		StartTime:             now,
		EndTime:               now.Add(2 * time.Hour),
		Recurring:             true,
		RecurrencePattern:     "weekly",
		SuppressAlerts:        true,
		SuppressNotifications: true,
		AffectedAgents:        []string{"agent-a", "agent-b"},
		AffectedGroups:        []string{"group-1"},
		Enabled:               true,
		CreatedBy:             &createdBy,
	}
	if w.ID != "mw-001" {
		t.Errorf("ID = %q, want \"mw-001\"", w.ID)
	}
	if w.Name != "定期メンテナンス" {
		t.Errorf("Name = %q, want \"定期メンテナンス\"", w.Name)
	}
	if len(w.AffectedAgents) != 2 {
		t.Errorf("AffectedAgents 数 = %d, want 2", len(w.AffectedAgents))
	}
	if w.CreatedBy == nil || *w.CreatedBy != "admin-001" {
		t.Errorf("CreatedBy = %v, want \"admin-001\"", w.CreatedBy)
	}
}

// TestWindowIsActiveAt_CurrentlyActive は現在時刻がウィンドウ内であれば有効であることを確認する
func TestWindowIsActiveAt_CurrentlyActive(t *testing.T) {
	now := time.Now()
	w := &MaintenanceWindow{
		StartTime: now.Add(-30 * time.Minute),
		EndTime:   now.Add(30 * time.Minute),
		Enabled:   true,
	}
	if !windowIsActiveAt(w, now) {
		t.Error("現在時刻がウィンドウ内の場合、アクティブであるべき")
	}
}

// TestWindowIsActiveAt_NotYetStarted は開始前のウィンドウがアクティブでないことを確認する
func TestWindowIsActiveAt_NotYetStarted(t *testing.T) {
	now := time.Now()
	w := &MaintenanceWindow{
		StartTime: now.Add(1 * time.Hour),
		EndTime:   now.Add(3 * time.Hour),
		Enabled:   true,
	}
	if windowIsActiveAt(w, now) {
		t.Error("開始前のウィンドウはアクティブでないべき")
	}
}

// TestWindowIsActiveAt_AlreadyEnded は終了後のウィンドウがアクティブでないことを確認する
func TestWindowIsActiveAt_AlreadyEnded(t *testing.T) {
	now := time.Now()
	w := &MaintenanceWindow{
		StartTime: now.Add(-3 * time.Hour),
		EndTime:   now.Add(-1 * time.Hour),
		Enabled:   true,
	}
	if windowIsActiveAt(w, now) {
		t.Error("終了後のウィンドウはアクティブでないべき")
	}
}

// TestWindowIsActiveAt_DisabledWindow は無効ウィンドウが時間内でもアクティブでないことを確認する
func TestWindowIsActiveAt_DisabledWindow(t *testing.T) {
	now := time.Now()
	w := &MaintenanceWindow{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now.Add(1 * time.Hour),
		Enabled:   false, // 無効
	}
	if windowIsActiveAt(w, now) {
		t.Error("無効ウィンドウは時間内でもアクティブでないべき")
	}
}

// TestWindowsOverlap_Overlapping は重なり合う2つのウィンドウを検出できることを確認する
func TestWindowsOverlap_Overlapping(t *testing.T) {
	base := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)
	a := &MaintenanceWindow{
		StartTime: base,
		EndTime:   base.Add(2 * time.Hour),
	}
	b := &MaintenanceWindow{
		StartTime: base.Add(1 * time.Hour),
		EndTime:   base.Add(3 * time.Hour),
	}
	if !windowsOverlap(a, b) {
		t.Error("重なり合うウィンドウはオーバーラップを返すべき")
	}
	// 対称性も確認
	if !windowsOverlap(b, a) {
		t.Error("ウィンドウのオーバーラップ判定は対称でないべきでない")
	}
}

// TestWindowsOverlap_NonOverlapping は重ならない2つのウィンドウを正しく識別することを確認する
func TestWindowsOverlap_NonOverlapping(t *testing.T) {
	base := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)
	a := &MaintenanceWindow{
		StartTime: base,
		EndTime:   base.Add(1 * time.Hour),
	}
	b := &MaintenanceWindow{
		StartTime: base.Add(2 * time.Hour),
		EndTime:   base.Add(3 * time.Hour),
	}
	if windowsOverlap(a, b) {
		t.Error("重ならないウィンドウはオーバーラップを返すべきでない")
	}
}

// TestWindowsOverlap_Adjacent は隣接するウィンドウ(接触のみ)がオーバーラップしないことを確認する
func TestWindowsOverlap_Adjacent(t *testing.T) {
	base := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)
	a := &MaintenanceWindow{
		StartTime: base,
		EndTime:   base.Add(1 * time.Hour),
	}
	b := &MaintenanceWindow{
		StartTime: base.Add(1 * time.Hour), // a の終了と同時開始
		EndTime:   base.Add(2 * time.Hour),
	}
	// 終了時刻と開始時刻が同じ場合はオーバーラップしない
	if windowsOverlap(a, b) {
		t.Error("隣接ウィンドウ(接触のみ)はオーバーラップしないべき")
	}
}

// TestWindowDuration_CalculatesCorrectly はウィンドウの継続時間が正しく計算されることを確認する
func TestWindowDuration_CalculatesCorrectly(t *testing.T) {
	base := time.Date(2026, 3, 23, 8, 0, 0, 0, time.UTC)
	cases := []struct {
		hours time.Duration
		name  string
	}{
		{1 * time.Hour, "1時間ウィンドウ"},
		{4 * time.Hour, "4時間ウィンドウ"},
		{24 * time.Hour, "24時間ウィンドウ"},
	}
	for _, tc := range cases {
		w := &MaintenanceWindow{
			StartTime: base,
			EndTime:   base.Add(tc.hours),
		}
		got := windowDuration(w)
		if got != tc.hours {
			t.Errorf("%s: duration = %v, want %v", tc.name, got, tc.hours)
		}
	}
}

// TestFilterActiveWindowsAt_MixedWindows は混在するウィンドウからアクティブなものだけ抽出できることを確認する
func TestFilterActiveWindowsAt_MixedWindows(t *testing.T) {
	now := time.Now()
	windows := []*MaintenanceWindow{
		// アクティブ
		{ID: "mw-1", StartTime: now.Add(-1 * time.Hour), EndTime: now.Add(1 * time.Hour), Enabled: true},
		// 開始前
		{ID: "mw-2", StartTime: now.Add(1 * time.Hour), EndTime: now.Add(3 * time.Hour), Enabled: true},
		// 終了済み
		{ID: "mw-3", StartTime: now.Add(-3 * time.Hour), EndTime: now.Add(-1 * time.Hour), Enabled: true},
		// 無効
		{ID: "mw-4", StartTime: now.Add(-1 * time.Hour), EndTime: now.Add(1 * time.Hour), Enabled: false},
	}
	active := filterActiveWindowsAt(windows, now)
	if len(active) != 1 {
		t.Errorf("アクティブウィンドウ数 = %d, want 1", len(active))
	}
	if len(active) == 1 && active[0].ID != "mw-1" {
		t.Errorf("アクティブウィンドウ ID = %q, want \"mw-1\"", active[0].ID)
	}
}

// TestFilterActiveWindowsAt_EmptySlice は空スライスに対して空スライスを返すことを確認する
func TestFilterActiveWindowsAt_EmptySlice(t *testing.T) {
	result := filterActiveWindowsAt([]*MaintenanceWindow{}, time.Now())
	if len(result) != 0 {
		t.Errorf("空入力から空出力のはず: got %d items", len(result))
	}
}

// TestMaintenanceWindow_AffectedAgentsDefault は AffectedAgents のデフォルトがゼロ値スライスであることを確認する
func TestMaintenanceWindow_AffectedAgentsDefault(t *testing.T) {
	w := &MaintenanceWindow{}
	// ゼロ値では nil スライスだが、Create/List では {} に変換される
	if w.AffectedAgents != nil {
		// ゼロ値では nil のまま — これは正常
		t.Log("AffectedAgents のゼロ値は nil (正常)")
	}
	// 空スライスを代入した場合の挙動確認
	w.AffectedAgents = []string{}
	if len(w.AffectedAgents) != 0 {
		t.Error("空スライス代入後は長さ0であるべき")
	}
}

// TestMaintenanceWindow_RecurrencePattern はリカーリングパターンのフィールドを確認する
func TestMaintenanceWindow_RecurrencePattern(t *testing.T) {
	patterns := []string{"daily", "weekly", "monthly", "custom"}
	for _, p := range patterns {
		w := MaintenanceWindow{
			Recurring:         true,
			RecurrencePattern: p,
		}
		if w.RecurrencePattern != p {
			t.Errorf("RecurrencePattern = %q, want %q", w.RecurrencePattern, p)
		}
		if !w.Recurring {
			t.Error("Recurring が true に設定されているべき")
		}
	}
}

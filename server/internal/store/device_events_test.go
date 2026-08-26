package store

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─── DeviceEvent 構造体テスト ─────────────────────────────────────────────────

// TestDeviceEvent_ZeroValue は DeviceEvent のゼロ値が期待通りであることを確認する
func TestDeviceEvent_ZeroValue(t *testing.T) {
	var e DeviceEvent
	if e.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", e.ID)
	}
	if e.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", e.AgentID)
	}
	if e.Action != "" {
		t.Errorf("Action のデフォルト = %q, want \"\"", e.Action)
	}
	if e.DeviceType != "" {
		t.Errorf("DeviceType のデフォルト = %q, want \"\"", e.DeviceType)
	}
	if e.RawData != nil {
		t.Errorf("RawData のデフォルトは nil であるべき: got %v", *e.RawData)
	}
}

// TestDeviceEvent_KnownActions は既知のデバイスイベントアクションを確認する
// USB デバイスの接続・切断などの操作を表す標準的なアクション値
func TestDeviceEvent_KnownActions(t *testing.T) {
	knownActions := []string{"connect", "disconnect", "block", "allow", "mount", "unmount"}
	for _, action := range knownActions {
		e := DeviceEvent{Action: action}
		if e.Action != action {
			t.Errorf("Action = %q, want %q", e.Action, action)
		}
	}
}

// TestDeviceEvent_KnownDeviceTypes は既知のデバイスタイプを確認する
// USB、Bluetooth、HID など標準的なデバイスタイプを列挙する
func TestDeviceEvent_KnownDeviceTypes(t *testing.T) {
	knownTypes := []string{"usb", "bluetooth", "hid", "storage", "network", "printer"}
	for _, dt := range knownTypes {
		e := DeviceEvent{DeviceType: dt}
		if e.DeviceType != dt {
			t.Errorf("DeviceType = %q, want %q", e.DeviceType, dt)
		}
	}
}

// TestDeviceEvent_FieldAssignment は DeviceEvent の全フィールド代入を確認する
func TestDeviceEvent_FieldAssignment(t *testing.T) {
	rawData := `{"usb_class": "08"}`
	e := DeviceEvent{
		ID:         "evt-001",
		AgentID:    "agent-abc",
		Action:     "connect",
		DeviceID:   "VID_0781&PID_5583",
		DeviceName: "SanDisk USB Drive",
		DeviceType: "usb",
		VendorID:   "0781",
		ProductID:  "5583",
		RawData:    &rawData,
		CreatedAt:  "2026-03-23T10:00:00Z",
	}

	if e.ID != "evt-001" {
		t.Errorf("ID = %q, want \"evt-001\"", e.ID)
	}
	if e.Action != "connect" {
		t.Errorf("Action = %q, want \"connect\"", e.Action)
	}
	if e.DeviceName != "SanDisk USB Drive" {
		t.Errorf("DeviceName = %q, want \"SanDisk USB Drive\"", e.DeviceName)
	}
	if e.VendorID != "0781" {
		t.Errorf("VendorID = %q, want \"0781\"", e.VendorID)
	}
	if e.ProductID != "5583" {
		t.Errorf("ProductID = %q, want \"5583\"", e.ProductID)
	}
	if *e.RawData != rawData {
		t.Errorf("*RawData = %q, want %q", *e.RawData, rawData)
	}
}

// TestDeviceEvent_CreatedAtRFC3339Format は CreatedAt が RFC3339 形式であることを確認する
func TestDeviceEvent_CreatedAtRFC3339Format(t *testing.T) {
	now := time.Now()
	e := DeviceEvent{
		CreatedAt: now.Format(time.RFC3339),
	}

	// RFC3339 形式は "T" で日付と時刻が区切られる
	if !strings.Contains(e.CreatedAt, "T") {
		t.Errorf("CreatedAt は RFC3339 形式であるべき: got %q", e.CreatedAt)
	}
}

// ─── DeviceEventFilter 構造体テスト ──────────────────────────────────────────

// TestDeviceEventFilter_ZeroValue は DeviceEventFilter のゼロ値を確認する
func TestDeviceEventFilter_ZeroValue(t *testing.T) {
	var f DeviceEventFilter
	if f.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", f.AgentID)
	}
	if f.Action != "" {
		t.Errorf("Action のデフォルト = %q, want \"\"", f.Action)
	}
	if f.DeviceType != "" {
		t.Errorf("DeviceType のデフォルト = %q, want \"\"", f.DeviceType)
	}
	if f.Since != nil {
		t.Errorf("Since のデフォルトは nil であるべき: got %v", f.Since)
	}
	if f.Until != nil {
		t.Errorf("Until のデフォルトは nil であるべき: got %v", f.Until)
	}
	if f.Limit != 0 {
		t.Errorf("Limit のデフォルト = %d, want 0", f.Limit)
	}
	if f.Offset != 0 {
		t.Errorf("Offset のデフォルト = %d, want 0", f.Offset)
	}
}

// TestDeviceEventFilter_LimitNormalization は Limit の正規化ロジックを確認する
// device_events.go の List メソッドで Limit が 0 以下の場合 50、500 超の場合 500 になる
func TestDeviceEventFilter_LimitNormalization(t *testing.T) {
	cases := []struct {
		input    int
		expected int
	}{
		{0, 50},
		{-1, 50},
		{50, 50},
		{100, 100},
		{500, 500},
		{501, 500},
		{1000, 500},
	}

	for _, tc := range cases {
		limit := tc.input
		if limit <= 0 {
			limit = 50
		}
		if limit > 500 {
			limit = 500
		}
		if limit != tc.expected {
			t.Errorf("Limit %d → %d, want %d", tc.input, limit, tc.expected)
		}
	}
}

// TestDeviceEventFilter_SinceUntilRange は Since/Until フィルターの時刻範囲を確認する
func TestDeviceEventFilter_SinceUntilRange(t *testing.T) {
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	until := now

	f := DeviceEventFilter{
		Since: &since,
		Until: &until,
	}

	if f.Since == nil || !f.Since.Equal(since) {
		t.Errorf("Since = %v, want %v", f.Since, since)
	}
	if f.Until == nil || !f.Until.Equal(until) {
		t.Errorf("Until = %v, want %v", f.Until, until)
	}
	if !f.Until.After(*f.Since) {
		t.Error("Until は Since より後であるべき")
	}
}

// ─── デバイスイベントクエリビルダーロジックテスト ──────────────────────────────

// buildDeviceEventWhere は **本物を呼びます。**
//
// 以前ここには List の組み立てを書き写したものが置いてありました。
func buildDeviceEventWhere(f DeviceEventFilter) (string, []interface{}) {
	return deviceEventListWhere(f)
}

// 1ページの件数の切り詰め。**写しには入っていませんでした。**
//
// 0 を通すと 0 件返り、画面では「デバイスの記録が無い」と見分けが
// 付きません。USB は持ち出しの経路なので、記録が空に見えることと
// 記録が無いことの区別が要ります。
func TestDeviceEventLimitIsClamped(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, 50}, {-1, 50}, {50, 50}, {500, 500}, {5000, 500},
	} {
		if got := clampDeviceEventLimit(tc.in); got != tc.want {
			t.Errorf("clampDeviceEventLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// 5つ全部を指定したとき、番号と引数が揃っていること。
func TestDeviceEventPlaceholdersStayInStepWithArgs(t *testing.T) {
	now := time.Now()
	where, args := deviceEventListWhere(DeviceEventFilter{
		AgentID: "a", Action: "b", DeviceType: "c", Since: &now, Until: &now,
	})
	if len(args) != 5 {
		t.Fatalf("args = %v, want 5 件", args)
	}
	for i := 1; i <= 5; i++ {
		if !strings.Contains(where, fmt.Sprintf("$%d", i)) {
			t.Errorf("$%d がありません: %q", i, where)
		}
	}
	if strings.Contains(where, "$6") {
		t.Errorf("引数の数を超えるプレースホルダがあります: %q", where)
	}
}

// TestBuildDeviceEventWhere_EmptyFilter は全フィルターが空のとき "WHERE 1=1" であることを確認する
func TestBuildDeviceEventWhere_EmptyFilter(t *testing.T) {
	where, args := buildDeviceEventWhere(DeviceEventFilter{})
	if where != "WHERE 1=1" {
		t.Errorf("空フィルターは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildDeviceEventWhere_AgentIDFilter は AgentID フィルターが条件を追加することを確認する
func TestBuildDeviceEventWhere_AgentIDFilter(t *testing.T) {
	f := DeviceEventFilter{AgentID: "agent-xyz"}
	where, args := buildDeviceEventWhere(f)

	if !strings.Contains(where, "agent_id") {
		t.Errorf("agent_id 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "agent-xyz" {
		t.Errorf("args = %v, want [agent-xyz]", args)
	}
}

// TestBuildDeviceEventWhere_ActionFilter は Action フィルターが条件を追加することを確認する
func TestBuildDeviceEventWhere_ActionFilter(t *testing.T) {
	f := DeviceEventFilter{Action: "connect"}
	where, args := buildDeviceEventWhere(f)

	if !strings.Contains(where, "action") {
		t.Errorf("action 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "connect" {
		t.Errorf("args = %v, want [connect]", args)
	}
}

// TestBuildDeviceEventWhere_DeviceTypeFilter は DeviceType フィルターが条件を追加することを確認する
func TestBuildDeviceEventWhere_DeviceTypeFilter(t *testing.T) {
	f := DeviceEventFilter{DeviceType: "usb"}
	where, args := buildDeviceEventWhere(f)

	if !strings.Contains(where, "device_type") {
		t.Errorf("device_type 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "usb" {
		t.Errorf("args = %v, want [usb]", args)
	}
}

// TestBuildDeviceEventWhere_SinceUntilFilter は Since/Until フィルターが時刻条件を追加することを確認する
func TestBuildDeviceEventWhere_SinceUntilFilter(t *testing.T) {
	now := time.Now()
	since := now.Add(-1 * time.Hour)
	f := DeviceEventFilter{
		Since: &since,
		Until: &now,
	}
	where, args := buildDeviceEventWhere(f)

	if !strings.Contains(where, "created_at >=") {
		t.Errorf("created_at >= 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "created_at <=") {
		t.Errorf("created_at <= 条件が含まれるべき: %q", where)
	}
	if len(args) != 2 {
		t.Errorf("Since+Until フィルターは引数 2 個のはず: got %d", len(args))
	}
}

// TestBuildDeviceEventWhere_AllFilters は全フィルターが組み合わさったとき引数数が正しいことを確認する
func TestBuildDeviceEventWhere_AllFilters(t *testing.T) {
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	f := DeviceEventFilter{
		AgentID:    "agent-001",
		Action:     "block",
		DeviceType: "usb",
		Since:      &since,
		Until:      &now,
	}
	_, args := buildDeviceEventWhere(f)

	// AgentID(1) + Action(1) + DeviceType(1) + Since(1) + Until(1) = 5
	if len(args) != 5 {
		t.Errorf("全フィルターで引数 5 個のはず: got %d", len(args))
	}
}

// ─── DeviceEventStatRow 構造体テスト ──────────────────────────────────────────

// TestDeviceEventStatRow_ZeroValue は DeviceEventStatRow のゼロ値を確認する
func TestDeviceEventStatRow_ZeroValue(t *testing.T) {
	var r DeviceEventStatRow
	if r.Action != "" {
		t.Errorf("Action のデフォルト = %q, want \"\"", r.Action)
	}
	if r.DeviceType != "" {
		t.Errorf("DeviceType のデフォルト = %q, want \"\"", r.DeviceType)
	}
	if r.Count != 0 {
		t.Errorf("Count のデフォルト = %d, want 0", r.Count)
	}
}

// TestDeviceEventStatRow_FieldAssignment は DeviceEventStatRow のフィールド代入を確認する
func TestDeviceEventStatRow_FieldAssignment(t *testing.T) {
	r := DeviceEventStatRow{
		Action:     "connect",
		DeviceType: "usb",
		Count:      42,
	}

	if r.Action != "connect" {
		t.Errorf("Action = %q, want \"connect\"", r.Action)
	}
	if r.DeviceType != "usb" {
		t.Errorf("DeviceType = %q, want \"usb\"", r.DeviceType)
	}
	if r.Count != 42 {
		t.Errorf("Count = %d, want 42", r.Count)
	}
}

// TestDeviceEventStatRow_Aggregation は複数の StatRow を集計するロジックを確認する
func TestDeviceEventStatRow_Aggregation(t *testing.T) {
	rows := []DeviceEventStatRow{
		{Action: "connect", DeviceType: "usb", Count: 10},
		{Action: "disconnect", DeviceType: "usb", Count: 8},
		{Action: "block", DeviceType: "usb", Count: 3},
		{Action: "connect", DeviceType: "bluetooth", Count: 5},
	}

	total := 0
	for _, r := range rows {
		total += r.Count
	}

	if total != 26 {
		t.Errorf("合計カウント = %d, want 26", total)
	}
}

// ─── nullStr ユーティリティ（device_events 側の利用）────────────────────────

// TestNullStr_DeviceNameEmpty はデバイス名が空のとき nullStr が nil を返すことを確認する
// device_events.go の Insert メソッドで空フィールドに NULL を保存するために使用される
func TestNullStr_DeviceNameEmpty(t *testing.T) {
	result := nullStr("")
	if result != nil {
		t.Errorf("空のデバイス名は nil を返すべき: got %v", *result)
	}
}

// TestNullStr_DeviceNameNonEmpty はデバイス名が非空のとき nullStr がポインタを返すことを確認する
func TestNullStr_DeviceNameNonEmpty(t *testing.T) {
	name := "SanDisk Ultra"
	result := nullStr(name)
	if result == nil {
		t.Fatal("非空のデバイス名は nil でないポインタを返すべき")
	}
	if *result != name {
		t.Errorf("*result = %q, want %q", *result, name)
	}
}

// TestNullStr_VendorProductIDs は VendorID / ProductID の nil 変換を確認する
func TestNullStr_VendorProductIDs(t *testing.T) {
	// 空の VendorID/ProductID → NULL（nilStr が nil を返す）
	if nullStr("") != nil {
		t.Error("空の VendorID は nil を返すべき")
	}

	// 非空の VendorID → ポインタを返す
	vid := "0781"
	if nullStr(vid) == nil {
		t.Error("非空の VendorID は nil でないべき")
	}
	if *nullStr(vid) != vid {
		t.Errorf("*nullStr(%q) = %q, want %q", vid, *nullStr(vid), vid)
	}
}

// ─── デバイスタイプ分類ロジックテスト ─────────────────────────────────────────

// classifyDeviceRisk はデバイスタイプとアクションに基づいてリスクレベルを分類するロジック
// connect イベントで storage タイプのデバイスは高リスクとみなす
func classifyDeviceRisk(deviceType, action string) string {
	if action == "block" {
		return "blocked"
	}
	if action == "connect" {
		switch deviceType {
		case "storage":
			return "high"
		case "usb":
			return "medium"
		case "bluetooth":
			return "medium"
		case "hid":
			return "low"
		}
	}
	return "info"
}

// TestClassifyDeviceRisk_BlockedAction はブロックアクションが "blocked" を返すことを確認する
func TestClassifyDeviceRisk_BlockedAction(t *testing.T) {
	cases := []struct {
		deviceType string
		action     string
	}{
		{"usb", "block"},
		{"storage", "block"},
		{"bluetooth", "block"},
	}

	for _, tc := range cases {
		got := classifyDeviceRisk(tc.deviceType, tc.action)
		if got != "blocked" {
			t.Errorf("classifyDeviceRisk(%q, %q) = %q, want \"blocked\"", tc.deviceType, tc.action, got)
		}
	}
}

// TestClassifyDeviceRisk_StorageConnectIsHigh は storage デバイスの接続が高リスクであることを確認する
func TestClassifyDeviceRisk_StorageConnectIsHigh(t *testing.T) {
	got := classifyDeviceRisk("storage", "connect")
	if got != "high" {
		t.Errorf("classifyDeviceRisk(\"storage\", \"connect\") = %q, want \"high\"", got)
	}
}

// TestClassifyDeviceRisk_USBConnectIsMedium は USB デバイスの接続が中リスクであることを確認する
func TestClassifyDeviceRisk_USBConnectIsMedium(t *testing.T) {
	got := classifyDeviceRisk("usb", "connect")
	if got != "medium" {
		t.Errorf("classifyDeviceRisk(\"usb\", \"connect\") = %q, want \"medium\"", got)
	}
}

// TestClassifyDeviceRisk_HIDConnectIsLow は HID デバイスの接続が低リスクであることを確認する
func TestClassifyDeviceRisk_HIDConnectIsLow(t *testing.T) {
	got := classifyDeviceRisk("hid", "connect")
	if got != "low" {
		t.Errorf("classifyDeviceRisk(\"hid\", \"connect\") = %q, want \"low\"", got)
	}
}

// TestClassifyDeviceRisk_DisconnectIsInfo は切断アクションが情報レベルであることを確認する
func TestClassifyDeviceRisk_DisconnectIsInfo(t *testing.T) {
	got := classifyDeviceRisk("usb", "disconnect")
	if got != "info" {
		t.Errorf("classifyDeviceRisk(\"usb\", \"disconnect\") = %q, want \"info\"", got)
	}
}

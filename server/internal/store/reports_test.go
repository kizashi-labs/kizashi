package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── ReportJobRow 構造体テスト ─────────────────────────────────────────────────

// TestReportJobRow_ZeroValue は ReportJobRow のゼロ値が期待通りであることを確認する
func TestReportJobRow_ZeroValue(t *testing.T) {
	var r ReportJobRow
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", r.Type)
	}
	if r.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", r.Status)
	}
	if r.RequestedBy != "" {
		t.Errorf("RequestedBy のデフォルト = %q, want \"\"", r.RequestedBy)
	}
	if r.CompletedAt != nil {
		t.Errorf("CompletedAt のデフォルトは nil であるべき: got %v", *r.CompletedAt)
	}
	if r.FromTime != nil {
		t.Errorf("FromTime のデフォルトは nil であるべき: got %v", *r.FromTime)
	}
	if r.ToTime != nil {
		t.Errorf("ToTime のデフォルトは nil であるべき: got %v", *r.ToTime)
	}
	if r.Error != "" {
		t.Errorf("Error のデフォルト = %q, want \"\"", r.Error)
	}
	if r.Content != nil {
		t.Errorf("Content のデフォルトは nil であるべき: got %v", r.Content)
	}
}

// TestReportJobRow_FieldAssignment は ReportJobRow の各フィールド代入が正しく反映されることを確認する
func TestReportJobRow_FieldAssignment(t *testing.T) {
	now := time.Now()
	completed := now.Add(5 * time.Minute)
	from := now.Add(-24 * time.Hour)
	to := now

	r := ReportJobRow{
		ID:              "report-001",
		Type:            "executive_summary",
		Status:          "completed",
		RequestedBy:     "user-abc",
		RequestedByName: "analyst@example.com",
		RequestedAt:     now,
		CompletedAt:     &completed,
		FromTime:        &from,
		ToTime:          &to,
		Error:           "",
		Content:         map[string]interface{}{"count": 42},
	}

	if r.ID != "report-001" {
		t.Errorf("ID = %q, want \"report-001\"", r.ID)
	}
	if r.Type != "executive_summary" {
		t.Errorf("Type = %q, want \"executive_summary\"", r.Type)
	}
	if r.Status != "completed" {
		t.Errorf("Status = %q, want \"completed\"", r.Status)
	}
	if r.CompletedAt == nil {
		t.Fatal("CompletedAt は nil でないべき")
	}
	if !r.CompletedAt.Equal(completed) {
		t.Errorf("CompletedAt = %v, want %v", *r.CompletedAt, completed)
	}
	if r.FromTime == nil || !r.FromTime.Equal(from) {
		t.Errorf("FromTime が期待値と異なる")
	}
	if r.ToTime == nil || !r.ToTime.Equal(to) {
		t.Errorf("ToTime が期待値と異なる")
	}
}

// TestReportJobRow_KnownTypes は既知のレポートタイプが文字列として表現できることを確認する
func TestReportJobRow_KnownTypes(t *testing.T) {
	// EDRプラットフォームで使用される標準的なレポートタイプ
	knownTypes := []string{
		"executive_summary",
		"threat_report",
		"incident_report",
		"compliance_report",
		"vulnerability_report",
	}
	for _, rt := range knownTypes {
		r := ReportJobRow{Type: rt}
		if r.Type != rt {
			t.Errorf("Type = %q, want %q", r.Type, rt)
		}
	}
}

// TestReportJobRow_KnownStatuses は既知のステータス値を確認する
// "pending" | "running" | "completed" | "failed" の4つが有効
func TestReportJobRow_KnownStatuses(t *testing.T) {
	validStatuses := []string{"pending", "running", "completed", "failed"}
	for _, status := range validStatuses {
		r := ReportJobRow{Status: status}
		if r.Status != status {
			t.Errorf("Status = %q, want %q", r.Status, status)
		}
	}
}

// TestReportJobRow_StatusTransitionOrder はステータス遷移の順序が意味的に正しいことを確認する
// pending → running → completed/failed の順が想定される
func TestReportJobRow_StatusTransitionOrder(t *testing.T) {
	transitions := []struct {
		from string
		to   string
		ok   bool
	}{
		{"pending", "running", true},
		{"running", "completed", true},
		{"running", "failed", true},
		{"completed", "failed", false}, // 完了後に失敗へは遷移しない
		{"failed", "completed", false}, // 失敗後に完了へは遷移しない
	}

	// 状態遷移の妥当性をピュアロジックで検証する
	isValidTransition := func(from, to string) bool {
		switch from {
		case "pending":
			return to == "running"
		case "running":
			return to == "completed" || to == "failed"
		default:
			return false
		}
	}

	for _, tc := range transitions {
		got := isValidTransition(tc.from, tc.to)
		if got != tc.ok {
			t.Errorf("遷移 %q → %q: got %v, want %v", tc.from, tc.to, got, tc.ok)
		}
	}
}

// TestReportJobRow_TimeRangeValidation は FromTime < ToTime の時間範囲が正しいことを確認する
func TestReportJobRow_TimeRangeValidation(t *testing.T) {
	now := time.Now()
	from := now.Add(-7 * 24 * time.Hour)
	to := now

	// 開始時刻 < 終了時刻 が有効な範囲
	isValidRange := func(fromT, toT *time.Time) bool {
		if fromT == nil || toT == nil {
			return true // 範囲未指定は有効
		}
		return fromT.Before(*toT)
	}

	if !isValidRange(&from, &to) {
		t.Error("過去 → 現在の範囲は有効であるべき")
	}
	if isValidRange(&to, &from) {
		t.Error("終了 < 開始の範囲は無効であるべき")
	}
	if !isValidRange(nil, nil) {
		t.Error("nil 範囲は有効であるべき")
	}
}

// TestReportJobRow_ContentJSON は Content フィールドが JSON にシリアライズ可能であることを確認する
func TestReportJobRow_ContentJSON(t *testing.T) {
	content := map[string]interface{}{
		"total_alerts":   150,
		"critical_count": 12,
		"report_period":  "2026-03",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
	}
	r := ReportJobRow{
		ID:      "report-json-test",
		Type:    "executive_summary",
		Content: content,
	}

	// Content が JSON マーシャル可能であることを確認する
	data, err := json.Marshal(r.Content)
	if err != nil {
		t.Fatalf("Content の JSON マーシャルに失敗: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON 出力が空であるべきでない")
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON アンマーシャルに失敗: %v", err)
	}
	// total_alerts が正しく復元されることを確認する
	if v, ok := decoded["total_alerts"]; !ok || v.(float64) != 150 {
		t.Errorf("total_alerts = %v, want 150", decoded["total_alerts"])
	}
}

// ─── ReportSchedule 構造体テスト ──────────────────────────────────────────────

// TestReportSchedule_ZeroValue_Reports は ReportSchedule のゼロ値を確認する
func TestReportSchedule_ZeroValue_Reports(t *testing.T) {
	var sc ReportSchedule
	if sc.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", sc.ID)
	}
	if sc.Frequency != "" {
		t.Errorf("Frequency のデフォルト = %q, want \"\"", sc.Frequency)
	}
	if sc.DayOfWeek != nil {
		t.Errorf("DayOfWeek のデフォルトは nil であるべき")
	}
	if sc.DayOfMonth != nil {
		t.Errorf("DayOfMonth のデフォルトは nil であるべき")
	}
	if sc.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
	if sc.LastRunAt != nil {
		t.Errorf("LastRunAt のデフォルトは nil であるべき")
	}
	if sc.Recipients != nil {
		t.Errorf("Recipients のデフォルトは nil であるべき")
	}
}

// TestReportSchedule_KnownFrequencies は有効な頻度値を確認する
// "daily" | "weekly" | "monthly" の3つが標準
func TestReportSchedule_KnownFrequencies(t *testing.T) {
	frequencies := []string{"daily", "weekly", "monthly"}
	for _, f := range frequencies {
		sc := ReportSchedule{Frequency: f}
		if sc.Frequency != f {
			t.Errorf("Frequency = %q, want %q", sc.Frequency, f)
		}
	}
}

// TestReportSchedule_RecipientsSlice_Reports は Recipients スライスの操作を確認する
func TestReportSchedule_RecipientsSlice_Reports(t *testing.T) {
	sc := ReportSchedule{
		Recipients: []string{
			"security@example.com",
			"ciso@example.com",
			"ops@example.com",
		},
	}
	if len(sc.Recipients) != 3 {
		t.Errorf("Recipients 件数 = %d, want 3", len(sc.Recipients))
	}
	if sc.Recipients[0] != "security@example.com" {
		t.Errorf("Recipients[0] = %q, want \"security@example.com\"", sc.Recipients[0])
	}
}

// TestComputeNextRun_Daily は daily スケジュールの次回実行時刻計算を確認する
func TestComputeNextRun_Daily(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "daily",
		Hour:      9,
	}
	// 午前9時より前の時刻を基準にする
	after := time.Date(2026, 3, 23, 8, 0, 0, 0, time.UTC)
	next := ComputeNextRun(sc, after)

	// 同日の09:00が返されるべき
	if next.Hour() != 9 {
		t.Errorf("次回実行時刻の Hour = %d, want 9", next.Hour())
	}
	if !next.After(after) {
		t.Errorf("次回実行時刻 %v は after %v より後であるべき", next, after)
	}
	// 翌日ではなく同日のはず
	if next.Day() != after.Day() {
		t.Errorf("同日09:00前なので同日に実行されるべき: got day=%d, after day=%d", next.Day(), after.Day())
	}
}

// TestComputeNextRun_DailyAlreadyPassed は当日の実行時刻を過ぎた場合に翌日になることを確認する
func TestComputeNextRun_DailyAlreadyPassed(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "daily",
		Hour:      9,
	}
	// 午前9時を過ぎた時刻を基準にする
	after := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)
	next := ComputeNextRun(sc, after)

	// 翌日09:00が返されるべき
	if next.Day() != 24 {
		t.Errorf("10:00以降なので翌日になるべき: got day=%d, want 24", next.Day())
	}
	if next.Hour() != 9 {
		t.Errorf("実行時刻 Hour = %d, want 9", next.Hour())
	}
}

// TestComputeNextRun_Monthly は monthly スケジュールの次回実行時刻計算を確認する
func TestComputeNextRun_Monthly(t *testing.T) {
	dom := 1
	sc := &ReportSchedule{
		Frequency:  "monthly",
		Hour:       8,
		DayOfMonth: &dom,
	}
	// 月初1日を過ぎた時刻を基準にする
	after := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	next := ComputeNextRun(sc, after)

	// 翌月1日の8:00が返されるべき
	if next.Month() != 4 {
		t.Errorf("次回実行月 = %d, want 4 (April)", int(next.Month()))
	}
	if next.Day() != 1 {
		t.Errorf("次回実行日 = %d, want 1", next.Day())
	}
}

// TestComputeNextRun_Weekly は weekly スケジュールが正しい曜日を返すことを確認する
func TestComputeNextRun_Weekly(t *testing.T) {
	dow := 1 // 月曜日 (Weekday=1)
	sc := &ReportSchedule{
		Frequency: "weekly",
		Hour:      6,
		DayOfWeek: &dow,
	}
	// 月曜日以外の基準時刻を使う（2026-03-23 は月曜日なので火曜日にする）
	after := time.Date(2026, 3, 24, 6, 0, 0, 0, time.UTC) // 火曜日
	next := ComputeNextRun(sc, after)

	// 次の月曜日を返すべき
	if next.Weekday() != time.Monday {
		t.Errorf("次回実行曜日 = %v, want Monday", next.Weekday())
	}
	if !next.After(after) {
		t.Errorf("次回実行時刻は after より後であるべき")
	}
}

// TestComputeNextRun_UnknownFrequency_Reports は不明な頻度で24時間後が返されることを確認する
func TestComputeNextRun_UnknownFrequency_Reports(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "quarterly",
		Hour:      12,
	}
	after := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)
	next := ComputeNextRun(sc, after)

	expected := after.Add(24 * time.Hour)
	diff := next.Sub(expected)
	if diff < 0 {
		diff = -diff
	}
	// 誤差が1秒以内であることを確認する
	if diff > time.Second {
		t.Errorf("不明な頻度: next = %v, want %v (±1s)", next, expected)
	}
}

// ─── レポートフィルタービルダーロジックテスト ──────────────────────────────────

// buildReportListWhere は report_jobs の LIST クエリと同等の WHERE 句構築を再現するヘルパー
func buildReportListWhere(reportType, status string) (string, []interface{}) {
	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if reportType != "" {
		where += " AND rj.type = $" + itoa(idx)
		args = append(args, reportType)
		idx++
	}
	if status != "" {
		where += " AND rj.status = $" + itoa(idx)
		args = append(args, status)
		idx++
	}
	_ = idx
	return where, args
}

// TestBuildReportListWhere_EmptyFilter は全フィルターが空のとき "WHERE 1=1" であることを確認する
func TestBuildReportListWhere_EmptyFilter(t *testing.T) {
	where, args := buildReportListWhere("", "")
	if where != "WHERE 1=1" {
		t.Errorf("空フィルターは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildReportListWhere_TypeFilter は reportType フィルターが type 条件を追加することを確認する
func TestBuildReportListWhere_TypeFilter(t *testing.T) {
	where, args := buildReportListWhere("executive_summary", "")
	if !strings.Contains(where, "rj.type") {
		t.Errorf("type 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "executive_summary" {
		t.Errorf("args = %v, want [executive_summary]", args)
	}
}

// TestBuildReportListWhere_StatusFilter は status フィルターが status 条件を追加することを確認する
func TestBuildReportListWhere_StatusFilter(t *testing.T) {
	where, args := buildReportListWhere("", "completed")
	if !strings.Contains(where, "rj.status") {
		t.Errorf("status 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "completed" {
		t.Errorf("args = %v, want [completed]", args)
	}
}

// TestBuildReportListWhere_BothFilters は両フィルターが組み合わさったとき引数が2件であることを確認する
func TestBuildReportListWhere_BothFilters(t *testing.T) {
	where, args := buildReportListWhere("threat_report", "pending")
	if !strings.Contains(where, "rj.type") {
		t.Errorf("type 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "rj.status") {
		t.Errorf("status 条件が含まれるべき: %q", where)
	}
	if len(args) != 2 {
		t.Errorf("両フィルターで引数 2 件のはず: got %d", len(args))
	}
}

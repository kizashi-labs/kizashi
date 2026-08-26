package store

import (
	"testing"
	"time"
)

// ─── ComputeNextRun テスト ─────────────────────────────────────────────────────

// TestComputeNextRun_Daily_AfterHour は毎日スケジュールで、
// 今日の実行時刻を過ぎた場合に翌日の同時刻を返すことを確認する
func TestComputeNextRun_Daily_AfterHour(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "daily",
		Hour:      9, // 毎日 09:00 UTC
	}

	// 基準点: 当日 10:00 (= 実行時刻の 1 時間後)
	after := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	want := time.Date(2024, 6, 16, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(daily, after 10:00) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Daily_BeforeHour は毎日スケジュールで、
// 今日の実行時刻より前の場合は当日の同時刻を返すことを確認する
func TestComputeNextRun_Daily_BeforeHour(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "daily",
		Hour:      9,
	}

	// 基準点: 当日 08:00 (= 実行時刻の 1 時間前)
	after := time.Date(2024, 6, 15, 8, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	want := time.Date(2024, 6, 15, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(daily, before 09:00) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Daily_ExactHour は毎日スケジュールで、
// 基準点がちょうど実行時刻のとき翌日を返すことを確認する
func TestComputeNextRun_Daily_ExactHour(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "daily",
		Hour:      9,
	}

	// 基準点: ちょうど 09:00
	after := time.Date(2024, 6, 15, 9, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	// "after" と等しいため翌日になる
	want := time.Date(2024, 6, 16, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(daily, exact 09:00) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Weekly_SameDayAfterHour は週次スケジュールで、
// 指定曜日の実行時刻を過ぎた場合は翌週の同曜日を返すことを確認する
func TestComputeNextRun_Weekly_SameDayAfterHour(t *testing.T) {
	dow := 1 // Monday
	sc := &ReportSchedule{
		Frequency: "weekly",
		DayOfWeek: &dow,
		Hour:      8,
	}

	// 2024-06-17 は月曜日、10:00 (= 実行時刻の 2 時間後)
	after := time.Date(2024, 6, 17, 10, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	// 翌週月曜日 08:00
	want := time.Date(2024, 6, 24, 8, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(weekly Monday, after 10:00) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Weekly_DifferentDay は週次スケジュールで、
// 基準点が指定曜日より前の曜日の場合に同週内の正しい曜日を返すことを確認する
func TestComputeNextRun_Weekly_DifferentDay(t *testing.T) {
	dow := 5 // Friday
	sc := &ReportSchedule{
		Frequency: "weekly",
		DayOfWeek: &dow,
		Hour:      12,
	}

	// 2024-06-17 は月曜日 (Weekday=1), 同週の金曜日は 2024-06-21
	after := time.Date(2024, 6, 17, 0, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	want := time.Date(2024, 6, 21, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(weekly Friday, from Monday) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Weekly_NilDayOfWeek は DayOfWeek が nil のとき
// デフォルト日曜日（0）として動作することを確認する
func TestComputeNextRun_Weekly_NilDayOfWeek(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "weekly",
		DayOfWeek: nil, // デフォルトは 0 = Sunday
		Hour:      6,
	}

	// 2024-06-17 は月曜日 → 翌日曜日は 2024-06-23
	after := time.Date(2024, 6, 17, 7, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	if int(got.Weekday()) != 0 {
		t.Errorf("DayOfWeek nil のとき日曜日 (0) を返すべき: got weekday=%d", got.Weekday())
	}
}

// TestComputeNextRun_Monthly_DomInFuture は月次スケジュールで、
// 今月の指定日がまだ先の場合に今月の正しい日付を返すことを確認する
func TestComputeNextRun_Monthly_DomInFuture(t *testing.T) {
	dom := 20
	sc := &ReportSchedule{
		Frequency:  "monthly",
		DayOfMonth: &dom,
		Hour:       0,
	}

	// 6月10日 → 6月20日がまだ未来
	after := time.Date(2024, 6, 10, 0, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	want := time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(monthly day=20, from day=10) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Monthly_DomPassed は月次スケジュールで、
// 今月の指定日を過ぎた場合に翌月の同日を返すことを確認する
func TestComputeNextRun_Monthly_DomPassed(t *testing.T) {
	dom := 5
	sc := &ReportSchedule{
		Frequency:  "monthly",
		DayOfMonth: &dom,
		Hour:       10,
	}

	// 6月15日 → 6月5日はすでに過ぎているため 7月5日
	after := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	want := time.Date(2024, 7, 5, 10, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ComputeNextRun(monthly day=5, from day=15) = %v, want %v", got, want)
	}
}

// TestComputeNextRun_Monthly_NilDayOfMonth は DayOfMonth が nil のとき
// 1日（デフォルト）として動作することを確認する
func TestComputeNextRun_Monthly_NilDayOfMonth(t *testing.T) {
	sc := &ReportSchedule{
		Frequency:  "monthly",
		DayOfMonth: nil, // デフォルトは 1
		Hour:       0,
	}

	// 1月5日 → 次の1日は 2月1日
	after := time.Date(2024, 1, 5, 0, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	if got.Day() != 1 {
		t.Errorf("DayOfMonth nil のとき 1 日を返すべき: got day=%d", got.Day())
	}
}

// TestComputeNextRun_UnknownFrequency は未知の Frequency のとき
// 24 時間後にフォールバックすることを確認する
func TestComputeNextRun_UnknownFrequency(t *testing.T) {
	sc := &ReportSchedule{
		Frequency: "hourly", // 未知の値
		Hour:      0,
	}

	after := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	got := ComputeNextRun(sc, after)

	// デフォルトは after + 24 時間
	want := after.Add(24 * time.Hour)
	if !got.Equal(want) {
		t.Errorf("未知の frequency は after+24h を返すべき: got %v, want %v", got, want)
	}
}

// ─── ReportSchedule 構造体テスト ──────────────────────────────────────────────

// TestReportSchedule_ZeroValue は ReportSchedule のゼロ値が期待通りであることを確認する
func TestReportSchedule_ZeroValue(t *testing.T) {
	var sc ReportSchedule
	if sc.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", sc.ID)
	}
	if sc.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
	if sc.DayOfWeek != nil {
		t.Error("DayOfWeek のデフォルトは nil であるべき")
	}
	if sc.DayOfMonth != nil {
		t.Error("DayOfMonth のデフォルトは nil であるべき")
	}
	if sc.LastRunAt != nil {
		t.Error("LastRunAt のデフォルトは nil であるべき")
	}
	if sc.Recipients != nil {
		t.Error("Recipients のデフォルトは nil であるべき")
	}
}

// TestReportSchedule_FrequencyValues は有効な Frequency 値を確認する
func TestReportSchedule_FrequencyValues(t *testing.T) {
	validFrequencies := []string{"daily", "weekly", "monthly"}
	for _, freq := range validFrequencies {
		sc := ReportSchedule{Frequency: freq}
		if sc.Frequency != freq {
			t.Errorf("Frequency = %q, want %q", sc.Frequency, freq)
		}
	}
}

// TestReportSchedule_RecipientsSlice は Recipients が空スライスに初期化されることを確認する
func TestReportSchedule_RecipientsSlice(t *testing.T) {
	sc := ReportSchedule{
		Recipients: []string{"alice@example.com", "bob@example.com"},
	}
	if len(sc.Recipients) != 2 {
		t.Errorf("Recipients 長 = %d, want 2", len(sc.Recipients))
	}
	if sc.Recipients[0] != "alice@example.com" {
		t.Errorf("Recipients[0] = %q, want \"alice@example.com\"", sc.Recipients[0])
	}
}

// TestReportSchedule_HourRange は Hour フィールドが 0〜23 の範囲を受け入れることを確認する
func TestReportSchedule_HourRange(t *testing.T) {
	for h := 0; h <= 23; h++ {
		sc := ReportSchedule{Hour: h}
		if sc.Hour != h {
			t.Errorf("Hour = %d, want %d", sc.Hour, h)
		}
	}
}

// TestComputeNextRun_AlwaysAfterInput は ComputeNextRun の結果が常に入力より未来であることを確認する
func TestComputeNextRun_AlwaysAfterInput(t *testing.T) {
	dom := 15
	dow := 3
	testCases := []struct {
		name string
		sc   *ReportSchedule
	}{
		{"daily", &ReportSchedule{Frequency: "daily", Hour: 12}},
		{"weekly", &ReportSchedule{Frequency: "weekly", DayOfWeek: &dow, Hour: 8}},
		{"monthly", &ReportSchedule{Frequency: "monthly", DayOfMonth: &dom, Hour: 6}},
		{"unknown", &ReportSchedule{Frequency: "unknown"}},
	}

	after := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range testCases {
		got := ComputeNextRun(tc.sc, after)
		if !got.After(after) {
			t.Errorf("[%s] ComputeNextRun は after より未来を返すべき: got=%v, after=%v",
				tc.name, got, after)
		}
	}
}

package scheduler

import (
	"testing"
	"time"
)

// computeNextRunFromSchedule はスケジュール文字列から次回実行時刻を算出する。
// レポートの配信間隔の正しさに直結するため、各周期と未知値のフォールバックを検証する。
func TestComputeNextRunFromSchedule(t *testing.T) {
	base := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	cases := []struct {
		schedule string
		want     time.Time
	}{
		{"daily", base.Add(24 * time.Hour)},
		{"weekly", base.Add(7 * 24 * time.Hour)},
		{"monthly", base.Add(30 * 24 * time.Hour)},
		// 大文字・混在でも小文字化して判定される。
		{"WEEKLY", base.Add(7 * 24 * time.Hour)},
		{"Monthly", base.Add(30 * 24 * time.Hour)},
		// 未知の値は daily 相当 (24h) にフォールバックする。
		{"hourly", base.Add(24 * time.Hour)},
		{"", base.Add(24 * time.Hour)},
	}

	for _, tc := range cases {
		t.Run(tc.schedule, func(t *testing.T) {
			got := computeNextRunFromSchedule(tc.schedule, base)
			if !got.Equal(tc.want) {
				t.Errorf("computeNextRunFromSchedule(%q) = %v, want %v", tc.schedule, got, tc.want)
			}
		})
	}
}

// 算出結果は常に基準時刻より未来であること (負の間隔を生まない) を確認する。
func TestComputeNextRunFromSchedule_AlwaysFuture(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, s := range []string{"daily", "weekly", "monthly", "unknown"} {
		if !computeNextRunFromSchedule(s, base).After(base) {
			t.Errorf("schedule %q は基準時刻より未来を返すべき", s)
		}
	}
}

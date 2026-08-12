package scheduler

import (
	"testing"
)

// scheduler パッケージの純ロジックヘルパーのうち、機能別テストファイルで
// カバーされていないものだけをここに置く。
//
// normaliseIOCType / mispTypeToIOCType → feed_scheduler_test.go
// fmtScore / itoa                      → compliance_scorer_test.go
// joinOrNone                           → daily_briefing_scheduler_test.go
// validateSelectOnly                   → hunt_scheduler_test.go
// computeNextRunFromSchedule           → report_generator_test.go
//
// 同一パッケージ内で同名のテストを再宣言すると go vet がビルドを弾くため、
// 重複させないこと。

func TestCVEToSeverityScore(t *testing.T) {
	cases := map[string]int{
		"critical": 9,
		"CRITICAL": 9, // 大文字も正規化
		"high":     7,
		"medium":   5,
		"low":      3,
		"unknown":  3, // 既定値
		"":         3,
	}
	for in, want := range cases {
		if got := cveToSeverityScore(in); got != want {
			t.Errorf("cveToSeverityScore(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestPtrOrEmpty(t *testing.T) {
	if got := ptrOrEmpty(nil); got != "" {
		t.Errorf("ptrOrEmpty(nil) = %q, want empty", got)
	}
	s := "hello"
	if got := ptrOrEmpty(&s); got != "hello" {
		t.Errorf("ptrOrEmpty(&s) = %q, want hello", got)
	}
}

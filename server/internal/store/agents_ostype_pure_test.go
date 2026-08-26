package store

import "testing"

// normalizeOSType は agents.os_type の CHECK 制約
// ('windows','linux','darwin') を守る唯一の関所。エージェントが送る
// runtime.GOOS は未対応プラットフォームでは制約外の値になり、そのまま
// UPDATE に流すとハートビート全体が 23514 で失敗する。
func TestNormalizeOSType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"linux", "linux"},
		{"windows", "windows"},
		{"darwin", "darwin"},
		// 未申告 → 既存値を保持させるため "" のまま
		{"", ""},
		// CHECK 制約外の runtime.GOOS は握りつぶす (ハートビートを落とさない)
		{"freebsd", ""},
		{"openbsd", ""},
		{"android", ""},
		{"js", ""},
		// 表記ゆれは受け付けない (制約は小文字固定)
		{"Linux", ""},
		{"WINDOWS", ""},
		// 明らかな不正入力
		{"linux; DROP TABLE agents", ""},
	}
	for _, tt := range tests {
		if got := normalizeOSType(tt.in); got != tt.want {
			t.Errorf("normalizeOSType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

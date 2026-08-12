package scheduler

import "testing"

// joinOrNone は空スライスを「なし」に、非空をカンマ区切りに整形する。
// デイリーブリーフィング本文の各セクション表示に使われる。
func TestJoinOrNone(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "なし"},
		{[]string{}, "なし"},
		{[]string{"alert-1"}, "alert-1"},
		{[]string{"a", "b", "c"}, "a, b, c"},
	}
	for _, tc := range cases {
		if got := joinOrNone(tc.in); got != tc.want {
			t.Errorf("joinOrNone(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

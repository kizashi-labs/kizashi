package compliance

import "testing"

// 非公開ヘルパー itoa / boolStr の内部テスト（strconv 非依存の自前実装の正しさを固定）。

func TestItoa(t *testing.T) {
	cases := map[int]string{
		0:     "0",
		7:     "7",
		42:    "42",
		100:   "100",
		-5:    "-5",
		-1234: "-1234",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestBoolStr(t *testing.T) {
	if got := boolStr(true, "yes", "no"); got != "yes" {
		t.Errorf("boolStr(true) = %q, want yes", got)
	}
	if got := boolStr(false, "yes", "no"); got != "no" {
		t.Errorf("boolStr(false) = %q, want no", got)
	}
}

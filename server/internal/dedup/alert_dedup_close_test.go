package dedup

import (
	"errors"
	"testing"
)

// **群ごとに1回だけ報告すること。**
//
// 重複を閉じる UPDATE は群の中で何度も走ります。1件ずつ `tick.Fail` に
// 出すと、DB が応答しないときログが群の数だけ溢れます。かといって
// 黙ると、**画面には重複が並んだまま**で、その回は成功として刻まれます。
//
// 判定を `closeOutcome` に出してあるのは、**通る木では `failed` が 0 の
// ままだから**です —— `if closed.needsReporting()` を潰す変異は、木が
// きれいなあいだ何も変えません。
func TestClosingDuplicatesReportsOncePerGroup(t *testing.T) {
	boom := errors.New("DBが応答しません")

	for _, c := range []struct {
		name   string
		errs   []error
		report bool
		failed int
		total  int
	}{
		{"全部閉じられた", []error{nil, nil, nil}, false, 0, 3},
		{"1件だけ閉じられなかった", []error{nil, boom, nil}, true, 1, 3},
		{"全部だめ", []error{boom, boom}, true, 2, 2},
		{"閉じる相手がいない", nil, false, 0, 0},
	} {
		var o closeOutcome
		for _, e := range c.errs {
			o.add(e)
		}
		if got := o.needsReporting(); got != c.report {
			t.Errorf("%s: 報告する = %v, want %v。**黙ると画面には重複が"+
				"並んだままで、その回は成功として刻まれます**", c.name, got, c.report)
		}
		if o.failed != c.failed || o.total != c.total {
			t.Errorf("%s: failed=%d total=%d, want %d/%d",
				c.name, o.failed, o.total, c.failed, c.total)
		}
		if c.report && o.last == nil {
			t.Errorf("%s: 渡す error がありません。ログが「error=」で"+
				"終わります", c.name)
		}
		if !c.report && o.last != nil {
			t.Errorf("%s: 失敗していないのに error を持っています", c.name)
		}
	}
}

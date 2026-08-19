package metrics

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// 出すと決めたアラートが出なかった分は、背景処理の失敗と混ぜないこと。
//
// 背景処理の失敗の多くは「今回の分が遅れる」です。これは「出すと決めた
// 警報が、出ないまま終わった」で、重さが違います。同じ数に混ぜると、
// 後者が前者に埋もれます。
//
// 行き先は既にあった AlertInsertFailures です。同じ事実の counter を
// 新しく作りかけて、既存に気づきました。二つあると、片方に警報を貼った
// 人は見落としに気づけません。
func TestADroppedAlertIsCountedApartFromOtherFailures(t *testing.T) {
	const source = "test_source_dropped"
	bgBefore := metricValue(BackgroundFailures.WithLabelValues(source))

	AlertDropped(source, errors.New("INSERT が失敗しました"), "Mimikatz on WS-04")

	if got := metricValue(AlertInsertFailures.WithLabelValues(source)); got != 1 {
		t.Errorf("落としたアラート = %v, want 1", got)
	}
	if got := metricValue(BackgroundFailures.WithLabelValues(source)); got != bgBefore {
		t.Errorf("背景処理の失敗に混ざっています (%v → %v)", bgBefore, got)
	}
}

func TestDroppedAlertsAreCountedPerSource(t *testing.T) {
	AlertDropped("test_src_a", errors.New("x"), "t")
	AlertDropped("test_src_b", errors.New("y"), "t")
	AlertDropped("test_src_b", errors.New("z"), "t")

	if got := metricValue(AlertInsertFailures.WithLabelValues("test_src_a")); got != 1 {
		t.Errorf("a = %v, want 1", got)
	}
	if got := metricValue(AlertInsertFailures.WithLabelValues("test_src_b")); got != 2 {
		t.Errorf("b = %v, want 2", got)
	}
}

// 何を出そうとしたかが記録に残ること。件数だけでは、どの検知が消えたのか
// 分かりません。
// `"title"` だけを探していたときは、`title string` という引数の宣言が
// それを満たしていました。ログから title を落としても検査は通ります
// — 実際、変異させたらそれが生き残りました。**探す文字列が、確かめたい
// こととは別の場所で満たされていたわけです。**
var alertDroppedNeeds = []string{
	"slog.",               // 何を出そうとしたか
	"AlertInsertFailures", // 何回落としたか
	`"title", title`,      // どのアラートか（宣言ではなく、記録に載っていること）
}

func TestAlertDroppedRecordsWhatItWasGoingToRaise(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("metrics.go を読めません: %v", err)
	}
	at := strings.Index(string(src), "func AlertDropped(")
	if at < 0 {
		t.Fatal("AlertDropped の定義が見つかりません")
	}
	body := string(src)[at:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	if missing := missingFrom(body, alertDroppedNeeds); len(missing) > 0 {
		t.Errorf("AlertDropped が %v を持っていません", missing)
	}

	// 逆向きの確認。求めるものの一覧が骨抜きだと、上は何でも通ります。
	for _, c := range []struct {
		name, stub string
		want       []string
	}{
		{"数えるだけ", "AlertInsertFailures.WithLabelValues(s).Inc()",
			[]string{"slog.", `"title", title`}},
		{"記録するだけ", `slog.Error("x", "title", title)`, []string{"AlertInsertFailures"}},
		// 引数の宣言だけがある形。ログには載っていません。
		{"title を引数に持つだけ",
			`func AlertDropped(source string, err error, title string) {` + "\n" +
				`slog.Error("x", "source", source)` + "\n" +
				`AlertInsertFailures.WithLabelValues(source).Inc()`,
			[]string{`"title", title`}},
	} {
		got := missingFrom(c.stub, alertDroppedNeeds)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s実装の不足 = %v, want %v", c.name, got, c.want)
		}
	}
}

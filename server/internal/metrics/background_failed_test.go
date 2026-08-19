package metrics

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func metricValue(m prometheus.Metric) float64 {
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		return -1
	}
	if c := out.GetCounter(); c != nil {
		return c.GetValue()
	}
	return out.GetGauge().GetValue()
}

// BackgroundFailed が「数を消すための呼び出し」にならないための検査です。
//
// answered_with_a_value_test.go は、分岐にログ以外の呼び出しがあれば
// 「値で答えているだけではない」として数えません。BackgroundFailed は
// ログ以外の呼び出しなので、slog.Error をこれに書き換えるだけで43箇所が
// 数から消えます。それが許されるのは、本当に別の行き先を持っている
// あいだだけです。中身が slog だけに戻ったら、43箇所は黙って消えたまま
// になります。
func TestBackgroundFailedWritesSomewhereOtherThanTheLog(t *testing.T) {
	const component = "test_component_writes"
	before := metricValue(BackgroundFailures.WithLabelValues(component))
	at := time.Now().Unix()

	BackgroundFailed(component, errors.New("読めませんでした"), "テスト")

	if got := metricValue(BackgroundFailures.WithLabelValues(component)); got != before+1 {
		t.Errorf("失敗回数 = %v, want %v", got, before+1)
	}
	if ts := metricValue(BackgroundLastFailureTimestamp.WithLabelValues(component)); ts < float64(at) {
		t.Errorf("最終失敗時刻が更新されていません (%v < %v)。"+
			"件数だけでは、去年100回失敗したのと今失敗しているのが同じ形です", ts, at)
	}
}

// 経路ごとに分かれていること。全部同じラベルにまとめると、
// どこが止まっているのか分かりません。
func TestBackgroundFailuresAreCountedPerComponent(t *testing.T) {
	BackgroundFailed("test_component_a", errors.New("x"), "テスト")
	BackgroundFailed("test_component_b", errors.New("y"), "テスト")
	BackgroundFailed("test_component_b", errors.New("z"), "テスト")

	if got := metricValue(BackgroundFailures.WithLabelValues("test_component_a")); got != 1 {
		t.Errorf("a = %v, want 1", got)
	}
	if got := metricValue(BackgroundFailures.WithLabelValues("test_component_b")); got != 2 {
		t.Errorf("b = %v, want 2", got)
	}
}

// 実装がログだけに戻っていないこと。上の検査は値を見ますが、
// 「ログを消して指標だけ残す」も同じくらい困ります — 件数しか無いと、
// なぜ失敗したのかがどこにも残りません。
// BackgroundFailed が満たすべきもの。ログと指標の両方です。
// 片方だけだと、理由が残らないか、件数が残らないかのどちらかになります。
var backgroundFailedNeeds = []string{
	"slog.",                          // なぜ失敗したか
	"BackgroundFailures",             // 何回失敗したか
	"BackgroundLastFailureTimestamp", // いつ失敗したか
}

func missingFrom(body string, needs []string) []string {
	var out []string
	for _, n := range needs {
		if !strings.Contains(body, n) {
			out = append(out, n)
		}
	}
	return out
}

func TestBackgroundFailedStillLogsTheReason(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("metrics.go を読めません: %v", err)
	}
	at := strings.Index(string(src), "func BackgroundFailed(")
	if at < 0 {
		t.Fatal("BackgroundFailed の定義が見つかりません")
	}
	body := string(src)[at:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	if missing := missingFrom(body, backgroundFailedNeeds); len(missing) > 0 {
		t.Errorf("BackgroundFailed が %v を使っていません。"+
			"理由はログにしか残らず、件数は指標にしか残りません。両方要ります", missing)
	}

	// 逆向きの確認。求めるものの一覧が骨抜きになっていると、上の判定は
	// どんな実装でも通ります。件数ではなく「何が足りないか」まで見ます
	// — 一覧から1項目落とすと数は合ったままになるためです。
	for _, c := range []struct {
		name, stub string
		want       []string
	}{
		{"ログしか書かない", "slog.Error(msg)",
			[]string{"BackgroundFailures", "BackgroundLastFailureTimestamp"}},
		{"指標しか書かない",
			"BackgroundFailures.WithLabelValues(c).Inc()\nBackgroundLastFailureTimestamp.WithLabelValues(c).Set(0)",
			[]string{"slog."}},
	} {
		got := missingFrom(c.stub, backgroundFailedNeeds)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s実装の不足 = %v, want %v。"+
				"求めるものの一覧から項目が落ちています", c.name, got, c.want)
		}
	}
}

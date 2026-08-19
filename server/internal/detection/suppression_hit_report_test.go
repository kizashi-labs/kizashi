package detection

import (
	"context"
	"errors"
	"testing"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// 抑制ルールのヒット数を書けなかったときに、それが部品ごとの件数に
// 出ることを直接確かめます。
//
// **なぜ直接呼ぶのか。** この記録は「イベントが抑制された」経路の中に
// あり、通る木では失敗しません。つまり `err != nil` の枝は一度も通らず、
// **`err != nil` を `err == nil` に反転する変異が生き残ります**。
// 反転すると「書けたときに失敗を報告し、書けなかったときは黙る」に
// なりますが、書き込みが常に成功する検査からはどちらも同じに見えます。
// 呼べる形に切り出して、失敗する数え役を渡すのが唯一の殺し方です。
//
// 落ちたときに何が起きるか: ヒット数は0のまま残ります。抑制ルールの
// 棚卸しは「ヒット0のルールは要らない」で行われるので、**実際は毎日
// 抑制しているルールが消され、抑えていたアラートが戻ってきます。**

func counterValue(m prometheus.Metric) float64 {
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		return -1
	}
	return out.GetCounter().GetValue()
}

// stubHitCounter is a SuppressionHitCounter that fails, or does not, on demand.
type stubHitCounter struct {
	err    error
	calls  int
	lastID string
}

func (s *stubHitCounter) IncrHitCount(_ context.Context, ruleID string) error {
	s.calls++
	s.lastID = ruleID
	return s.err
}

func TestAFailedSuppressionHitCountIsReported(t *testing.T) {
	const component = "suppression_hit_count"

	cases := []struct {
		name      string
		counter   *stubHitCounter
		wantCalls int
		wantMoved float64
	}{
		{
			name:      "書けなかったら件数が動く",
			counter:   &stubHitCounter{err: errors.New("書き込みを拒否されました")},
			wantCalls: 1,
			wantMoved: 1,
		},
		{
			name:      "書けたら件数は動かない",
			counter:   &stubHitCounter{},
			wantCalls: 1,
			wantMoved: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := counterValue(metrics.BackgroundFailures.WithLabelValues(component))

			e := &Engine{suppressionHit: tc.counter}
			e.noteSuppressionHit(context.Background(), "rule-42")

			if tc.counter.calls != tc.wantCalls {
				t.Fatalf("IncrHitCount の呼び出し回数 = %d, want %d", tc.counter.calls, tc.wantCalls)
			}
			if tc.counter.lastID != "rule-42" {
				t.Errorf("渡されたルールID = %q, want %q。"+
					"別のルールの件数を増やすと、抑制の棚卸しが逆向きに間違えます",
					tc.counter.lastID, "rule-42")
			}
			after := counterValue(metrics.BackgroundFailures.WithLabelValues(component))
			if moved := after - before; moved != tc.wantMoved {
				t.Errorf("%s の失敗件数の増分 = %v, want %v。"+
					"報告しないと、ヒット0が「効いていない」と「書けていない」の"+
					"どちらなのか外から分かりません", component, moved, tc.wantMoved)
			}
		})
	}
}

// 数え役を持たない Engine（機能を切っている構成）で落ちないこと。
// nil チェックを消す変異はここで死にます。
func TestNoSuppressionCounterIsNotAFailure(t *testing.T) {
	const component = "suppression_hit_count"
	before := counterValue(metrics.BackgroundFailures.WithLabelValues(component))

	e := &Engine{}
	e.noteSuppressionHit(context.Background(), "rule-42")

	if after := counterValue(metrics.BackgroundFailures.WithLabelValues(component)); after != before {
		t.Errorf("数え役を持たない構成で失敗を報告しました (%v → %v)。"+
			"切ってある機能が毎イベント失敗として積まれます", before, after)
	}
}

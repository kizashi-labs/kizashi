package intel

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/edr-platform/server/internal/metrics"
)

func counterValue(m prometheus.Metric) float64 {
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		return -1
	}
	return out.GetCounter().GetValue()
}

// 読めない行を飛ばしたことが数に残ること。
//
// 壊れた行を黙って飛ばすと、フィードの書式が変わって全行落ちても
// 「今日は0件でした」と同じ形になります。取り込み側は0件を正常として
// 記録するので、何日落ちていても誰も気づきません。行を捨てるのは正しい
// 判断ですが、何行捨てたかは残します。
func TestASkippedFeedLineIsCounted(t *testing.T) {
	before := counterValue(metrics.BackgroundFailures.WithLabelValues("urlhaus_csv"))

	// 3列目まで無い行を混ぜます。1行目は正しい行。
	csv := "1,2026-01-01,http://evil.example/a,online\n" +
		"broken-line-with-one-field\n" +
		"3,2026-01-01,http://evil.example/b,online\n"

	entries, err := parseURLhausCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseURLhausCSV: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("読めた行 = %d, want 2", len(entries))
	}

	after := counterValue(metrics.BackgroundFailures.WithLabelValues("urlhaus_csv"))
	if after <= before {
		t.Errorf("飛ばした行が数に残っていません (%v → %v)。"+
			"書式が変わって全行落ちても「0件のフィード」と同じ形になります", before, after)
	}
}

// 全行読めたときは何も報告しないこと。上の検査だけだと、
// 常に報告する実装でも通ります。
func TestACleanFeedReportsNothing(t *testing.T) {
	before := counterValue(metrics.BackgroundFailures.WithLabelValues("urlhaus_csv"))

	csv := "1,2026-01-01,http://evil.example/c,online\n"
	if _, err := parseURLhausCSV(strings.NewReader(csv)); err != nil {
		t.Fatalf("parseURLhausCSV: %v", err)
	}

	if after := counterValue(metrics.BackgroundFailures.WithLabelValues("urlhaus_csv")); after != before {
		t.Errorf("読めた行しか無いのに報告されています (%v → %v)", before, after)
	}
}

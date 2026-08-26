package detection

import "testing"

// normalizeZScore は alerts.anomaly_score の「0–1」契約を守る唯一の砦なので、
// 境界と発散ケースを固定する。生の z を入れていた時期に UI が 60786% を
// 描画した回帰の再発防止。
func TestNormalizeZScore(t *testing.T) {
	tests := []struct {
		name string
		z    float64
		want float64
	}{
		{"閾値以下は0", 3.0, 0},
		{"閾値未満は0", 1.5, 0},
		{"負値は0", -5, 0},
		{"閾値のすぐ上", 3.7, 0.1},
		{"中間", 6.5, 0.5},
		{"上限ちょうどは1", 10.0, 1},
		{"上限超えは1で頭打ち", 607.86, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeZScore(tt.z)
			if diff := got - tt.want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("normalizeZScore(%v) = %v, want %v", tt.z, got, tt.want)
			}
		})
	}
}

// 契約そのもの: どんな入力でも 0–1 に収まること。
func TestNormalizeZScoreAlwaysInRange(t *testing.T) {
	for _, z := range []float64{-1e9, -1, 0, 2.99, 3, 3.01, 5, 9.99, 10, 10.01, 1e9} {
		got := normalizeZScore(z)
		if got < 0 || got > 1 {
			t.Errorf("normalizeZScore(%v) = %v — 0–1 の範囲外", z, got)
		}
	}
}

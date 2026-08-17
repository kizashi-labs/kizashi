package scheduler

import (
	"testing"
	"time"
)

// 期限の丸めは設定ミスの被害を抑えるためにある。短すぎる期限は、単に遅い
// だけのコマンドを timeout として畳んでしまい、あとから成功が返ってきても
// 行は timeout のまま残る。誤った記録を作るくらいなら、遅れて畳むほうがよい。
func TestNewResponseActionTimeoutWorkerClampsTimeout(t *testing.T) {
	cases := []struct {
		name  string
		given time.Duration
		want  time.Duration
	}{
		{"未設定は既定値", 0, defaultResponseActionTimeout},
		{"負値は既定値", -5 * time.Minute, defaultResponseActionTimeout},
		{"下限未満は下限へ丸める", 10 * time.Second, minResponseActionTimeout},
		{"下限ちょうどはそのまま", minResponseActionTimeout, minResponseActionTimeout},
		{"下限超はそのまま", 30 * time.Minute, 30 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := NewResponseActionTimeoutWorker(nil, c.given)
			if w.timeout != c.want {
				t.Errorf("timeout = %v, want %v", w.timeout, c.want)
			}
		})
	}
}

// 掃引間隔が期限より長いと、期限切れの検出が最大で 1 間隔ぶん遅れる。
// 既定値の関係が崩れていないことを固定する。
func TestSweepIntervalIsShorterThanMinimumTimeout(t *testing.T) {
	if timeoutSweepInterval >= minResponseActionTimeout {
		t.Errorf("掃引間隔 %v が期限の下限 %v 以上です。"+
			"期限切れの検出が 1 間隔ぶん遅れます",
			timeoutSweepInterval, minResponseActionTimeout)
	}
}

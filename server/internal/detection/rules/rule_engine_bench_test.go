package rules

import (
	"context"
	"fmt"
	"testing"
)

// 検知エンジンのスループットは FP ソークの実測で約 130 events/sec が上限と分かっている
// (docs/ops/FPソーク運用.md)。同じスタックの ingestion は 1,010 events/sec で欠落ゼロ
// なので、8分の1 に落ちる原因は detection 側にある。しかし detection パッケージには
// ベンチマークが1本も無く、「ML異常検知 / ルール評価 / 相関 / ランタイム検知器9種」の
// どれが効いているのかを測る手段が存在しなかった。
//
// この 130 events/sec が、
//   - FP ソークを 1.67 シミュレートホスト日/回に縛り(speed を上げると消化待ちが伸びるだけ)
//   - 「大規模本番での低FP実証」を測れないままにしている
// ので、まず内訳を測れるようにする。憶測で最適化しないための土台。
//
// Evaluate は e.rules を線形に総当たりする(インデックスもプレフィルタも無い)ため、
// ルール数に比例するはずである — が、実測せずに決めつけない。本番の検証環境は
// edr_rules_loaded = 2341 件をロードしている。

// benchRule は「マッチしない現実的な Sigma ルール」を1件作る。SigmaHQ の典型的な形
// (Image|endswith + CommandLine|contains の AND)を模す。i でルール内容を散らして
// おかないと、sigma-go 側のキャッシュが効いて実態より速く出る可能性がある。
func benchRule(i int) *DetectionRule {
	content := fmt.Sprintf(`
title: bench rule %d
logsource:
  category: process_creation
detection:
  sel:
    Image|endswith: '\bench_nonexistent_%d.exe'
    CommandLine|contains: 'bench-token-%d'
  condition: sel
`, i, i, i)
	return &DetectionRule{
		ID: fmt.Sprintf("bench-%d", i), Name: fmt.Sprintf("bench %d", i),
		Type: "sigma", Enabled: true, Severity: 50, Content: content,
	}
}

// benchEvent は評価対象のイベント。実機の分布では process より image_load の方が
// 桁で多いが(2026-07-26 実測: image_load 2149 / file 844 / process 69)、Sigma ルールの
// 大半は process_creation を対象にしているのでまずこちらで測る。
func benchEvent() map[string]interface{} {
	return map[string]interface{}{
		"type": "process", "agent_id": "bench-host", "platform": "windows",
		"Image":            `C:\Windows\System32\svchost.exe`,
		"CommandLine":      `svchost.exe -k netsvcs -p`,
		"ParentImage":      `C:\Windows\System32\services.exe`,
		"User":             `NT AUTHORITY\SYSTEM`,
		"ProcessId":        float64(4242),
		"ParentProcessId":  float64(700),
		"OriginalFileName": "svchost.exe",
	}
}

// BenchmarkRuleEngineEvaluate はルール数に対するスケーリングを測る。
// 線形なら「1イベントあたりのルール評価コスト × ルール数」が律速で、
// 打ち手はインデックス化(logsource/category や Image 拡張子での事前絞り込み)になる。
func BenchmarkRuleEngineEvaluate(b *testing.B) {
	for _, n := range []int{1, 100, 500, 1000, 2500} {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			e := NewRuleEngine()
			rules := make([]*DetectionRule, 0, n)
			for i := 0; i < n; i++ {
				rules = append(rules, benchRule(i))
			}
			e.LoadRules(rules)

			ctx := context.Background()
			evt := benchEvent()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Evaluate(ctx, evt); err != nil {
					b.Fatalf("Evaluate: %v", err)
				}
			}
		})
	}
}

// BenchmarkRuleEngineEvaluate_PlatformGate は、プラットフォームゲート(#654 で
// 実効化された)が評価をどれだけ削るかを測る。windows ルールに linux イベントを
// 当てると全件が gate で落ちるので、「ゲートが効いたときの下限コスト」が出る。
// ゲート前後の差が大きいほど、logsource ベースの事前絞り込みにも効果が見込める。
func BenchmarkRuleEngineEvaluate_PlatformGate(b *testing.B) {
	const n = 2500
	for _, tc := range []struct {
		name     string
		gate     bool
		platform string
	}{
		{"gate_off", false, "windows"},
		{"gate_on_all_match", true, "windows"},
		{"gate_on_all_skip", true, "linux"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			e := NewRuleEngine()
			rules := make([]*DetectionRule, 0, n)
			for i := 0; i < n; i++ {
				r := benchRule(i)
				r.Platform = []string{"windows"}
				rules = append(rules, r)
			}
			e.LoadRules(rules)
			e.SetPlatformGate(tc.gate)

			ctx := context.Background()
			evt := benchEvent()
			evt["platform"] = tc.platform

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Evaluate(ctx, evt); err != nil {
					b.Fatalf("Evaluate: %v", err)
				}
			}
		})
	}
}

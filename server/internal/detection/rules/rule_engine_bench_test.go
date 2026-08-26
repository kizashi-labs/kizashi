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

// BenchmarkRuleEngineEvaluate_LogsourceIndex は logsource インデックス
// (logsource_index.go)の効果を、**検証環境の実分布に近いルール構成**で測る。
//
// 実測(2026-08-05, enabled=true の 2,341 ルール):
//
//	process_creation 1,624 / registry_set 207 / ps_script 162 / image_load 103 /
//	network_connection 54 / (category 抽出不可) 47 / registry_event 33 /
//	ps_module 33 / file_event 22 / dns_query 22 / registry_delete 10 /
//	create_remote_thread 9
//
// この構成で image_load / file / dns のイベントを流すと、種別の合わない
// 数千ルールが評価対象から外れる。逆に process イベントは
// (コマンドライン系 + create_remote_thread を含むため)ほとんど絞れない。
// 全体の効果はイベント分布との掛け算で決まるので、両方を測って差を見る。
func BenchmarkRuleEngineEvaluate_LogsourceIndex(b *testing.B) {
	dist := []struct {
		category string
		n        int
	}{
		{"process_creation", 1624}, {"registry_set", 207}, {"ps_script", 162},
		{"image_load", 103}, {"network_connection", 54}, {"registry_event", 33},
		{"ps_module", 33}, {"file_event", 22}, {"dns_query", 22},
		{"registry_delete", 10}, {"create_remote_thread", 9}, {"", 47},
	}
	rules := make([]*DetectionRule, 0, 2326)
	i := 0
	for _, d := range dist {
		for k := 0; k < d.n; k++ {
			r := benchRule(i)
			if d.category != "" {
				r.Content = fmt.Sprintf(`
title: bench %d
logsource:
  category: %s
detection:
  sel:
    Image|endswith: '\bench_nonexistent_%d.exe'
  condition: sel
`, i, d.category, i)
			} else {
				r.Content = fmt.Sprintf(`
title: bench %d
detection:
  sel:
    Image|endswith: '\bench_nonexistent_%d.exe'
  condition: sel
`, i, i)
			}
			rules = append(rules, r)
			i++
		}
	}

	events := map[string]map[string]interface{}{
		"image_load": {"type": "image_load", "agent_id": "h", "platform": "windows",
			"ImageLoaded": `C:\Windows\System32\ntdll.dll`, "Image": `C:\Windows\System32\svchost.exe`},
		"file": {"type": "file", "agent_id": "h", "platform": "windows",
			"TargetFilename": `C:\Users\u\Documents\report.docx`},
		"dns": {"type": "dns", "agent_id": "h", "platform": "windows", "QueryName": "www.example.com"},
		"process": {"type": "process", "agent_id": "h", "platform": "windows",
			"Image": `C:\Windows\System32\svchost.exe`, "CommandLine": `svchost.exe -k netsvcs`},
	}

	for _, on := range []bool{false, true} {
		label := "index_off"
		if on {
			label = "index_on"
		}
		for et, evt := range events {
			b.Run(label+"/"+et, func(b *testing.B) {
				e := NewRuleEngine()
				e.LoadRules(rules)
				e.SetLogsourceIndex(on)
				ctx := context.Background()
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

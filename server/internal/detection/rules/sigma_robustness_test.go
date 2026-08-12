package rules

import (
	"context"
	"strings"
	"testing"
)

// 実機検証(2026-08-01)で検知サーバのログに出ていた実際の失敗:
//
//	WARN Sigmaルールのコンパイルに失敗しました(未評価)
//	  rule="Ransomware File Extension Modification"
//	  error="line 11: cannot unmarshal !!map into time.Duration"
//
// 原因は sigma-go v0.6.6 の Detection.UnmarshalYAML が timeframe の「値」ではなく
// detection マッピング全体を time.Duration にデコードしていること。timeframe を
// 持つルールは丸ごと未評価になり、ランサムウェア拡張子ルールが死んでいた。
func TestCompile_TimeframeRuleNoLongerSkipped(t *testing.T) {
	content := `title: TF Rule
id: tf-1
logsource:
  category: file_rename
detection:
  selection:
    TargetFilename|endswith: '.locked'
  condition: selection
  timeframe: 5m
level: high`
	r := &DetectionRule{ID: "tf-1", Name: "TF Rule", Type: "sigma", Content: content}
	cs, err := compileSigmaRule(r, NewRuleEngine().config)
	if err != nil {
		t.Fatalf("timeframe を持つルールがコンパイルできない: %v", err)
	}
	res, err := cs.evaluator.Matches(context.Background(),
		map[string]interface{}{"path": "victim.locked"})
	if err != nil {
		t.Fatalf("評価エラー: %v", err)
	}
	if !res.Match {
		t.Fatal("timeframe 除去後もセレクションは一致すべき")
	}
}

// 集約条件は sigma-go の評価器が未実装で、一致イベント到達時に nil 参照で panic する。
// コンパイル時に明示的に拒否し、検知サーバが落ちないようにする。
func TestCompile_AggregationRuleRejectedNotPanicking(t *testing.T) {
	content := `title: Agg Rule
id: agg-1
logsource:
  category: file_rename
detection:
  selection:
    TargetFilename|endswith: '.locked'
  condition: selection | count() > 10
level: critical`
	r := &DetectionRule{ID: "agg-1", Name: "Agg Rule", Type: "sigma", Content: content}
	if _, err := compileSigmaRule(r, NewRuleEngine().config); err == nil {
		t.Fatal("集約条件ルールはコンパイル時に拒否すべき(評価時にpanicするため)")
	} else if !strings.Contains(err.Error(), "集約条件") {
		t.Fatalf("拒否理由が分かる文面になっていない: %v", err)
	}
}

// 万一 panic するルールが評価まで到達しても、サーバ全体を落とさない。
func TestEvaluateSigma_RecoversFromPanic(t *testing.T) {
	e := NewRuleEngine()
	// 評価器を nil にした壊れたエントリを直接差し込む(panic を強制)
	e.sigma["boom"] = &compiledSigmaRule{rule: &DetectionRule{ID: "boom"}, evaluator: nil}
	matched, err := e.evaluateSigma(context.Background(), "boom", map[string]interface{}{"a": "b"})
	if matched {
		t.Fatal("panic したルールを一致として扱ってはならない")
	}
	if err == nil {
		t.Fatal("panic はエラーとして報告されるべき")
	}
}

// トップレベルの timeframe は誤って削らない(detection 内のものだけ落とす)。
func TestStripDetectionTimeframe_LeavesTopLevelKeys(t *testing.T) {
	in := "timeframe: top\ndetection:\n  timeframe: 5m\n  condition: selection\n"
	out := stripDetectionTimeframe(in)
	if !strings.Contains(out, "timeframe: top") {
		t.Fatal("トップレベルの timeframe を削ってはならない")
	}
	if strings.Contains(out, "  timeframe: 5m") {
		t.Fatal("detection 内の timeframe が削られていない")
	}
}

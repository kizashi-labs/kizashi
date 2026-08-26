package remediation

import (
	"context"
	"testing"
	"time"
)

func TestCooldownKey_DistinctPerAgent(t *testing.T) {
	if cooldownKey("r1", "a1") == cooldownKey("r1", "a2") {
		t.Error("同一ルール・別エージェントのcooldownキーは異なるべき")
	}
	if cooldownKey("r1", "a1") == cooldownKey("r2", "a1") {
		t.Error("別ルール・同一エージェントのcooldownキーは異なるべき")
	}
	k1 := cooldownKey("r1", "a1")
	k2 := cooldownKey("r1", "a1")
	if k1 != k2 {
		t.Error("同一(ルール,エージェント)のcooldownキーは一致すべき")
	}
}

// TestTriggerOnAlert_CooldownIsPerAgent は cooldown が rule-global ではなく
// (rule, agent) 単位であることを検証する回帰テスト。rule-global だと、あるホストを
// 隔離した後 cooldown 窓の間、他のホストの隔離まで抑制され、拡散する攻撃で最初の
// 1台しか対応できないバグになる。
func TestTriggerOnAlert_CooldownIsPerAgent(t *testing.T) {
	e := NewEngine(nil, nil) // pool/nats は nil: Actions 空ルールは副作用なく log を返す
	e.AddRule(&RemediationRule{
		ID:       "r-iso",
		Name:     "Isolate on Critical",
		Enabled:  true,
		Trigger:  RuleTrigger{MinSeverity: 8},
		Cooldown: time.Hour,
		Actions:  nil, // no-op: dispatch されず status=success の log のみ
	})
	ctx := context.Background()

	// ホストA: 初回は発火する。
	if logs := e.TriggerOnAlert(ctx, "alert1", "agent-A", "hostA", 9, nil); len(logs) != 1 {
		t.Fatalf("agent-A 初回は発火すべき、got %d logs", len(logs))
	}
	// ホストA: cooldown 窓内の再発は抑制される。
	if logs := e.TriggerOnAlert(ctx, "alert2", "agent-A", "hostA", 9, nil); len(logs) != 0 {
		t.Errorf("agent-A の cooldown 中は抑制すべき、got %d logs", len(logs))
	}
	// ホストB: A の cooldown 窓内でも別ホストなので発火しなければならない
	// (rule-global cooldown バグの回帰検知)。
	if logs := e.TriggerOnAlert(ctx, "alert3", "agent-B", "hostB", 9, nil); len(logs) != 1 {
		t.Errorf("agent-B は別ホストなので発火すべき(rule-global cooldown回帰)、got %d logs", len(logs))
	}
	// ホストB: 自身の cooldown 窓内の再発は抑制される。
	if logs := e.TriggerOnAlert(ctx, "alert4", "agent-B", "hostB", 9, nil); len(logs) != 0 {
		t.Errorf("agent-B の cooldown 中は抑制すべき、got %d logs", len(logs))
	}
}

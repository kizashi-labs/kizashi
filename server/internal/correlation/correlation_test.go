package correlation

import (
	"context"
	"testing"
	"time"
)

// ─── evalCondition ────────────────────────────────────────────────────────────

func makeEvent(agentID, eventType string, severity int, data map[string]interface{}) alertEvent {
	return alertEvent{
		AlertID:   "alert-" + agentID,
		AgentID:   agentID,
		EventType: eventType,
		Severity:  severity,
		Data:      data,
		At:        time.Now(),
	}
}

func TestEvalCondition_Eq_AgentID(t *testing.T) {
	ev := makeEvent("agent-abc", "process", 5, nil)
	c := Condition{Field: "agent_id", Operator: "eq", Value: "agent-abc"}
	if !evalCondition(c, ev) {
		t.Error("agent_id の eq 条件が一致するはずです")
	}
}

func TestEvalCondition_Eq_AgentID_CaseInsensitive(t *testing.T) {
	ev := makeEvent("Agent-ABC", "process", 5, nil)
	c := Condition{Field: "agent_id", Operator: "eq", Value: "agent-abc"}
	if !evalCondition(c, ev) {
		t.Error("agent_id の eq 条件は大文字小文字を区別しないはずです")
	}
}

func TestEvalCondition_Eq_EventType(t *testing.T) {
	ev := makeEvent("a1", "network", 3, nil)
	c := Condition{Field: "event_type", Operator: "eq", Value: "network"}
	if !evalCondition(c, ev) {
		t.Error("event_type の eq 条件が一致するはずです")
	}
}

func TestEvalCondition_Gte_Severity(t *testing.T) {
	ev := makeEvent("a1", "process", 8, nil)
	c := Condition{Field: "severity", Operator: "gte", Value: "7"}
	if !evalCondition(c, ev) {
		t.Error("severity 8 >= 7 は true のはずです")
	}
}

func TestEvalCondition_Gte_Severity_NotMet(t *testing.T) {
	ev := makeEvent("a1", "process", 3, nil)
	c := Condition{Field: "severity", Operator: "gte", Value: "7"}
	if evalCondition(c, ev) {
		t.Error("severity 3 >= 7 は false のはずです")
	}
}

func TestEvalCondition_Contains_DataField(t *testing.T) {
	ev := makeEvent("a1", "process", 5, map[string]interface{}{
		"process_name": "mimikatz.exe",
	})
	c := Condition{Field: "process_name", Operator: "contains", Value: "mimikatz"}
	if !evalCondition(c, ev) {
		t.Error("dataフィールドの contains 条件が一致するはずです")
	}
}

func TestEvalCondition_UnknownField_ReturnsFalse(t *testing.T) {
	ev := makeEvent("a1", "process", 5, nil)
	c := Condition{Field: "no_such_field", Operator: "eq", Value: "value"}
	if evalCondition(c, ev) {
		t.Error("未知のフィールドは false を返すべきです")
	}
}

// ─── eventMatchesRule ─────────────────────────────────────────────────────────

func makeRule(id string, eventTypes []string, conditions []Condition) *CorrelationRule {
	return &CorrelationRule{
		ID:         id,
		Name:       "Rule " + id,
		EventTypes: eventTypes,
		Conditions: conditions,
		TimeWindow: 5 * time.Minute,
		MinEvents:  2,
		Severity:   8,
	}
}

func TestEventMatchesRule_EventTypeMatch(t *testing.T) {
	ev := makeEvent("a1", "network", 5, nil)
	rule := makeRule("r1", []string{"network"}, nil)
	if !engineForTest().eventMatchesRule(ev, rule) {
		t.Error("イベントタイプが一致する場合 true のはずです")
	}
}

func TestEventMatchesRule_EventTypeMismatch(t *testing.T) {
	ev := makeEvent("a1", "process", 5, nil)
	rule := makeRule("r1", []string{"network"}, nil)
	if engineForTest().eventMatchesRule(ev, rule) {
		t.Error("イベントタイプが一致しない場合 false のはずです")
	}
}

func TestEventMatchesRule_NoEventTypeFilter_MatchesAll(t *testing.T) {
	ev := makeEvent("a1", "dns", 5, nil)
	rule := makeRule("r1", nil, nil) // EventTypesが空 = 全タイプにマッチ
	if !engineForTest().eventMatchesRule(ev, rule) {
		t.Error("EventTypesが空の場合、全タイプにマッチするはずです")
	}
}

func TestEventMatchesRule_WithCondition(t *testing.T) {
	ev := makeEvent("agent-99", "process", 9, nil)
	rule := makeRule("r1", []string{"process"}, []Condition{
		{Field: "severity", Operator: "gte", Value: "8"},
	})
	if !engineForTest().eventMatchesRule(ev, rule) {
		t.Error("イベントタイプと条件が一致する場合 true のはずです")
	}
}

func TestEventMatchesRule_ConditionNotMet(t *testing.T) {
	ev := makeEvent("agent-99", "process", 3, nil)
	rule := makeRule("r1", []string{"process"}, []Condition{
		{Field: "severity", Operator: "gte", Value: "8"},
	})
	if engineForTest().eventMatchesRule(ev, rule) {
		t.Error("条件が満たされない場合 false のはずです")
	}
}

// ─── Engine.ProcessAlert / GetStats ──────────────────────────────────────────

func engineForTest() *Engine {
	return NewEngine(nil)
}

func TestEngine_GetStats_Empty(t *testing.T) {
	e := engineForTest()
	stats := e.GetStats()
	if stats.TotalIncidents != 0 {
		t.Errorf("初期状態でインシデント数は0のはずです: got %d", stats.TotalIncidents)
	}
	if stats.RulesCount != 0 {
		t.Errorf("初期状態でルール数は0のはずです: got %d", stats.RulesCount)
	}
}

func TestEngine_AddRule_IncreasesCount(t *testing.T) {
	e := engineForTest()
	e.AddRule(makeRule("r1", nil, nil))
	e.AddRule(makeRule("r2", nil, nil))
	stats := e.GetStats()
	if stats.RulesCount != 2 {
		t.Errorf("AddRule×2後、RulesCountは2のはずです: got %d", stats.RulesCount)
	}
}

func TestEngine_AddRule_UpdatesExisting(t *testing.T) {
	e := engineForTest()
	r1 := makeRule("dup", nil, nil)
	r1.Name = "Original"
	e.AddRule(r1)

	r2 := makeRule("dup", nil, nil)
	r2.Name = "Updated"
	e.AddRule(r2)

	// ルール数は1のままのはず
	stats := e.GetStats()
	if stats.RulesCount != 1 {
		t.Errorf("同IDのルールは更新されるべきです（追加ではなく）: RulesCount=%d", stats.RulesCount)
	}
}

func TestEngine_ProcessAlert_CreatesIncident(t *testing.T) {
	e := engineForTest()
	rule := makeRule("incident-rule", []string{"process"}, nil)
	rule.MinEvents = 2
	rule.TimeWindow = time.Minute
	e.AddRule(rule)

	ctx := context.Background()
	// MinEvents=2 に達したらインシデントが作成される
	e.ProcessAlert(ctx, "alert-1", "agent-1", "process", "", 9, nil)
	e.ProcessAlert(ctx, "alert-2", "agent-1", "process", "", 9, nil)

	stats := e.GetStats()
	if stats.TotalIncidents == 0 {
		t.Error("MinEvents到達後はインシデントが作成されるべきです")
	}
}

func TestEngine_ListRules(t *testing.T) {
	e := engineForTest()
	e.AddRule(makeRule("x1", nil, nil))
	e.AddRule(makeRule("x2", nil, nil))

	rules := e.ListRules()
	if len(rules) != 2 {
		t.Errorf("ListRules: got %d, want 2", len(rules))
	}
}

func TestEngine_GetIncidentByID_NotFound(t *testing.T) {
	e := engineForTest()
	_, found := e.GetIncidentByID("nonexistent")
	if found {
		t.Error("存在しないIDは found=false を返すべきです")
	}
}

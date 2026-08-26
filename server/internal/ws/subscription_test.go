package ws

import (
	"testing"
)

// ─── ParseSubscribeMessage ────────────────────────────────────────────────────

func TestParseSubscribeMessage_ValidJSON_ReturnsFilter(t *testing.T) {
	data := []byte(`{"action":"subscribe","filter":{"types":["alert"],"severities":["critical"]}}`)
	filter, ok := ParseSubscribeMessage(data)
	if !ok {
		t.Fatal("ParseSubscribeMessage: ok should be true")
	}
	if filter == nil {
		t.Fatal("ParseSubscribeMessage: filter should not be nil")
	}
	if len(filter.Types) != 1 || filter.Types[0] != "alert" {
		t.Errorf("Types: got %v, want [alert]", filter.Types)
	}
}

func TestParseSubscribeMessage_WrongAction_ReturnsFalse(t *testing.T) {
	data := []byte(`{"action":"unsubscribe","filter":{}}`)
	_, ok := ParseSubscribeMessage(data)
	if ok {
		t.Error("action=unsubscribe: false を返すべきです")
	}
}

func TestParseSubscribeMessage_InvalidJSON_ReturnsFalse(t *testing.T) {
	_, ok := ParseSubscribeMessage([]byte(`{invalid`))
	if ok {
		t.Error("不正 JSON: false を返すべきです")
	}
}

func TestParseSubscribeMessage_EmptyFilter_ReturnsEmptyFilter(t *testing.T) {
	data := []byte(`{"action":"subscribe","filter":{}}`)
	filter, ok := ParseSubscribeMessage(data)
	if !ok {
		t.Fatal("空 filter: ok should be true")
	}
	if len(filter.Types) != 0 {
		t.Errorf("空 Types: got %d, want 0", len(filter.Types))
	}
}

func TestParseSubscribeMessage_MultipleTypes(t *testing.T) {
	data := []byte(`{"action":"subscribe","filter":{"types":["alert","agent","incident"]}}`)
	filter, ok := ParseSubscribeMessage(data)
	if !ok {
		t.Fatal("複数 types: ok should be true")
	}
	if len(filter.Types) != 3 {
		t.Errorf("Types 数: got %d, want 3", len(filter.Types))
	}
}

// ─── MatchesFilter ────────────────────────────────────────────────────────────

func TestMatchesFilter_NilFilter_ReturnsTrue(t *testing.T) {
	if !MatchesFilter(nil, "alert", "agent-001", "critical") {
		t.Error("nil フィルター: true を返すべきです")
	}
}

func TestMatchesFilter_EmptyFilter_ReturnsTrue(t *testing.T) {
	filter := &SubscriptionFilter{}
	if !MatchesFilter(filter, "alert", "agent-001", "high") {
		t.Error("空フィルター: true を返すべきです")
	}
}

func TestMatchesFilter_TypeMatch_ReturnsTrue(t *testing.T) {
	filter := &SubscriptionFilter{Types: []string{"alert"}}
	if !MatchesFilter(filter, "alert", "", "") {
		t.Error("type 一致: true を返すべきです")
	}
}

func TestMatchesFilter_TypeMismatch_ReturnsFalse(t *testing.T) {
	filter := &SubscriptionFilter{Types: []string{"alert"}}
	if MatchesFilter(filter, "agent", "", "") {
		t.Error("type 不一致: false を返すべきです")
	}
}

func TestMatchesFilter_WildcardType_ReturnsTrue(t *testing.T) {
	filter := &SubscriptionFilter{Types: []string{"*"}}
	if !MatchesFilter(filter, "any_type", "", "") {
		t.Error("ワイルドカード type: true を返すべきです")
	}
}

func TestMatchesFilter_AgentIDMatch_ReturnsTrue(t *testing.T) {
	filter := &SubscriptionFilter{AgentIDs: []string{"agent-001", "agent-002"}}
	if !MatchesFilter(filter, "", "agent-001", "") {
		t.Error("agentID 一致: true を返すべきです")
	}
}

func TestMatchesFilter_AgentIDMismatch_ReturnsFalse(t *testing.T) {
	filter := &SubscriptionFilter{AgentIDs: []string{"agent-001"}}
	if MatchesFilter(filter, "", "agent-999", "") {
		t.Error("agentID 不一致: false を返すべきです")
	}
}

func TestMatchesFilter_AgentIDEmpty_SkipsCheck(t *testing.T) {
	filter := &SubscriptionFilter{AgentIDs: []string{"agent-001"}}
	// agentID が空の場合はチェックをスキップして true
	if !MatchesFilter(filter, "", "", "") {
		t.Error("agentID 空: チェックスキップで true を返すべきです")
	}
}

func TestMatchesFilter_SeverityCaseInsensitive(t *testing.T) {
	filter := &SubscriptionFilter{Severities: []string{"CRITICAL"}}
	if !MatchesFilter(filter, "", "", "critical") {
		t.Error("severity 大文字小文字無視: true を返すべきです")
	}
}

func TestMatchesFilter_SeverityMismatch_ReturnsFalse(t *testing.T) {
	filter := &SubscriptionFilter{Severities: []string{"critical"}}
	if MatchesFilter(filter, "", "", "low") {
		t.Error("severity 不一致: false を返すべきです")
	}
}

func TestMatchesFilter_CombinedFilters_AllMatch(t *testing.T) {
	filter := &SubscriptionFilter{
		Types:      []string{"alert"},
		AgentIDs:   []string{"agent-001"},
		Severities: []string{"high", "critical"},
	}
	if !MatchesFilter(filter, "alert", "agent-001", "critical") {
		t.Error("全条件一致: true を返すべきです")
	}
}

func TestMatchesFilter_CombinedFilters_OneMismatch(t *testing.T) {
	filter := &SubscriptionFilter{
		Types:      []string{"alert"},
		AgentIDs:   []string{"agent-001"},
		Severities: []string{"high"},
	}
	// severity が一致しない
	if MatchesFilter(filter, "alert", "agent-001", "low") {
		t.Error("severity 不一致: false を返すべきです")
	}
}

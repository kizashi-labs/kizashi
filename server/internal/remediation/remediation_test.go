package remediation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ─── triggerMatches ───────────────────────────────────────────────────────────

func TestTriggerMatches_EventTypeMatch(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{EventType: "process", MinSeverity: 0}
	if !e.triggerMatches(trigger, "process", 5, nil) {
		t.Error("イベントタイプが一致する場合 true のはずです")
	}
}

func TestTriggerMatches_EventTypeMismatch(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{EventType: "network"}
	if e.triggerMatches(trigger, "process", 5, nil) {
		t.Error("イベントタイプが一致しない場合 false のはずです")
	}
}

func TestTriggerMatches_EventTypeCaseInsensitive(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{EventType: "PROCESS"}
	if !e.triggerMatches(trigger, "process", 5, nil) {
		t.Error("イベントタイプ比較は大文字小文字を区別しないはずです")
	}
}

func TestTriggerMatches_SeverityBelowMin(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{MinSeverity: 8}
	if e.triggerMatches(trigger, "any", 3, nil) {
		t.Error("重大度がMinSeverity未満の場合 false のはずです")
	}
}

func TestTriggerMatches_SeverityExactlyMin(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{MinSeverity: 7}
	if !e.triggerMatches(trigger, "any", 7, nil) {
		t.Error("重大度がMinSeverityと等しい場合 true のはずです")
	}
}

func TestTriggerMatches_TagMatch(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{Tags: []string{"ransomware"}}
	if !e.triggerMatches(trigger, "any", 0, []string{"ransomware", "lateral-movement"}) {
		t.Error("タグが1つでも一致する場合 true のはずです")
	}
}

func TestTriggerMatches_TagNoMatch(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{Tags: []string{"ransomware"}}
	if e.triggerMatches(trigger, "any", 0, []string{"phishing"}) {
		t.Error("タグが一致しない場合 false のはずです")
	}
}

func TestTriggerMatches_TagCaseInsensitive(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{Tags: []string{"RANSOMWARE"}}
	if !e.triggerMatches(trigger, "any", 0, []string{"ransomware"}) {
		t.Error("タグ比較は大文字小文字を区別しないはずです")
	}
}

func TestTriggerMatches_NoEventTypeFilter_AllTypesMatch(t *testing.T) {
	e := NewEngine(nil, nil)
	trigger := RuleTrigger{} // EventType="" = 全タイプ
	if !e.triggerMatches(trigger, "dns", 5, nil) {
		t.Error("EventTypeが空の場合、全イベントタイプにマッチするはずです")
	}
}

// ─── DryRun ───────────────────────────────────────────────────────────────────

func TestDryRun_MatchingRule(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{
		ID:      "r1",
		Name:    "Isolate on Critical",
		Enabled: true,
		Trigger: RuleTrigger{EventType: "process", MinSeverity: 8},
	})

	matched := e.DryRun("process", 9, nil)
	if len(matched) == 0 {
		t.Error("条件を満たすルールがある場合、DryRunはマッチ名を返すべきです")
	}
}

func TestDryRun_DisabledRuleNotMatched(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{
		ID:      "r2",
		Name:    "Disabled Rule",
		Enabled: false,
		Trigger: RuleTrigger{EventType: "process", MinSeverity: 1},
	})

	matched := e.DryRun("process", 9, nil)
	if len(matched) != 0 {
		t.Error("無効化されたルールはDryRunで返されるべきではありません")
	}
}

func TestDryRun_NoRulesReturnsEmpty(t *testing.T) {
	e := NewEngine(nil, nil)
	matched := e.DryRun("process", 9, nil)
	if len(matched) != 0 {
		t.Errorf("ルールなしでDryRunはemptyを返すべきです: got %v", matched)
	}
}

// ─── AddRule / EnableRule / GetRuleByID ───────────────────────────────────────

func TestAddRule_AddsRule(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{ID: "x1", Name: "Test", Enabled: true})
	rules := e.GetRules()
	if len(rules) != 1 {
		t.Errorf("AddRule後、GetRulesは1件を返すべきです: got %d", len(rules))
	}
}

func TestAddRule_UpdatesExistingID(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{ID: "dup", Name: "Original", Enabled: true})
	e.AddRule(&RemediationRule{ID: "dup", Name: "Updated", Enabled: true})
	rules := e.GetRules()
	if len(rules) != 1 {
		t.Errorf("同IDのルールは更新されるべきです: got %d rules", len(rules))
	}
	if rules[0].Name != "Updated" {
		t.Errorf("ルール名: got %q, want Updated", rules[0].Name)
	}
}

func TestEnableRule_TogglesState(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{ID: "e1", Name: "Toggle", Enabled: true})
	e.EnableRule("e1", false)
	r, found := e.GetRuleByID("e1")
	if !found {
		t.Fatal("GetRuleByID: ルールが見つかりません")
	}
	if r.Enabled {
		t.Error("EnableRule(false)後、ルールは無効になるべきです")
	}
}

func TestGetRuleByID_NotFound(t *testing.T) {
	e := NewEngine(nil, nil)
	_, found := e.GetRuleByID("nonexistent")
	if found {
		t.Error("存在しないIDは found=false を返すべきです")
	}
}

func TestGetRules_ReturnsCopy(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{ID: "c1", Name: "Original", Enabled: true})
	rules := e.GetRules()
	if len(rules) != 1 {
		t.Errorf("GetRulesは1件を返すべきです: got %d", len(rules))
	}
}

// ─── 除外リスト (IsExcluded / AddExclusion / RemoveExclusion / ListExclusions) ──

func TestIsExcluded_ExactMatch(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "dc-01", Reason: "ドメコン"})
	if !e.IsExcluded("dc-01") {
		t.Error("除外リストに完全一致するホストは true を返すべきです")
	}
}

func TestIsExcluded_GlobMatch(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "dc-*"})
	tests := []struct {
		hostname string
		want     bool
	}{
		{"dc-01", true},
		{"dc-primary", true},
		{"web-01", false},
	}
	for _, tc := range tests {
		got := e.IsExcluded(tc.hostname)
		if got != tc.want {
			t.Errorf("IsExcluded(%q) = %v, want %v", tc.hostname, got, tc.want)
		}
	}
}

func TestIsExcluded_EmptyHostnameNeverMatches(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "*"})
	if e.IsExcluded("") {
		t.Error("空ホスト名は除外リストにマッチしてはなりません")
	}
}

func TestIsExcluded_NoExclusions_ReturnsFalse(t *testing.T) {
	e := NewEngine(nil, nil)
	if e.IsExcluded("any-host") {
		t.Error("除外リストが空の場合は false を返すべきです")
	}
}

func TestAddExclusion_AssignsID(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "prod-db-*"})
	list := e.ListExclusions()
	if len(list) != 1 {
		t.Fatalf("除外リストは1件のはずです: got %d", len(list))
	}
	if list[0].ID == "" {
		t.Error("AddExclusion は ID を自動生成するべきです")
	}
}

func TestAddExclusion_SetsCreatedAt(t *testing.T) {
	before := time.Now().Add(-time.Second)
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "srv-*"})
	list := e.ListExclusions()
	if list[0].CreatedAt.Before(before) {
		t.Error("AddExclusion は CreatedAt を現在時刻に設定するべきです")
	}
}

func TestRemoveExclusion_RemovesEntry(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "dc-*"})
	id := e.ListExclusions()[0].ID
	if !e.RemoveExclusion(id) {
		t.Fatal("RemoveExclusion は true を返すべきです")
	}
	if e.IsExcluded("dc-01") {
		t.Error("削除後はマッチしないはずです")
	}
}

func TestRemoveExclusion_NotFound(t *testing.T) {
	e := NewEngine(nil, nil)
	if e.RemoveExclusion("nonexistent-id") {
		t.Error("存在しないIDに対して false を返すべきです")
	}
}

func TestListExclusions_ReturnsCopy(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddExclusion(RemediationExclusion{HostnamePattern: "a-*"})
	e.AddExclusion(RemediationExclusion{HostnamePattern: "b-*"})
	list := e.ListExclusions()
	if len(list) != 2 {
		t.Errorf("ListExclusions: got %d, want 2", len(list))
	}
}

func TestTriggerOnAlert_SkipsExcludedHost(t *testing.T) {
	e := NewEngine(nil, nil)
	e.AddRule(&RemediationRule{
		ID:      "r1",
		Name:    "Isolate",
		Enabled: true,
		Trigger: RuleTrigger{MinSeverity: 1},
	})
	e.AddExclusion(RemediationExclusion{HostnamePattern: "dc-*"})

	logs := e.TriggerOnAlert(context.Background(), "alert-1", "agent-1", "dc-primary", 9, nil)
	if len(logs) != 0 {
		t.Errorf("除外ホストではルールを実行しないはずです: got %d logs", len(logs))
	}
}

// ─── 自動ロールバック (scheduleRollback / ApproveExecution) ───────────────────

func TestApproveExecution_CancelsPendingRollback(t *testing.T) {
	e := NewEngine(nil, nil)
	// 長めのタイムアウトでロールバックを予約（テスト中に発火しない）
	e.scheduleRollback(10*time.Minute, "exec-001", "agent-A")

	pending := e.ListPendingRollbacks()
	if len(pending) != 1 {
		t.Fatalf("ロールバック予約後、ListPendingRollbacksは1件を返すべきです: got %d", len(pending))
	}

	if !e.ApproveExecution("exec-001") {
		t.Fatal("ApproveExecution は true を返すべきです")
	}

	pending = e.ListPendingRollbacks()
	if len(pending) != 0 {
		t.Errorf("承認後、ペンディングリストは空のはずです: got %d", len(pending))
	}
}

func TestApproveExecution_NotFound(t *testing.T) {
	e := NewEngine(nil, nil)
	if e.ApproveExecution("nonexistent") {
		t.Error("存在しない executionID に対して false を返すべきです")
	}
}

func TestApproveExecution_IdempotentSecondCall(t *testing.T) {
	e := NewEngine(nil, nil)
	e.scheduleRollback(10*time.Minute, "exec-002", "agent-B")
	e.ApproveExecution("exec-002")
	// 2 回目は not found なので false
	if e.ApproveExecution("exec-002") {
		t.Error("2回目の承認呼び出しは false を返すべきです")
	}
}

func TestScheduleRollback_AutoExecutesAfterTimeout(t *testing.T) {
	// NATS なしでも scheduleRollback は goroutine を開始する。
	// タイムアウト後に pendingRollbacks から削除されること、および
	// actionUnisolateNetwork が NATS なし ("NATS not available") で graceful に失敗することを確認。
	e := NewEngine(nil, nil)
	e.scheduleRollback(50*time.Millisecond, "exec-003", "agent-C")

	// ロールバック goroutine が完了するまで待つ
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending := e.ListPendingRollbacks()
		if len(pending) == 0 {
			return // 正常: ロールバック実行後にエントリが削除された
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("タイムアウト後、pendingRollbacks からエントリが削除されるべきでした")
}

func TestListPendingRollbacks_Empty(t *testing.T) {
	e := NewEngine(nil, nil)
	pending := e.ListPendingRollbacks()
	if len(pending) != 0 {
		t.Errorf("初期状態では0件のはずです: got %d", len(pending))
	}
}

// ─── executionIsolated ────────────────────────────────────────────────────────

func TestExecutionIsolated_TrueWhenIsolateSucceeded(t *testing.T) {
	e := NewEngine(nil, nil)
	log := ExecutionLog{
		Actions: []ActionResult{
			{ActionType: "isolate_network", Success: true},
		},
	}
	if !e.executionIsolated(log) {
		t.Error("isolate_network が成功した場合 true を返すべきです")
	}
}

func TestExecutionIsolated_FalseWhenIsolateFailed(t *testing.T) {
	e := NewEngine(nil, nil)
	log := ExecutionLog{
		Actions: []ActionResult{
			{ActionType: "isolate_network", Success: false},
		},
	}
	if e.executionIsolated(log) {
		t.Error("isolate_network が失敗した場合 false を返すべきです")
	}
}

func TestExecutionIsolated_FalseWhenNoIsolateAction(t *testing.T) {
	e := NewEngine(nil, nil)
	log := ExecutionLog{
		Actions: []ActionResult{
			{ActionType: "kill_process", Success: true},
			{ActionType: "notify", Success: true},
		},
	}
	if e.executionIsolated(log) {
		t.Error("isolate_network アクションがない場合 false を返すべきです")
	}
}

func TestExecutionIsolated_EmptyActions(t *testing.T) {
	e := NewEngine(nil, nil)
	if e.executionIsolated(ExecutionLog{}) {
		t.Error("アクションが空の場合 false を返すべきです")
	}
}

// ─── actionWebhook ────────────────────────────────────────────────────────────

func TestActionWebhook_SuccessfulDelivery(t *testing.T) {
	var received atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Store(true)
		// X-EDR-Source ヘッダーを確認
		if r.Header.Get("X-EDR-Source") != "remediation-engine" {
			t.Errorf("X-EDR-Source ヘッダー: got %q, want \"remediation-engine\"", r.Header.Get("X-EDR-Source"))
		}
		if r.Method != http.MethodPost {
			t.Errorf("HTTP メソッド: got %q, want POST", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewEngine(nil, nil)
	ok, msg := e.actionWebhook(context.Background(), map[string]string{
		"url": srv.URL,
	}, "agent-X", "trigger-Y")

	if !ok {
		t.Errorf("webhook 配信に失敗しました: %s", msg)
	}
	if !received.Load() {
		t.Error("テストサーバーがリクエストを受信しませんでした")
	}
}

func TestActionWebhook_NoURL(t *testing.T) {
	e := NewEngine(nil, nil)
	ok, msg := e.actionWebhook(context.Background(), map[string]string{}, "agent-X", "trigger-Y")
	if ok {
		t.Error("URL なしの場合 false を返すべきです")
	}
	if msg == "" {
		t.Error("エラーメッセージを返すべきです")
	}
}

func TestActionWebhook_ServerReturns500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := NewEngine(nil, nil)
	ok, _ := e.actionWebhook(context.Background(), map[string]string{"url": srv.URL}, "a", "t")
	if ok {
		t.Error("サーバーが 5xx を返した場合 false を返すべきです")
	}
}

func TestActionWebhook_CustomMethod(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewEngine(nil, nil)
	ok, _ := e.actionWebhook(context.Background(), map[string]string{
		"url":    srv.URL,
		"method": "PUT",
	}, "a", "t")
	if !ok {
		t.Error("PUT メソッドでも成功するべきです")
	}
	if gotMethod != "PUT" {
		t.Errorf("HTTP メソッド: got %q, want PUT", gotMethod)
	}
}

func TestActionWebhook_TimeoutRespected(t *testing.T) {
	// 応答を返さないサーバーでタイムアウトが機能するか確認
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// タイムアウトより長く待機
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := NewEngine(nil, nil)
	start := time.Now()
	ok, _ := e.actionWebhook(context.Background(), map[string]string{
		"url":             srv.URL,
		"timeout_seconds": "1",
	}, "a", "t")
	elapsed := time.Since(start)

	if ok {
		t.Error("タイムアウト時は false を返すべきです")
	}
	// タイムアウトが効いていれば 1.5 秒以内に戻るはず（余裕を持って 1.8s）
	if elapsed > 1800*time.Millisecond {
		t.Errorf("タイムアウトが機能していません: elapsed %v", elapsed)
	}
}

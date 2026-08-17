package detection

import (
	"context"
	"errors"
	"testing"

	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/store"
)

// recordingIsolator (auto_isolate_reachability_test.go) captures isolation requests
// instead of talking to an agent.

// suppressingIsolator stands in for a Gatekeeper that declined to act — the
// AUTO_RESPONSE_ENABLED kill switch, the cooldown, the hourly budget or dry run.
// どれであっても、この経路は「実行されなかった」を error にせず素通しする。
type suppressingIsolator struct{ calls int }

func (s *suppressingIsolator) Isolate(_ context.Context, _ isolation.Request) (isolation.Result, error) {
	s.calls++
	return isolation.Result{Outcome: isolation.OutcomeDisabled, Reason: "AUTO_RESPONSE_ENABLED=false"}, nil
}

// プレイブックの隔離も Gatekeeper を通ること。
//
// 以前この経路は自前の autoResponse フラグだけを見ていて、冷却期間・時間あたり
// 上限・ドライラン・response_actions への記録をどれも通らなかった。経路ごとに
// 規則が違うことが、実隔離が記録に残らない状態を生んでいた。
func TestPlaybookRunner_IsolateGoesThroughTheGatekeeper(t *testing.T) {
	action := store.PlaybookAction{Type: "isolate_endpoint"}
	alert := &StoredAlert{ID: "alert-1", AgentID: "agent-1", Title: "t", Severity: 10}

	iso := &recordingIsolator{}
	r := NewPlaybookRunner(nil, nil, nil, iso, nil)
	if err := r.runAction(context.Background(), action, alert); err != nil {
		t.Fatalf("runAction: %v", err)
	}
	if len(iso.isolated) != 1 || iso.isolated[0] != "agent-1" {
		t.Fatalf("playbook isolation did not reach the gatekeeper, got %v", iso.isolated)
	}
	if iso.origins[0] != isolation.OriginPlaybook {
		t.Errorf("origin = %q, want %q", iso.origins[0], isolation.OriginPlaybook)
	}
}

// 抑止はエラーではない。抑止をエラーにすると、プレイブック実行全体が失敗扱いになり
// notify や create_incident の結果まで「失敗」に見える。
func TestPlaybookRunner_SuppressedIsolationIsNotAnError(t *testing.T) {
	iso := &suppressingIsolator{}
	r := NewPlaybookRunner(nil, nil, nil, iso, nil)
	alert := &StoredAlert{ID: "alert-1", AgentID: "agent-1", Title: "t", Severity: 10}

	// 抑止は errIsolationNotExecuted を返す。nil だと runActions が
	// isolate_endpoint を実行ログに「実行済み」として並べ、事後には
	// そのホストがネットワークから切られたと読まれる。
	// 「実行全体を失敗扱いにしない」という本来の要件は runActions 側で
	// 満たしている——すぐ下で確かめる。
	action := store.PlaybookAction{Type: "isolate_endpoint"}
	if err := r.runAction(context.Background(), action, alert); !errors.Is(err, errIsolationNotExecuted) {
		t.Fatalf("a suppressed isolation must report that it did not run, got %v", err)
	}
	if iso.calls != 1 {
		t.Errorf("the gatekeeper must be consulted exactly once, got %d", iso.calls)
	}

	// 抑止された回は、失敗でも実行済みでもない。
	pb := &store.Playbook{ID: "pb-1", Actions: []store.PlaybookAction{action}}
	run := &store.PlaybookRun{PlaybookID: pb.ID, AlertID: alert.ID, Success: true}
	r.runActions(context.Background(), pb, alert, run)
	if !run.Success {
		t.Errorf("抑止されたのに失敗として記録されました: %s", run.ErrorMsg)
	}
	if len(run.ActionsRun) != 0 {
		t.Errorf("抑止されたアクションが実行済みとして記録されています: %+v", run.ActionsRun)
	}
}

// recordingNotifier captures playbook notifications instead of dispatching them.
type recordingNotifier struct{ messages []string }

func (n *recordingNotifier) NotifyText(_ context.Context, message string, _ int) error {
	n.messages = append(n.messages, message)
	return nil
}

// Turning off unattended response must make an operator MORE informed, not less:
// the non-destructive actions keep running.
func TestPlaybookRunner_NotifyStillRunsWithIsolationOff(t *testing.T) {
	notifier := &recordingNotifier{}
	r := NewPlaybookRunner(nil, nil, nil, &suppressingIsolator{}, notifier)
	alert := &StoredAlert{ID: "alert-1", AgentID: "agent-1", Title: "t", Severity: 10}

	if err := r.runAction(context.Background(), store.PlaybookAction{Type: "notify"}, alert); err != nil {
		t.Fatalf("runAction: %v", err)
	}
	if len(notifier.messages) != 1 {
		t.Errorf("隔離を切っても通知は止めない。got %d", len(notifier.messages))
	}
}

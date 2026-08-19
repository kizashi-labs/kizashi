package detection

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/store"
)

// A playbook run is the only record of what the platform did automatically
// while nobody was watching. Three things made that record read better than
// what happened.
//
//   - "notify" with no notifier configured returned nil. Success. The run log
//     said the on-call was told.
//   - "assign_alert" logged a line saying it was skipped and returned nil.
//     Success. The console offers the action as 「アラートを割り当て」, the run
//     log said it was assigned, and the alert sat unassigned.
//   - Every action was appended to ActionsRun whether it succeeded or failed,
//     and ErrorMsg kept only the last error. A playbook whose isolate_endpoint
//     failed still listed isolate_endpoint as executed, and a playbook with
//     three failures recorded one.
//
// A missing record is a gap someone can notice. A record that is wrong in the
// reassuring direction is not.

type stubNotifier struct {
	err    error
	called int
}

func (s *stubNotifier) NotifyText(ctx context.Context, message string, severity int) error {
	s.called++
	return s.err
}

// failingIsolator は Gatekeeper まで届いたが送出に失敗した状態を返す。
// 「端末に届かなかった」であって「安全弁が止めた」ではないので、こちらは
// 実行ログに失敗として残らなければならない。
type failingIsolator struct{ err error }

func (f *failingIsolator) Isolate(_ context.Context, _ isolation.Request) (isolation.Result, error) {
	return isolation.Result{}, f.err
}

func alertFixture() *StoredAlert {
	return &StoredAlert{
		ID: "alert-1", AgentID: "agent-1", Title: "Mimikatz",
		Severity: 9, Hostname: "dc-primary", Status: "open",
	}
}

// The headline: an action that did not happen is not reported as done.
func TestAnActionThatDidNotRunIsNotReportedAsDone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner *PlaybookRunner
		action store.PlaybookAction
	}{
		{"notify に通知先が無い",
			&PlaybookRunner{}, store.PlaybookAction{Type: "notify", Message: "x"}},
		{"assign_alert にストアが無い",
			&PlaybookRunner{}, store.PlaybookAction{Type: "assign_alert", UserID: "u1"}},
		{"assign_alert に user_id が無い",
			&PlaybookRunner{alerts: &store.AlertStore{}}, store.PlaybookAction{Type: "assign_alert"}},
		{"isolate_endpoint にcommanderが無い",
			&PlaybookRunner{}, store.PlaybookAction{Type: "isolate_endpoint"}},
		{"create_incident にストアが無い",
			&PlaybookRunner{}, store.PlaybookAction{Type: "create_incident"}},
	} {
		if err := tc.runner.runAction(context.Background(), tc.action, alertFixture()); err == nil {
			t.Errorf("%s: 実行できていないのに成功を返しました。"+
				"実行ログには「実行済み」として残り、コンソールでは"+
				"対応が済んでいるように見えます", tc.name)
		}
	}
}

// assign_alert in particular: the console offers it, so "it does nothing" is a
// promise the product makes and does not keep.
func TestAssignAlertIsNotASilentNoOp(t *testing.T) {
	r := &PlaybookRunner{}
	err := r.runAction(context.Background(),
		store.PlaybookAction{Type: "assign_alert", UserID: "analyst-1"}, alertFixture())
	if err == nil {
		t.Fatal("assign_alert が黙って成功しています")
	}
	// The old implementation's giveaway was that it never touched anything.
	// The replacement must at minimum demand the pieces an assignment needs.
	if !strings.Contains(err.Error(), "alert store") {
		t.Errorf("何が足りないのかが分かりません: %v", err)
	}
}

// An unknown action type was already refused. That is the shape the others now
// match, and it must stay refused.
func TestAnUnknownActionTypeIsRefused(t *testing.T) {
	r := &PlaybookRunner{}
	if err := r.runAction(context.Background(),
		store.PlaybookAction{Type: "reboot_everything"}, alertFixture()); err == nil {
		t.Error("未知のアクションタイプが成功を返しました")
	}
}

// ─── the run record ──────────────────────────────────────────────────────────

func TestTheRunRecordListsOnlyWhatSucceeded(t *testing.T) {
	notifier := &stubNotifier{}
	r := &PlaybookRunner{notifier: notifier, isolator: &failingIsolator{err: errors.New("agent offline")}}

	pb := &store.Playbook{ID: "pb-1", Actions: []store.PlaybookAction{
		{Type: "isolate_endpoint"},           // fails: agent offline
		{Type: "notify", Message: "隔離しました"},  // succeeds
		{Type: "assign_alert", UserID: "u1"}, // fails: no alert store
	}}
	run := &store.PlaybookRun{PlaybookID: pb.ID, AlertID: "alert-1", Success: true}
	r.runActions(context.Background(), pb, alertFixture(), run)

	if run.Success {
		t.Error("2件失敗しているのに成功として記録されています")
	}
	if len(run.ActionsRun) != 1 || run.ActionsRun[0].Type != "notify" {
		t.Errorf("実行ログに、実行できなかったアクションが含まれています: %+v。"+
			"隔離に失敗したのに isolate_endpoint が「実行済み」として残ると、"+
			"事後にそのホストは隔離済みだったと読まれます", run.ActionsRun)
	}
	if notifier.called != 1 {
		t.Errorf("notify が呼ばれていません: %d", notifier.called)
	}
}

// Every failure has to survive into the record, not just the last one.
func TestEveryFailureReachesTheRunRecord(t *testing.T) {
	r := &PlaybookRunner{}
	pb := &store.Playbook{ID: "pb-1", Actions: []store.PlaybookAction{
		{Type: "isolate_endpoint"},
		{Type: "create_incident"},
		{Type: "notify"},
	}}
	run := &store.PlaybookRun{PlaybookID: pb.ID, AlertID: "alert-1", Success: true}
	r.runActions(context.Background(), pb, alertFixture(), run)

	if len(run.ActionsRun) != 0 {
		t.Errorf("全件失敗しているのに実行済みが記録されています: %+v", run.ActionsRun)
	}
	for _, want := range []string{"isolate_endpoint", "create_incident", "notify"} {
		if !strings.Contains(run.ErrorMsg, want) {
			t.Errorf("%s の失敗が記録に残っていません。"+
				"最後の1件だけを残すと、他の失敗は無かったことになります: %q",
				want, run.ErrorMsg)
		}
	}
}

// And a playbook that works is still recorded as working.
func TestASuccessfulPlaybookIsRecordedAsSuccessful(t *testing.T) {
	notifier := &stubNotifier{}
	commander := &recordingIsolator{}
	r := &PlaybookRunner{notifier: notifier, isolator: commander}

	pb := &store.Playbook{ID: "pb-1", Actions: []store.PlaybookAction{
		{Type: "isolate_endpoint"},
		{Type: "notify", Message: "隔離しました"},
	}}
	run := &store.PlaybookRun{PlaybookID: pb.ID, AlertID: "alert-1", Success: true}
	r.runActions(context.Background(), pb, alertFixture(), run)

	if !run.Success {
		t.Errorf("成功したプレイブックが失敗として記録されました: %s", run.ErrorMsg)
	}
	if len(run.ActionsRun) != 2 {
		t.Errorf("実行したアクションが記録されていません: %+v", run.ActionsRun)
	}
	if run.ErrorMsg != "" {
		t.Errorf("エラーが無いのにエラー文が入っています: %q", run.ErrorMsg)
	}
	if len(commander.isolated) != 1 || commander.isolated[0] != "agent-1" {
		t.Errorf("隔離が実行されていません: %+v", commander.isolated)
	}
}

// A notifier that reports failure must make the run fail. This is the join
// between this package and the dispatcher fix — if NotifyText went back to
// returning nil unconditionally, this is where it would stop mattering.
func TestANotifierThatCouldNotSendFailsTheRun(t *testing.T) {
	r := &PlaybookRunner{notifier: &stubNotifier{err: errors.New("送信先がありません")}}
	pb := &store.Playbook{ID: "pb-1", Actions: []store.PlaybookAction{{Type: "notify"}}}
	run := &store.PlaybookRun{PlaybookID: pb.ID, AlertID: "alert-1", Success: true}
	r.runActions(context.Background(), pb, alertFixture(), run)

	if run.Success {
		t.Error("通知が送れていないのに成功として記録されています")
	}
	if len(run.ActionsRun) != 0 {
		t.Errorf("送れていない通知が実行済みとして記録されています: %+v", run.ActionsRun)
	}
}

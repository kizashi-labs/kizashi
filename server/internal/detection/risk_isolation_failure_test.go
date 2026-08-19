package detection

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var errIsolationRefused = errors.New("agent offline: command not delivered")

// fakeCommander fails for the agents named and succeeds for the rest.
type fakeCommander struct {
	failFor map[string]bool
	calls   []string
}

func (c *fakeCommander) IsolateAgent(_ context.Context, agentID, _ string) error {
	c.calls = append(c.calls, agentID)
	if c.failFor[agentID] {
		return errIsolationRefused
	}
	return nil
}

// monitorWithFake returns a monitor whose isolation and alert writing are both
// under the test's control, so applyIsolations can be driven without a
// database.
func monitorWithFake(failFor ...string) (*RiskActionMonitor, *fakeCommander, *[]*StoredAlert) {
	fc := &fakeCommander{failFor: map[string]bool{}}
	for _, a := range failFor {
		fc.failFor[a] = true
	}
	var saved []*StoredAlert
	m := NewRiskActionMonitor(nil, fc)
	m.saveAlertFn = func(a *StoredAlert) error { saved = append(saved, a); return nil }
	return m, fc, &saved
}

// Containment that did not happen left no record.
//
// runOnce selects agents over the risk threshold, calls IsolateAgent, and on
// success writes a severity-10 alert saying the endpoint was isolated. On
// failure it did this:
//
//	slog.Error("RiskActionMonitor: 自動隔離に失敗しました", …)
//	continue
//
// So the only trace a SOC can see exists when containment worked. An endpoint
// scoring past the threshold that is still on the network — the case that
// needs someone to act — produced nothing but a log line.
//
// The retry makes it worse rather than better: the query re-selects the same
// agent every two minutes, so the failure repeats silently for as long as it
// lasts, and each repeat is as invisible as the first.
//
// Now the first failure writes an alert of the same severity as the success,
// and the agent is remembered so the next 720 attempts that day do not write
// 720 copies of it.

func TestTheFirstFailureAlertsAndTheRepeatsDoNot(t *testing.T) {
	m := NewRiskActionMonitor(nil, nil)

	if !m.markFailed("agent-1") {
		t.Fatal("最初の失敗が報告されていません")
	}
	for i := 0; i < 5; i++ {
		if m.markFailed("agent-1") {
			t.Fatalf("%d回目の失敗も報告されています。2分ごとに再試行するので、"+
				"同じ内容が積み上がって最初の1件が埋もれます", i+2)
		}
	}

	// A different agent is a different failure.
	if !m.markFailed("agent-2") {
		t.Error("別のエージェントの失敗が報告されていません")
	}
}

// Once isolation succeeds, the next failure is news again.
func TestASuccessRearmsTheAlert(t *testing.T) {
	m := NewRiskActionMonitor(nil, nil)

	if !m.markFailed("agent-1") {
		t.Fatal("最初の失敗が報告されていません")
	}
	if m.markFailed("agent-1") {
		t.Fatal("2回目が報告されています")
	}

	m.clearFailed("agent-1")

	if !m.markFailed("agent-1") {
		t.Error("成功したあとの失敗が報告されていません。" +
			"一度失敗した端末は、以後どれだけ失敗しても黙ったままになります")
	}
}

// clearFailed on an agent that never failed must not disturb the others.
func TestClearingAnUnknownAgentIsHarmless(t *testing.T) {
	m := NewRiskActionMonitor(nil, nil)
	if !m.markFailed("agent-1") {
		t.Fatal("最初の失敗が報告されていません")
	}
	m.clearFailed("agent-2")
	if m.markFailed("agent-1") {
		t.Error("無関係なエージェントの成功で、記録が消えています")
	}
}

// The alert must say the thing that matters: the endpoint is still connected.
// A record that only says "failed" leaves the reader to work out whether the
// containment happened.
func TestTheFailureAlertSaysTheEndpointIsStillConnected(t *testing.T) {
	var saved *StoredAlert
	m := NewRiskActionMonitor(nil, nil)
	m.saveAlertFn = func(a *StoredAlert) error { saved = a; return nil }

	m.saveFailureAlert(context.Background(), riskMatch{agentID: "agent-1", riskScore: 87}, errIsolationRefused)

	if saved == nil {
		t.Fatal("アラートが保存されていません")
	}
	if saved.Severity != 10 {
		t.Errorf("severity = %d, want 10。隔離できなかった端末は、"+
			"隔離できた端末より軽い出来事ではありません", saved.Severity)
	}
	if saved.AgentID != "agent-1" {
		t.Errorf("agent_id = %q", saved.AgentID)
	}
	for _, want := range []string{"87", "まだネットワークに接続", errIsolationRefused.Error()} {
		if !strings.Contains(saved.Title+saved.Description, want) {
			t.Errorf("アラートが %q を含んでいません: %s / %s", want, saved.Title, saved.Description)
		}
	}
	// And it must be distinguishable from the success alert, or the two
	// collapse into one line in a list.
	if !strings.Contains(saved.RuleName, "失敗") {
		t.Errorf("成功時のアラートと名前で区別できません: %q", saved.RuleName)
	}
}

// The loop itself: a failed isolation writes exactly one alert however many
// times it is retried, and a success writes the success alert and re-arms.
func TestApplyIsolationsRecordsBothOutcomes(t *testing.T) {
	m, _, saved := monitorWithFake("bad-agent")
	matches := []riskMatch{
		{agentID: "bad-agent", riskScore: 91},
		{agentID: "ok-agent", riskScore: 88},
	}

	m.applyIsolations(context.Background(), matches)
	if len(*saved) != 2 {
		t.Fatalf("アラートが %d 件 (want 2: 失敗1件と成功1件): %v", len(*saved), *saved)
	}

	var failure, success *StoredAlert
	for _, a := range *saved {
		if strings.Contains(a.RuleName, "失敗") {
			failure = a
		} else {
			success = a
		}
	}
	if failure == nil {
		t.Error("隔離に失敗した端末のアラートがありません。" +
			"記録が残るのは封じ込めが効いたときだけになります")
	}
	if success == nil {
		t.Error("隔離できた端末のアラートがありません")
	}

	// Retried two minutes later, the same failure must not add another copy.
	m.applyIsolations(context.Background(), matches)
	failures := 0
	for _, a := range *saved {
		if strings.Contains(a.RuleName, "失敗") {
			failures++
		}
	}
	if failures != 1 {
		t.Errorf("失敗のアラートが %d 件。再試行のたびに積むと最初の1件が埋もれます", failures)
	}
}

// And once the agent is finally isolated, a later failure is reported again.
func TestApplyIsolationsReportsAgainAfterARecovery(t *testing.T) {
	m, fc, saved := monitorWithFake("flaky")
	matches := []riskMatch{{agentID: "flaky", riskScore: 95}}

	m.applyIsolations(context.Background(), matches)
	fc.failFor["flaky"] = false
	m.applyIsolations(context.Background(), matches)
	fc.failFor["flaky"] = true
	m.applyIsolations(context.Background(), matches)

	failures := 0
	for _, a := range *saved {
		if strings.Contains(a.RuleName, "失敗") {
			failures++
		}
	}
	if failures != 2 {
		t.Errorf("失敗のアラートが %d 件 (want 2)。一度成功したあとの失敗は"+
			"新しい出来事です", failures)
	}
}

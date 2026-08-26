package isolation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeSender records what reached the endpoint.
type fakeSender struct {
	isolated   []string
	unisolated []string
	commandIDs []string
	actors     []string
	err        error
}

func (f *fakeSender) IsolateEndpoint(_ context.Context, agentID, _, _, commandID, actor string) error {
	if f.err != nil {
		return f.err
	}
	f.isolated = append(f.isolated, agentID)
	f.commandIDs = append(f.commandIDs, commandID)
	f.actors = append(f.actors, actor)
	return nil
}

func (f *fakeSender) UnisolateEndpoint(_ context.Context, agentID, _, commandID string) error {
	if f.err != nil {
		return f.err
	}
	f.unisolated = append(f.unisolated, agentID)
	f.commandIDs = append(f.commandIDs, commandID)
	return nil
}

// fakeRecorder records the audit rows.
type fakeRecorder struct {
	n           int
	statuses    []string
	completed   []string
	details     []map[string]string
	triggeredBy []string
}

func (r *fakeRecorder) Record(_ context.Context, _, _, status, triggeredBy string, details interface{}) (string, error) {
	r.n++
	r.statuses = append(r.statuses, status)
	r.triggeredBy = append(r.triggeredBy, triggeredBy)
	if d, ok := details.(map[string]string); ok {
		r.details = append(r.details, d)
	} else {
		r.details = append(r.details, nil)
	}
	return "row-" + status, nil
}

func (r *fakeRecorder) Complete(_ context.Context, id, status, _ string) error {
	r.completed = append(r.completed, id+"→"+status)
	return nil
}

func newTestGatekeeper(cfg Config) (*Gatekeeper, *fakeSender, *fakeRecorder) {
	s, r := &fakeSender{}, &fakeRecorder{}
	return New(s, r, cfg), s, r
}

// 記録は送出の前。id をコマンドに載せるため、順序が逆だと ack の受け先が無い。
func TestIsolateRecordsBeforeDispatchAndPassesTheRowID(t *testing.T) {
	g, s, r := newTestGatekeeper(Config{UnattendedEnabled: true})

	res, err := g.Isolate(context.Background(), Request{
		AgentID: "agent-1", Origin: OriginRule, Reason: "test", Label: "rule",
	})
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if res.Outcome != OutcomeDispatched {
		t.Fatalf("outcome = %q, want %q", res.Outcome, OutcomeDispatched)
	}
	if len(s.isolated) != 1 {
		t.Fatalf("the endpoint was not told: %v", s.isolated)
	}
	if r.statuses[0] != statusPending {
		t.Errorf("first record status = %q, want %q", r.statuses[0], statusPending)
	}
	if len(s.commandIDs) != 1 || s.commandIDs[0] != res.ActionID {
		t.Errorf("command carried %v, want the audit row id %q", s.commandIDs, res.ActionID)
	}
	if len(r.completed) != 1 || r.completed[0] != res.ActionID+"→"+statusDispatched {
		t.Errorf("completions = %v, want the row moved to %q", r.completed, statusDispatched)
	}
}

// 送出が失敗したら success にしない。これが #704 で潰した嘘の再発防止。
func TestDispatchFailureIsRecordedAsFailure(t *testing.T) {
	s, r := &fakeSender{err: errors.New("nats down")}, &fakeRecorder{}
	g := New(s, r, Config{UnattendedEnabled: true})

	res, err := g.Isolate(context.Background(), Request{AgentID: "agent-1", Origin: OriginRule})
	if err == nil {
		t.Fatal("a dispatch failure must surface as an error")
	}
	if res.Outcome.Executed() {
		t.Errorf("outcome = %q, must not report as executed", res.Outcome)
	}
	if len(r.completed) != 1 || r.completed[0] != "row-pending→"+statusFailure {
		t.Errorf("completions = %v, want the row completed as %q", r.completed, statusFailure)
	}
}

// AUTO_RESPONSE_ENABLED=false は無人経路を全て止める。止めたことも記録する。
func TestUnattendedIsolationIsBlockedByTheKillSwitch(t *testing.T) {
	for _, origin := range []Origin{OriginRule, OriginPlaybook, OriginAITriage, OriginRemediation, OriginQuarantineAction} {
		t.Run(string(origin), func(t *testing.T) {
			g, s, r := newTestGatekeeper(Config{UnattendedEnabled: false})
			res, err := g.Isolate(context.Background(), Request{AgentID: "agent-1", Origin: origin})
			if err != nil {
				t.Fatalf("a blocked isolation is not an error: %v", err)
			}
			if res.Outcome != OutcomeDisabled {
				t.Errorf("outcome = %q, want %q", res.Outcome, OutcomeDisabled)
			}
			if len(s.isolated) != 0 {
				t.Errorf("%s reached the endpoint with the kill switch off", origin)
			}
			if len(r.statuses) != 1 || r.statuses[0] != statusSuppressed {
				t.Errorf("statuses = %v, want one %q row — ログだけでは件数を数えられない",
					r.statuses, statusSuppressed)
			}
		})
	}
}

// 手動隔離はキルスイッチにも安全弁にも従わない。押した人が結果を引き受ける。
func TestManualIsolationIgnoresTheKillSwitchAndTheGuard(t *testing.T) {
	g, s, _ := newTestGatekeeper(Config{UnattendedEnabled: false, HourlyBudget: 1, DryRun: true})
	for i := 0; i < 3; i++ {
		res, err := g.Isolate(context.Background(), Request{
			AgentID: "agent-1", Origin: OriginManual, TriggeredBy: "user-1",
		})
		if err != nil {
			t.Fatalf("manual isolate %d: %v", i, err)
		}
		if res.Outcome != OutcomeDispatched {
			t.Fatalf("manual isolate %d suppressed as %q", i, res.Outcome)
		}
	}
	if len(s.isolated) != 3 {
		t.Errorf("manual isolations dispatched = %d, want 3", len(s.isolated))
	}
}

// ドライランは隔離しないが、何が止まるはずだったかを行として残す。
func TestDryRunSuppressesButRecords(t *testing.T) {
	g, s, r := newTestGatekeeper(Config{UnattendedEnabled: true, DryRun: true})

	res, err := g.Isolate(context.Background(), Request{AgentID: "agent-1", Origin: OriginRule, Label: "rule-x"})
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if res.Outcome != OutcomeDryRun {
		t.Fatalf("outcome = %q, want %q", res.Outcome, OutcomeDryRun)
	}
	if len(s.isolated) != 0 {
		t.Fatal("dry run reached the endpoint")
	}
	if len(r.details) != 1 || r.details[0]["outcome"] != string(OutcomeDryRun) {
		t.Errorf("details = %v, want outcome=%q so the count is queryable in SQL",
			r.details, OutcomeDryRun)
	}
	if !g.DryRun() {
		t.Error("DryRun() must report the configured mode")
	}
}

// 冷却期間: 同じ端末を続けて止めない。
func TestCooldownRefusesTheSameAgent(t *testing.T) {
	g, s, r := newTestGatekeeper(Config{UnattendedEnabled: true, Cooldown: time.Hour, HourlyBudget: 10})
	base := time.Date(2026, 8, 13, 20, 0, 0, 0, time.UTC)
	g.guard.now = func() time.Time { return base }

	if _, err := g.Isolate(context.Background(), Request{AgentID: "a1", Origin: OriginRule}); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.guard.now = func() time.Time { return base.Add(10 * time.Minute) }
	res, _ := g.Isolate(context.Background(), Request{AgentID: "a1", Origin: OriginRule})
	if res.Outcome != OutcomeRefused {
		t.Fatalf("second isolate within the cooldown: outcome = %q, want %q", res.Outcome, OutcomeRefused)
	}
	if len(s.isolated) != 1 {
		t.Errorf("dispatched %d times, want 1", len(s.isolated))
	}
	if r.statuses[len(r.statuses)-1] != statusSuppressed {
		t.Error("the refusal must be recorded, not just logged")
	}

	// 別の端末は止めない。広がる攻撃で 1 台目が他を守ってしまうのは逆効果。
	other, _ := g.Isolate(context.Background(), Request{AgentID: "a2", Origin: OriginRule})
	if other.Outcome != OutcomeDispatched {
		t.Errorf("a different agent was refused by another agent's cooldown: %q", other.Outcome)
	}
}

// 時間あたり上限: 全社を止めない。
func TestHourlyBudgetTripsTheBreaker(t *testing.T) {
	g, s, _ := newTestGatekeeper(Config{UnattendedEnabled: true, Cooldown: time.Nanosecond, HourlyBudget: 2})
	base := time.Date(2026, 8, 13, 20, 0, 0, 0, time.UTC)
	n := 0
	g.guard.now = func() time.Time { n++; return base.Add(time.Duration(n) * time.Minute) }

	outcomes := []Outcome{}
	for i := 0; i < 4; i++ {
		res, _ := g.Isolate(context.Background(), Request{AgentID: "agent-" + string(rune('a'+i)), Origin: OriginRule})
		outcomes = append(outcomes, res.Outcome)
	}
	if len(s.isolated) != 2 {
		t.Fatalf("dispatched %d, want the budget of 2 (outcomes=%v)", len(s.isolated), outcomes)
	}
	if outcomes[2] != OutcomeRefused || outcomes[3] != OutcomeRefused {
		t.Errorf("outcomes = %v, want the 3rd and 4th refused", outcomes)
	}
}

// 窓を過ぎれば上限は回復する。恒久的に止まったままでは本物の攻撃に対応できない。
func TestBudgetRecoversAfterTheWindow(t *testing.T) {
	g, s, _ := newTestGatekeeper(Config{UnattendedEnabled: true, Cooldown: time.Nanosecond, HourlyBudget: 1})
	base := time.Date(2026, 8, 13, 20, 0, 0, 0, time.UTC)
	g.guard.now = func() time.Time { return base }
	if _, err := g.Isolate(context.Background(), Request{AgentID: "a1", Origin: OriginRule}); err != nil {
		t.Fatalf("first: %v", err)
	}
	g.guard.now = func() time.Time { return base.Add(2 * time.Hour) }
	if res, _ := g.Isolate(context.Background(), Request{AgentID: "a2", Origin: OriginRule}); res.Outcome != OutcomeDispatched {
		t.Fatalf("after the window: outcome = %q, want %q", res.Outcome, OutcomeDispatched)
	}
	if len(s.isolated) != 2 {
		t.Errorf("dispatched %d, want 2", len(s.isolated))
	}
}

// 解除に安全弁は無い。戻せないほうが危険。
func TestUnisolateIsNeverSuppressed(t *testing.T) {
	g, s, _ := newTestGatekeeper(Config{UnattendedEnabled: false, DryRun: true, HourlyBudget: 1})
	for i := 0; i < 3; i++ {
		if _, err := g.Unisolate(context.Background(), Request{AgentID: "a1", Origin: OriginRemediation}); err != nil {
			t.Fatalf("unisolate %d: %v", i, err)
		}
	}
	if len(s.unisolated) != 3 {
		t.Errorf("unisolate dispatched %d, want 3 — 解除は止めない", len(s.unisolated))
	}
}

// 経路の記入漏れは無人扱いに倒す。既定で安全側に落ちること。
func TestMissingOriginIsTreatedAsUnattended(t *testing.T) {
	g, s, _ := newTestGatekeeper(Config{UnattendedEnabled: false})
	res, err := g.Isolate(context.Background(), Request{AgentID: "a1"})
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if res.Outcome != OutcomeDisabled {
		t.Errorf("outcome = %q, want %q — 空の Origin が手動扱いになると安全弁を素通りする",
			res.Outcome, OutcomeDisabled)
	}
	if len(s.isolated) != 0 {
		t.Error("an origin-less request reached the endpoint with the kill switch off")
	}
}

func TestAgentIDIsRequired(t *testing.T) {
	g, _, _ := newTestGatekeeper(Config{UnattendedEnabled: true})
	if _, err := g.Isolate(context.Background(), Request{Origin: OriginRule}); !errors.Is(err, ErrNoAgent) {
		t.Errorf("err = %v, want ErrNoAgent", err)
	}
}

// 記録できなくても隔離は続ける。止めるべき端末を止めないほうが危険。
func TestIsolationProceedsWithoutARecorder(t *testing.T) {
	s := &fakeSender{}
	g := New(s, nil, Config{UnattendedEnabled: true})
	res, err := g.Isolate(context.Background(), Request{AgentID: "a1", Origin: OriginRule})
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if res.Outcome != OutcomeDispatched || len(s.isolated) != 1 {
		t.Errorf("outcome=%q dispatched=%d, want the endpoint told anyway", res.Outcome, len(s.isolated))
	}
}

// 送出先が無いのに成功を返さないこと。
func TestNoSenderDoesNotReportSuccess(t *testing.T) {
	g := New(nil, &fakeRecorder{}, Config{UnattendedEnabled: true})
	res, err := g.Isolate(context.Background(), Request{AgentID: "a1", Origin: OriginManual})
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if res.Outcome.Executed() {
		t.Errorf("outcome = %q with no sender configured", res.Outcome)
	}
}

// nil の Gatekeeper でも panic せず、実行しなかったことを返す。
// 結線漏れが panic ではなく「隔離されない」で現れると気づきにくいが、
// panic でサービスが落ちるほうが被害は大きい。
func TestNilGatekeeperIsSafe(t *testing.T) {
	var g *Gatekeeper
	res, err := g.Isolate(context.Background(), Request{AgentID: "a1", Origin: OriginRule})
	if err != nil {
		t.Fatalf("nil gatekeeper: %v", err)
	}
	if res.Outcome.Executed() {
		t.Error("a nil gatekeeper must not report an executed isolation")
	}
	if g.DryRun() {
		t.Error("a nil gatekeeper is not in dry-run mode")
	}
}

func TestOriginUnattended(t *testing.T) {
	if OriginManual.Unattended() {
		t.Error("manual isolation has a human in the loop")
	}
	for _, o := range []Origin{OriginRule, OriginPlaybook, OriginAITriage, OriginRemediation, OriginQuarantineAction} {
		if !o.Unattended() {
			t.Errorf("%q must be treated as unattended", o)
		}
	}
}

// 送出先に渡る actor は、response_actions.executed_by と同じ値でなければならない。
//
// この2つは以前バラバラだった。CommandStore が agents.isolated_by へ "ai_agent" を
// 決め打ちしていたため、**経路にかかわらず全ての隔離が AI トリアージの仕業に
// 見えていた**。手動隔離も、ハンドラが操作者のユーザーIDを書いた直後に上書き
// されていた。誤隔離を追うとき最初に見る列がそれでは、無実の経路が犯人に見え、
// 本当の経路が視界に入らない。
func TestIsolateActorMatchesRecordedExecutedBy(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"操作者がいればその人", Request{AgentID: "a1", Origin: OriginManual, TriggeredBy: "user-42"}, "user-42"},
		{"無人なら経路名", Request{AgentID: "a1", Origin: OriginRule}, "auto_rule"},
		{"隔離アクションAPI", Request{AgentID: "a1", Origin: OriginQuarantineAction}, "quarantine_action"},
		{"AIトリアージだけが ai_triage", Request{AgentID: "a1", Origin: OriginAITriage}, "ai_triage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sender := &fakeSender{}
			rec := &fakeRecorder{}
			gk := New(sender, rec, Config{UnattendedEnabled: true})
			if _, err := gk.Isolate(context.Background(), c.req); err != nil {
				t.Fatalf("isolate: %v", err)
			}
			if len(sender.actors) != 1 || sender.actors[0] != c.want {
				t.Errorf("送出先に渡った actor = %v, want %q", sender.actors, c.want)
			}
			// 記録側と一致していること。片方だけ直すと、また同じ乖離が生まれる。
			if len(rec.triggeredBy) == 0 || rec.triggeredBy[0] != c.want {
				t.Errorf("response_actions の executed_by = %v, want %q", rec.triggeredBy, c.want)
			}
		})
	}
}

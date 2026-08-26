package response

import (
	"context"
	"errors"
	"testing"
)

// 隔離は「一度掛けたら効き続ける」ものではない。iptables -F、ポリシーの再適用、
// ファイアウォールサービスの再起動、管理者の手作業——ルールが消える経路はいくらでも
// ある。適用直後の検証 (#733) はその後の消失を捕まえられず、エージェントは
// 「隔離中」と言い続け、コンソールも封じ込め済みと表示する。

// driftMock は外部要因でルールが消えた状態を返すだけの差し替えである。
// 判定そのものは製品側 (response) が持っており、ここには写していない。
// missing が true の間は、実態として隔離されていないことになる。
type driftMock struct {
	isolated     bool
	missing      bool
	verifyErr    error
	isolateCalls int
	lastAllowed  []string
}

func (m *driftMock) Isolate(allowedIPs []string, _ []uint16) error {
	m.isolateCalls++
	m.lastAllowed = append([]string(nil), allowedIPs...)
	m.isolated = true
	m.missing = false // 貼り直したので実態も回復する
	return nil
}

func (m *driftMock) Unisolate() error {
	m.isolated = false
	return nil
}

func (m *driftMock) IsIsolated() bool { return m.isolated }

func (m *driftMock) VerifyIsolation() (bool, error) {
	if m.verifyErr != nil {
		return false, m.verifyErr
	}
	return m.isolated && !m.missing, nil
}

func newDriftExecutor(iso *driftMock) (*Executor, *mockAckSender) {
	ack := &mockAckSender{}
	return NewExecutor(iso, nil, nil, "agent-1", "https://10.0.0.1:8080", ack), ack
}

// 隔離中のはずなのにルールが消えていたら、同じ条件で貼り直す。
func TestDriftReappliesMissingIsolation(t *testing.T) {
	iso := &driftMock{}
	e, _ := newDriftExecutor(iso)
	ctx := context.Background()

	e.Isolate(ctx, IsolateCmd{CommandID: "cmd-1", Reason: "test", AllowedIPs: []string{"10.0.0.9"}})
	if iso.isolateCalls != 1 {
		t.Fatalf("初回の隔離が実行されていません (calls=%d)", iso.isolateCalls)
	}

	// 外部が iptables -F 相当でルールを消した
	iso.missing = true

	e.CheckIsolationDrift(ctx)

	if iso.isolateCalls != 2 {
		t.Fatalf("消えたルールが再適用されていません (calls=%d)", iso.isolateCalls)
	}
	if ok, _ := iso.VerifyIsolation(); !ok {
		t.Error("再適用後も実態が隔離されていません")
	}
}

// 再適用で EDR サーバへの経路まで塞ぐと、コマンドチャネルを失って二度と
// 解除できなくなる。許可 IP を覚えていることが前提条件。
func TestDriftReapplyKeepsAllowedIPs(t *testing.T) {
	iso := &driftMock{}
	e, _ := newDriftExecutor(iso)
	ctx := context.Background()

	e.Isolate(ctx, IsolateCmd{CommandID: "cmd-1", Reason: "test", AllowedIPs: []string{"10.0.0.9"}})
	iso.missing = true
	e.CheckIsolationDrift(ctx)

	found := false
	for _, ip := range iso.lastAllowed {
		if ip == "10.0.0.9" {
			found = true
		}
	}
	if !found {
		t.Errorf("再適用で元の許可 IP が失われました: %v", iso.lastAllowed)
	}
	if len(iso.lastAllowed) < 2 {
		t.Errorf("EDR サーバの許可が付いていません: %v", iso.lastAllowed)
	}
}

// 隔離していないはずなのにルールがある場合は、消さずに報告するだけ。
// 管理者が意図して入れたルールを消す権利はエージェントに無いし、
// 消せば通信を壊しかねない。
func TestDriftDoesNotRemoveUnexpectedRules(t *testing.T) {
	iso := &driftMock{isolated: true} // 隔離コマンドを受けていないのにルールがある
	e, _ := newDriftExecutor(iso)

	e.CheckIsolationDrift(context.Background())

	if iso.isolateCalls != 0 {
		t.Errorf("意図しないルールに対して隔離を実行しました (calls=%d)", iso.isolateCalls)
	}
	if !iso.isolated {
		t.Error("エージェントが勝手にルールを消しました")
	}
}

// 状態を確認できなかったときに貼り直すと、既に効いている隔離を二重に適用したり、
// 権限不足のたびに再試行を繰り返したりする。確認できないなら何もしない。
func TestDriftDoesNothingWhenVerificationFails(t *testing.T) {
	iso := &driftMock{}
	e, _ := newDriftExecutor(iso)
	ctx := context.Background()

	e.Isolate(ctx, IsolateCmd{CommandID: "cmd-1", Reason: "test"})
	before := iso.isolateCalls

	iso.verifyErr = errors.New("permission denied")
	e.CheckIsolationDrift(ctx)

	if iso.isolateCalls != before {
		t.Errorf("確認できないのに再適用しました (before=%d after=%d)", before, iso.isolateCalls)
	}
}

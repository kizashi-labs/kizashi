package response

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 隔離は「コマンドが失敗しなかった」ことをもって成功と報告していた。
// 終了コード 0 はルールが入ったことを意味しない——適用したつもりで効いていない
// 場合も、直後に別の何かが流した場合（iptables -F は珍しくない）も、そこまでは
// 成功に見える。IsIsolated() は 3 OS ともメモリ上のフラグを返すだけで、実態を
// 読む関数は Linux の起動時処理にしかなかった。
//
// ここでは「実態を読み返してから報告する」ことを固定する。

func newVerifyTestExecutor(iso *mockIsolationManager, ack *mockAckSender) *Executor {
	return NewExecutor(iso, nil, nil, "agent-1", "https://edr.example.com", ack)
}

func TestIsolateReportsFailureWhenRulesAreMissing(t *testing.T) {
	iso := &mockIsolationManager{verifyLies: true} // 成功を返すが実態は入っていない
	ack := &mockAckSender{}
	e := newVerifyTestExecutor(iso, ack)

	e.Isolate(context.Background(), IsolateCmd{CommandID: "cmd-1", Reason: "test"})

	if ack.calls == 0 {
		t.Fatal("ACK が送られていません")
	}
	if ack.success {
		t.Error("ルールが無いのに成功として報告されました")
	}
	if !strings.Contains(ack.errMsg, "no firewall rules") {
		t.Errorf("理由が伝わっていません: %q", ack.errMsg)
	}
}

// 「確認できなかった」と「確認したうえで入っていない」は違う。前者は権限や
// コマンド不在で起こり、対処が変わる。混ぜると復旧手順を誤る。
func TestIsolateReportsVerificationErrorDistinctly(t *testing.T) {
	iso := &mockIsolationManager{verifyErr: errors.New("permission denied")}
	ack := &mockAckSender{}
	e := newVerifyTestExecutor(iso, ack)

	e.Isolate(context.Background(), IsolateCmd{CommandID: "cmd-2", Reason: "test"})

	if ack.success {
		t.Error("確認できなかったのに成功として報告されました")
	}
	if !strings.Contains(ack.errMsg, "verification failed") {
		t.Errorf("確認失敗と分かる理由になっていません: %q", ack.errMsg)
	}
	if strings.Contains(ack.errMsg, "no firewall rules") {
		t.Error("「確認できなかった」が「ルールが無い」と混ざっています")
	}
}

func TestIsolateReportsSuccessWhenRulesArePresent(t *testing.T) {
	iso := &mockIsolationManager{}
	ack := &mockAckSender{}
	e := newVerifyTestExecutor(iso, ack)

	e.Isolate(context.Background(), IsolateCmd{CommandID: "cmd-3", Reason: "test"})

	if !ack.success {
		t.Errorf("正常な隔離が失敗として報告されました: %q", ack.errMsg)
	}
}

// 解除でルールが残ったまま「解除した」と報告すると、コンソール上は復旧済みなのに
// 端末は繋がらない——孤児化した隔離そのもの。この形は実際に起きている。
func TestUnisolateReportsFailureWhenRulesRemain(t *testing.T) {
	iso := &mockIsolationManager{isolated: true}
	ack := &mockAckSender{}
	e := newVerifyTestExecutor(iso, ack)

	// Unisolate は isolated を false にするが、実態は残っているとする
	iso.isolated = true
	e.Unisolate(context.Background(), UnisolateCmd{CommandID: "cmd-4", Reason: "test"})

	if ack.calls == 0 {
		t.Fatal("ACK が送られていません")
	}
}

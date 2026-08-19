package isolation

import (
	"context"
	"testing"
)

// AUTO_ISOLATE_EXEMPT は 2026-08-17 まで detection にしか実装が無かった。
// 環境変数は両サービスに配られていたので、api 経由の隔離（プレイブック・
// 自動修復・API 呼び出し）にも効いているように見えて、実際には安全弁が
// 一つも無かった。Gatekeeper は全経路が通る関門なので、ここで止める。
func TestExemptStopsUnattendedIsolation(t *testing.T) {
	sender := &fakeSender{}
	audit := &fakeRecorder{}
	gk := New(sender, audit, Config{
		UnattendedEnabled: true,
		Exempt:            []string{"edr-server", "jump-host"},
		HostnameResolver: func(_ context.Context, agentID string) string {
			if agentID == "agent-self" {
				return "EDR-Server" // 大文字小文字は無視される
			}
			return "worker-01"
		},
	})

	res, err := gk.Isolate(context.Background(), Request{
		AgentID: "agent-self", Origin: OriginRule, Reason: "ランサムウェア相関", Label: "ransomCorr",
	})
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	if res.Outcome != OutcomeExempt {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeExempt)
	}
	if res.Outcome.Executed() {
		t.Error("除外対象が実行済みとして扱われている")
	}
	if len(sender.isolated) != 0 {
		t.Errorf("除外対象にコマンドが送出された (%d 件)", len(sender.isolated))
	}

	// 除外は「記録して隔離しない」であって「黙って何もしない」ではない。
	// 記録が無いと、あとから「隔離条件を満たしたが除外された」を数えられず、
	// ドライランを外す前の見積りが除外ホスト分だけ構造的に欠ける。
	if audit.n == 0 {
		t.Fatal("除外が response_actions に記録されていない")
	}
	if got := audit.statuses[0]; got != "suppressed" {
		t.Errorf("status = %q, want %q", got, "suppressed")
	}
	if got := audit.details[0]["outcome"]; got != string(OutcomeExempt) {
		t.Errorf("details.outcome = %q, want %q", got, OutcomeExempt)
	}

	// 除外に載っていない端末は従来どおり隔離される。除外が広く効きすぎて
	// いないことの確認（安全弁が全部止めてしまうのも欠陥である）。
	res, err = gk.Isolate(context.Background(), Request{
		AgentID: "agent-other", Origin: OriginRule, Reason: "ランサムウェア相関",
	})
	if err != nil {
		t.Fatalf("isolate other: %v", err)
	}
	if !res.Outcome.Executed() {
		t.Errorf("除外対象でない端末が %q で止まった: %s", res.Outcome, res.Reason)
	}
}

// 手動隔離は除外の対象外。運用者が押した隔離が黙って落ちると、押した本人が
// 「効いていない」ことに気づけない（TestManualIsolationBypassesTheGuard と同じ理屈）。
func TestExemptDoesNotBlockManualIsolation(t *testing.T) {
	sender := &fakeSender{}
	gk := New(sender, &fakeRecorder{}, Config{
		UnattendedEnabled: false, // 無人経路は止まっている状態でも
		Exempt:            []string{"edr-server"},
	})

	res, err := gk.Isolate(context.Background(), Request{
		AgentID: "agent-self", Hostname: "edr-server",
		Origin: OriginManual, Reason: "手動隔離",
	})
	if err != nil {
		t.Fatalf("manual isolate: %v", err)
	}
	if !res.Outcome.Executed() {
		t.Errorf("手動隔離が %q で抑止された: %s", res.Outcome, res.Reason)
	}
}

// Request.Hostname が埋まっていれば解決器が無くても効く。逆に、解決器も
// ホスト名も無い場合はエージェント ID での一致だけが残る。
func TestExemptMatchesHostnameOrAgentID(t *testing.T) {
	cases := []struct {
		name     string
		list     []string
		hostname string
		agentID  string
		want     bool
	}{
		{"ホスト名で一致", []string{"edr-server"}, "edr-server", "a1", true},
		{"大文字小文字を無視", []string{"EDR-Server"}, "edr-server", "a1", true},
		{"前後の空白を無視", []string{"  edr-server  "}, "edr-server", "a1", true},
		{"エージェントIDで一致", []string{"a1"}, "", "a1", true},
		{"どちらにも一致しない", []string{"edr-server"}, "worker-01", "a1", false},
		{"空の項目は無視", []string{"", "  "}, "", "a1", false},
		// ホスト名が空のとき、空文字の項目が全端末に一致してはいけない。
		{"ホスト名が空でも誤爆しない", []string{"edr-server"}, "", "a1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsExempt(tc.list, tc.hostname, tc.agentID); got != tc.want {
				t.Errorf("IsExempt(%v, %q, %q) = %v, want %v",
					tc.list, tc.hostname, tc.agentID, got, tc.want)
			}
		})
	}
}

// 除外は冷却期間や時間あたり上限より前に効く。あちらは「今は駄目」だが、
// 除外は「対象にしない」なので、枠が空いていても覆らない。
func TestExemptTakesPrecedenceOverBudget(t *testing.T) {
	sender := &fakeSender{}
	gk := New(sender, &fakeRecorder{}, Config{
		UnattendedEnabled: true,
		HourlyBudget:      10, // 枠は十分にある
		Exempt:            []string{"edr-server"},
	})
	for i := 0; i < 3; i++ {
		res, _ := gk.Isolate(context.Background(), Request{
			AgentID: "a1", Hostname: "edr-server", Origin: OriginRule,
		})
		if res.Outcome != OutcomeExempt {
			t.Fatalf("%d 回目: Outcome = %q, want exempt", i, res.Outcome)
		}
	}
	if len(sender.isolated) != 0 {
		t.Errorf("除外対象にコマンドが送出された (%d 件)", len(sender.isolated))
	}
}

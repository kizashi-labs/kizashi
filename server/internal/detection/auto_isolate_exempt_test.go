package detection

import (
	"context"
	"testing"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
	"github.com/edr-platform/server/internal/isolation"
)

// TestAutoIsolateExempt covers the one response the platform cannot take back.
//
// Isolation firewalls the endpoint down to the EDR server alone, so isolating the
// host that RUNS the platform — a single-node deployment, a lab box, an operator's
// jump host — takes the service down AND locks the operator out of the machine they
// would fix it from. Recovery needs out-of-band access that may not exist.
//
// The exemption deliberately suppresses only the RESPONSE. Suppression rules cannot
// serve this purpose: they drop the alert, so exempting a host that way would blind
// detection on it, and their SeverityMax matches severity <= N, the opposite of the
// high-severity band that triggers isolation.
//
// これらのケースはかつて Engine.isAutoIsolateExempt を直接呼んでいた。その検査は
// 撤去され、判定は Gatekeeper だけが持つ（記録が残る側に寄せるため）。テストも
// 実物の Gatekeeper と Engine を組み合わせた形に変えてある。fake の isolator では
// 「Engine が自分で除外しなくなった」ことしか言えず、合成した結果が正しいかを
// 確かめられない。

// exemptSender records isolate dispatches. 除外が効いていれば 0 件になる。
type exemptSender struct{ isolated []string }

func (s *exemptSender) IsolateEndpoint(_ context.Context, agentID, _, _, _ string) error {
	s.isolated = append(s.isolated, agentID)
	return nil
}
func (s *exemptSender) UnisolateEndpoint(_ context.Context, _, _, _ string) error { return nil }

// exemptRecorder captures response_actions rows. 除外の記録が残ることの検査に使う。
type exemptRecorder struct {
	statuses []string
	outcomes []string
}

func (r *exemptRecorder) Record(_ context.Context, _, _, status, _ string, details interface{}) (string, error) {
	r.statuses = append(r.statuses, status)
	outcome := ""
	if d, ok := details.(map[string]string); ok {
		outcome = d["outcome"]
	}
	r.outcomes = append(r.outcomes, outcome)
	return "row-1", nil
}
func (r *exemptRecorder) Complete(_ context.Context, _, _, _ string) error { return nil }

// exemptEngine wires a real Gatekeeper behind the Engine, which is the shape that
// actually ships. HostnameResolver は敢えて設定しない — 呼び出し側が Hostname を
// 載せていることが、この経路の前提だからである。
func exemptEngine(exempt []string) (*Engine, *exemptSender, *exemptRecorder) {
	sender := &exemptSender{}
	rec := &exemptRecorder{}
	gk := isolation.New(sender, rec, isolation.Config{
		UnattendedEnabled: true,
		Exempt:            exempt,
	})
	return &Engine{
		store:    &captureStore{},
		rules:    detectionrules.NewRuleEngine(),
		isolator: gk,
		config: EngineConfig{
			AutoResponseEnabled:          true,
			AutoIsolateSeverityThreshold: 9,
		},
	}, sender, rec
}

func exemptAlert(agentID, hostname string) *StoredAlert {
	return &StoredAlert{
		ID: "alert-1", AgentID: agentID, Hostname: hostname,
		RuleID: "", RuleName: "ランサムウェア相関: 複合前兆シグナルによる暗号化直前の疑い",
		Severity: 10, AutoIsolate: true,
	}
}

func TestAutoIsolateExempt(t *testing.T) {
	const agentID = "11111111-1111-1111-1111-111111111111"
	const otherID = "22222222-2222-2222-2222-222222222222"

	cases := []struct {
		name       string
		exempt     []string
		agentID    string
		hostname   string
		wantExempt bool
	}{
		{"未設定なら誰も除外しない", nil, agentID, "edr-server", false},
		{"エージェントIDの完全一致", []string{agentID}, agentID, "edr-server", true},
		{"ホスト名は大文字小文字を無視", []string{"EDR-Server"}, agentID, "edr-server", true},
		{"別ホストは除外しない", []string{"edr-server"}, otherID, "workstation-7", false},
		{"複数指定のうち1つに一致", []string{"jump-host", "edr-server", "lab-box"}, agentID, "edr-server", true},
		{"空白は無視する（EXEMPT=\"a, b\" の空要素で全台除外にならない）", []string{" ", ""}, agentID, "edr-server", false},
		{"前後の空白を許容する", []string{"  edr-server  "}, agentID, "edr-server", true},
		// A hostname that merely CONTAINS an exempt entry must not match: "edr-server"
		// should not exempt "edr-server-of-a-customer". Isolation is the one place
		// where a too-broad match silently disarms the response.
		{"部分一致では除外しない", []string{"edr-server"}, agentID, "edr-server-prod-2", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, sender, rec := exemptEngine(c.exempt)
			e.applyRuleBasedResponse(context.Background(),
				exemptAlert(c.agentID, c.hostname), &EventEnvelope{}, nil)

			if c.wantExempt {
				if len(sender.isolated) != 0 {
					t.Errorf("除外対象を隔離した (%v)。隔離は外部から取り消せないため、"+
						"プラットフォーム自身や踏み台を隔離すると復旧に帯域外アクセスが要る",
						sender.isolated)
				}
				// 除外の「記録が残る」ことが本質。残らないと、ドライランを外す前の
				// 見積りが除外ホスト分だけ構造的に欠ける。
				if !containsStr(rec.outcomes, string(isolation.OutcomeExempt)) {
					t.Errorf("除外が response_actions に記録されていない (outcomes=%v)。"+
						"記録の無い除外は、応答経路が壊れているのと外形が同じ", rec.outcomes)
				}
				return
			}
			if len(sender.isolated) != 1 {
				t.Errorf("除外対象でない端末が隔離されなかった (isolated=%v, outcomes=%v)",
					sender.isolated, rec.outcomes)
			}
		})
	}
}

// Engine が Hostname を載せずに要求すると、ホスト名指定の除外は Gatekeeper 側で
// HostnameResolver がある環境でしか効かない。resolver を構成し忘れた環境（実際に
// cmd/detection がそうだった）では黙って除外が外れるため、載せていること自体を
// 検査する。
func TestRuleBasedIsolationCarriesHostname(t *testing.T) {
	e, sender, _ := exemptEngine([]string{"victim-01"})
	e.applyRuleBasedResponse(context.Background(),
		exemptAlert("agent-1", "victim-01"), &EventEnvelope{}, nil)
	if len(sender.isolated) != 0 {
		t.Fatal("ホスト名指定の除外が効かなかった。Engine が Request.Hostname を" +
			"載せていないと、resolver の無い環境で除外が黙って外れる")
	}
}

// match 経由で認可された隔離も除外を尊重する。
func TestExemptListAppliesToMatchAuthorisedIsolation(t *testing.T) {
	e, sender, rec := exemptEngine([]string{"agent-1"})
	a := exemptAlert("agent-1", "victim-01")
	a.AutoIsolate = false
	e.applyRuleBasedResponse(context.Background(), a, &EventEnvelope{},
		&detectionrules.RuleMatch{RuleID: "", Severity: 10, AutoIsolate: true})
	if len(sender.isolated) != 0 {
		t.Error("match 経由の隔離が除外リストを迂回しました")
	}
	if !containsStr(rec.outcomes, string(isolation.OutcomeExempt)) {
		t.Errorf("match 経由の除外が記録されていない (outcomes=%v)", rec.outcomes)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

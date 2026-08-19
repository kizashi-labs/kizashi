package detection

import (
	"context"
	"testing"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// These cases complement auto_isolate_reachability_test.go, which covers the
// reachability half: that a correlator's AutoIsolate flag now arrives at the
// commander at all. `recordingCommander`, `newIsolationEngine` and `alertFrom`
// live there and are reused here rather than redeclared.
//
// What this file adds is the half that file does not touch — the controls that
// stop an authorised isolation from happening, and the alert-side carrier of the
// intent:
//
//   - a nil commander
//   - StoredAlert.AutoIsolate, which is what survives into the persisted alert
//     when there is no match to read the flag off
//
// There is deliberately no switch gating heuristic isolation. An earlier version
// of this work put it behind an off-by-default AUTO_ISOLATE_HEURISTIC, reasoning
// that isolation cannot be undone from outside the isolated host. That was the
// wrong shape: a response that looks wired but stays inert unless someone finds
// an undocumented env var is the same defect this path had to begin with, just
// spelled differently. The operator's opt-in is AutoResponseEnabled, the severity
// threshold, and the exemption list below.

// heuristicAlert is what a correlator produces: no rule ID, isolation requested,
// carried on the alert rather than on a match.
func heuristicAlert() *StoredAlert {
	return &StoredAlert{
		ID: "alert-1", AgentID: "agent-1", Hostname: "victim-01",
		RuleID: "", RuleName: "ランサムウェア相関: 複合前兆シグナルによる暗号化直前の疑い",
		Severity: 10, AutoIsolate: true,
	}
}

// StoredAlert.AutoIsolate must authorise on its own. processEventData copies the
// match's flag onto the alert it persists, so a caller holding only the alert —
// including any future replay or re-evaluation path — still has the intent.
func TestAlertCarriedAutoIsolateIsHonoured(t *testing.T) {
	e, cmd := newIsolationEngine()
	e.applyRuleBasedResponse(context.Background(), heuristicAlert(), &EventEnvelope{}, nil)
	if len(cmd.isolated) != 1 || cmd.isolated[0] != "agent-1" {
		t.Fatalf("隔離が実行されませんでした (%v)。アラートに載った AutoIsolate が"+
			"応答経路に届いていません", cmd.isolated)
	}
}

// The severity threshold applies to the code-defined detectors too.
func TestHeuristicIsolationRespectsSeverityThreshold(t *testing.T) {
	e, cmd := newIsolationEngine()
	e.config.AutoIsolateSeverityThreshold = 10
	a := heuristicAlert()
	a.Severity = 9
	e.applyRuleBasedResponse(context.Background(), a, &EventEnvelope{}, nil)
	if len(cmd.isolated) != 0 {
		t.Error("しきい値未満のアラートで隔離しました")
	}
}

// 除外リスト（AUTO_ISOLATE_EXEMPT）の検査は auto_isolate_exempt_test.go にある。
// あちらは fake の isolator ではなく実物の Gatekeeper を Engine の後ろに置いており、
// 「除外されること」と「除外が response_actions に記録されること」の両方を見る。
// ここで fake を相手に再検査しても、Engine が自分で除外しなくなった事実しか
// 分からない。

// The DB-rule path implied a wired engine (a loaded rule meant a commander); the
// correlator path does not.
func TestHeuristicIsolationWithoutCommanderDoesNotPanic(t *testing.T) {
	e := &Engine{
		store: &captureStore{}, rules: detectionrules.NewRuleEngine(),
		config: EngineConfig{AutoResponseEnabled: true, AutoIsolateSeverityThreshold: 9},
	}
	e.applyRuleBasedResponse(context.Background(), heuristicAlert(), &EventEnvelope{}, nil)
}

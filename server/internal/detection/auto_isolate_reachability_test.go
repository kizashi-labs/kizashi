package detection

import (
	"context"
	"strconv"
	"testing"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
	"github.com/edr-platform/server/internal/isolation"
)

// recordingIsolator captures isolation requests instead of talking to an agent.
//
// 安全弁と記録は isolation.Gatekeeper が持つ。ここで確かめたいのは
// 「検知側がそもそも隔離を要求したか」なので、Gatekeeper は挟まない。
// 安全弁そのものの挙動は internal/isolation のテストが見る。
type recordingIsolator struct {
	isolated []string
	reasons  []string
	origins  []isolation.Origin
}

func (c *recordingIsolator) Isolate(_ context.Context, req isolation.Request) (isolation.Result, error) {
	c.isolated = append(c.isolated, req.AgentID)
	c.reasons = append(c.reasons, req.Reason)
	c.origins = append(c.origins, req.Origin)
	return isolation.Result{Outcome: isolation.OutcomeDispatched, ActionID: "row-1"}, nil
}

// newIsolationEngine builds the minimum Engine needed to exercise the auto-response
// path with auto-isolation armed at the production default threshold (9).
func newIsolationEngine() (*Engine, *recordingIsolator) {
	iso := &recordingIsolator{}
	return &Engine{
		store:    &captureStore{},
		rules:    detectionrules.NewRuleEngine(),
		isolator: iso,
		config: EngineConfig{
			AutoResponseEnabled:          true,
			AutoIsolateSeverityThreshold: 9,
		},
	}, iso
}

// 検知側が申告する経路が auto_rule であること。記録の origin がずれると、
// 「どの経路が端末を止めたのか」を後から辿れなくなる。
func TestRuleBasedIsolationDeclaresItsOrigin(t *testing.T) {
	e, iso := newIsolationEngine()
	m := &detectionrules.RuleMatch{RuleID: "", RuleName: "ランサムウェア相関", Severity: 10, AutoIsolate: true}
	e.applyRuleBasedResponse(context.Background(), alertFrom(m), nil, m)
	if len(iso.origins) != 1 || iso.origins[0] != isolation.OriginRule {
		t.Fatalf("origin = %v, want %q", iso.origins, isolation.OriginRule)
	}
}

func alertFrom(m *detectionrules.RuleMatch) *StoredAlert {
	return &StoredAlert{
		ID:       "alert-1",
		AgentID:  "agent-1",
		RuleID:   m.RuleID,
		RuleName: m.RuleName,
		Severity: m.Severity,
	}
}

// TestCorrelatorAutoIsolateIsHonoured is the regression guard for a silent failure:
// applyRuleBasedResponse looked up the DB rule by alert.RuleID and returned early
// when it was nil. Every stateful correlator emits RuleID:"" because it is code, not
// a row, so GetRule("") returned nil and their AutoIsolate:true was never read —
// the ransomware, C2 and implant correlators each declare auto-isolation at severity
// 10 on a multi-signal confirmation and none of them could ever isolate anything.
func TestCorrelatorAutoIsolateIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match *detectionrules.RuleMatch
	}{
		{"ransomware precursor composite", &detectionrules.RuleMatch{
			RuleID: "", RuleName: "ランサムウェア相関", RuleType: "correlation",
			Severity: 10, AutoIsolate: true,
		}},
		{"C2 confirmed on N axes", &detectionrules.RuleMatch{
			RuleID: "", RuleName: "C2相関", RuleType: "correlation",
			Severity: 10, AutoIsolate: true,
		}},
		{"active implant", &detectionrules.RuleMatch{
			RuleID: "", RuleName: "プロセス相関", RuleType: "correlation",
			Severity: 10, AutoIsolate: true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, cmd := newIsolationEngine()
			e.applyRuleBasedResponse(context.Background(), alertFrom(tc.match), nil, tc.match)
			if len(cmd.isolated) != 1 {
				t.Fatalf("correlator with AutoIsolate:true and severity %d did not isolate (calls=%d)",
					tc.match.Severity, len(cmd.isolated))
			}
		})
	}
}

// A match that does NOT ask for isolation must not isolate, whatever its severity.
// c2_correlator deliberately emits severity 9 without AutoIsolate below its
// confirmation threshold, and 9 is the default isolate threshold — so severity
// alone must never be sufficient.
func TestSeverityAloneDoesNotIsolate(t *testing.T) {
	e, cmd := newIsolationEngine()
	m := &detectionrules.RuleMatch{
		RuleID: "", RuleName: "C2相関(2軸)", RuleType: "correlation",
		Severity: 9, AutoIsolate: false,
	}
	e.applyRuleBasedResponse(context.Background(), alertFrom(m), nil, m)
	if len(cmd.isolated) != 0 {
		t.Fatalf("severity 9 without AutoIsolate isolated the host: %v", cmd.reasons)
	}
}

// The pre-existing DB-rule path (rules.auto_isolate, looked up by alert.RuleID)
// must keep working — the fix adds a second authorising source, it does not
// replace the first.
func TestDBRuleAutoIsolateStillWorks(t *testing.T) {
	e, cmd := newIsolationEngine()
	e.rules.LoadRules([]*detectionrules.DetectionRule{{
		ID: "rule-db-1", Name: "Cobalt Strike Beacon", Type: "sigma",
		Severity: 10, Enabled: true, AutoIsolate: true,
	}})
	alert := &StoredAlert{ID: "a", AgentID: "agent-1", RuleID: "rule-db-1", Severity: 10}
	// A DB-sourced match carries the flag too, but pass it unset to prove the
	// lookup path alone still authorises isolation.
	e.applyRuleBasedResponse(context.Background(), alert, nil, &detectionrules.RuleMatch{RuleID: "rule-db-1"})
	if len(cmd.isolated) != 1 {
		t.Fatalf("DB rule with auto_isolate=true no longer isolates (calls=%d)", len(cmd.isolated))
	}
}

// AutoResponseEnabled=false is the kill switch and must win over both sources.
func TestAutoResponseDisabledBlocksCorrelatorIsolation(t *testing.T) {
	e, cmd := newIsolationEngine()
	e.config.AutoResponseEnabled = false
	m := &detectionrules.RuleMatch{RuleID: "", Severity: 10, AutoIsolate: true}
	e.applyRuleBasedResponse(context.Background(), alertFrom(m), nil, m)
	if len(cmd.isolated) != 0 {
		t.Fatal("AUTO_RESPONSE_ENABLED=false did not block correlator-driven isolation")
	}
}

// A file burst on its own must not isolate. In a fully benign 20-host FP soak this
// detector fired 38 times — go/docker builds, restic/rsync backups, find, robocopy
// and Defender's own MsMpEng.exe — so it sits one below the isolate threshold by
// construction. Guards against someone raising it back to 9.
func TestFileBurstAloneStaysBelowIsolationThreshold(t *testing.T) {
	d := newFileBurstScorer()
	now := time.Now()
	var fired *detectionrules.RuleMatch
	for i := 0; i < fileBurstMinFiles; i++ {
		for _, m := range d.Observe("agent-1", "linux", "go", pathN(i), "FILE_ACTION_MODIFY", now) {
			fired = m
		}
	}
	if fired == nil {
		t.Fatal("file burst did not fire at all")
	}
	if fired.Severity >= 9 {
		t.Fatalf("file burst severity %d is at/above the default auto-isolate threshold (9); "+
			"a benign build would cut the host off the network", fired.Severity)
	}
	if fired.AutoIsolate {
		t.Fatal("file burst must not request auto-isolation on its own")
	}

	e, cmd := newIsolationEngine()
	e.applyRuleBasedResponse(context.Background(), alertFrom(fired), nil, fired)
	if len(cmd.isolated) != 0 {
		t.Fatalf("standalone file burst isolated the host: %v", cmd.reasons)
	}
}

// Paired with a precursor axis the same burst becomes an analyst-grade composite,
// but two axes alone no longer isolate — one of the two here (mass_modify) is
// empirically noisy. A THIRD distinct axis, with a specific one present, is what
// escalates to severity 10 + AutoIsolate, and that now actually reaches the
// commander.
func TestBurstPlusPrecursorsEscalatesAndIsolates(t *testing.T) {
	r := newRansomwareCorrelator()
	now := time.Now()

	if m := r.Observe("agent-1", ransomSigMassModify, now); len(m) != 0 {
		t.Fatalf("mass-modify alone produced a composite alert: %+v", m[0])
	}
	two := r.Observe("agent-1", ransomSigRecoveryInhibit, now.Add(30*time.Second))
	if len(two) != 1 {
		t.Fatalf("mass-modify + recovery-inhibit did not correlate (got %d matches)", len(two))
	}
	if two[0].AutoIsolate {
		t.Error("two axes must alert but not isolate unattended")
	}
	if two[0].Severity != 9 {
		t.Errorf("two-axis composite severity = %d, want 9", two[0].Severity)
	}

	three := r.Observe("agent-1", ransomSigDefenseTamper, now.Add(60*time.Second))
	if len(three) != 1 {
		t.Fatalf("a third distinct axis should re-fire on growth (got %d)", len(three))
	}
	m := three[0]
	if m.Severity != 10 || !m.AutoIsolate {
		t.Fatalf("three-axis composite: want severity 10 + AutoIsolate, got %d / %v", m.Severity, m.AutoIsolate)
	}

	e, cmd := newIsolationEngine()
	e.applyRuleBasedResponse(context.Background(), alertFrom(m), nil, m)
	if len(cmd.isolated) != 1 {
		t.Fatalf("confirmed encryption sequence did not isolate (calls=%d)", len(cmd.isolated))
	}
}

// The measured false-positive shape: routine Linux chmod (acl_stage, 67 alerts in 30
// days on one host) plus a benign build/backup burst (mass_modify, 129) is a
// two-axis co-occurrence made entirely of noisy axes. It must never isolate.
func TestNoisyAxesAloneNeverIsolate(t *testing.T) {
	r := newRansomwareCorrelator()
	now := time.Now()
	r.Observe("agent-1", ransomSigACLStage, now)
	m := r.Observe("agent-1", ransomSigMassModify, now.Add(time.Minute))
	if len(m) != 1 {
		t.Fatalf("want the composite to still alert, got %d", len(m))
	}
	if m[0].AutoIsolate {
		t.Error("chmod + file burst must not take a host off the network")
	}

	e, cmd := newIsolationEngine()
	e.applyRuleBasedResponse(context.Background(), alertFrom(m[0]), nil, m[0])
	if len(cmd.isolated) != 0 {
		t.Errorf("noisy-axis composite isolated the host: %v", cmd.reasons)
	}
}

func pathN(i int) string {
	return "/srv/data/file-" + strconv.Itoa(i) + ".dat"
}

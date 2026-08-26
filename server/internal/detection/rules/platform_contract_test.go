package rules

import "testing"

// The OS gate only works if the string the agent→ingestion path produces is one
// canonPlatform recognises. That contract was never load-bearing before
// 2026-08-04: the agent left EventBatch.Platform at PLATFORM_UNSPECIFIED, so
// ingestion's platformString always returned "unknown", canonPlatform mapped it to
// "" and platformMatchesEvent took its fail-open branch for every event. The gate
// (#356) was a no-op in production from the day it shipped.
//
// Now that agents stamp their OS, a mismatch between the two ends would silently
// re-open the same hole — and it would look identical to a working gate, because
// fail-open means "every rule runs", which is also what a healthy unknown-OS event
// does. These tests pin both directions.

// ingestionPlatformStrings mirrors server/internal/ingestion/handler.go's
// platformString(), which is unexported. Keep the two in sync: an enum value added
// there without a case here (or vice versa) means events arrive with a platform
// the gate cannot interpret.
var ingestionPlatformStrings = []string{
	"linux",   // v1.Platform_PLATFORM_LINUX
	"windows", // v1.Platform_PLATFORM_WINDOWS
	"darwin",  // v1.Platform_PLATFORM_DARWIN
}

func TestCanonPlatformAcceptsEveryIngestionValue(t *testing.T) {
	for _, p := range ingestionPlatformStrings {
		if canonPlatform(p) == "" {
			t.Errorf("ingestion が emit する platform %q を canonPlatform が解釈できません。"+
				"ゲートは fail-open するため、これは「壊れている」ではなく「効いていない」"+
				"状態として現れ、正常時と外形が同じになります", p)
		}
	}
}

// platformString returns "unknown" for PLATFORM_UNSPECIFIED — an agent too old to
// stamp the field, or an OS we do not name. That MUST fail open: dropping
// detections on an unidentified host is far worse than a rare cross-OS false
// positive, which is the entire reason the gate is written permissively.
func TestUnknownPlatformFailsOpen(t *testing.T) {
	for _, p := range []string{"unknown", "", "freebsd"} {
		if !platformMatchesEvent([]string{"windows"}, p) {
			t.Errorf("platform=%q でルールがゲートされました。未知の OS は fail-open "+
				"でなければ、エージェント更新前のホストの検知が黙って消えます", p)
		}
	}
}

// A rule with no platform label is universal and must never be gated, whatever the
// event's OS. SigmaHQ rules whose logsource carries no product land here
// (inferPlatforms returns all three, but hand-written and migration rules often
// leave it empty).
func TestUnlabelledRuleIsNeverGated(t *testing.T) {
	for _, p := range append(ingestionPlatformStrings, "unknown") {
		if !platformMatchesEvent(nil, p) {
			t.Errorf("platform 未指定のルールが %q でゲートされました", p)
		}
	}
}

// darwin (runtime.GOOS, what the agent reports) and macos (SigmaHQ
// logsource.product, what rules are labelled with) are the same OS. Equality alone
// would gate every macOS rule off every macOS event — the failure this fold exists
// to prevent.
func TestDarwinAndMacosAreTheSamePlatform(t *testing.T) {
	if !platformMatchesEvent([]string{"macos"}, "darwin") {
		t.Error("macos ラベルのルールが darwin イベントでゲートされました")
	}
	if !platformMatchesEvent([]string{"darwin"}, "darwin") {
		t.Error("darwin ラベルのルールが darwin イベントでゲートされました")
	}
}

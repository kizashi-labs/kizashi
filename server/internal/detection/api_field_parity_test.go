package detection

import (
	"sort"
	"testing"
)

// Which engine evaluates the `rules` table is a coverage decision, not a
// preference.
//
// After P4-6 both engines read that table: server-api's AlertPipeline (which
// keeps up) and server-detect's RuleEngine (whose consumer lags chronically).
// One event therefore produces two alert rows, and collapsing that to one means
// picking an owner. The api is only a safe owner if it can resolve the fields
// the DB rules select on.
//
// That had never been measured. `TestBuiltinRuleFieldSupportAudit` audits the
// BUILT-IN corpus against SupportedSigmaFields, and
// rules.TestMigrationSigmaFieldSupport audits the DB corpus against
// server-DETECT's field map. Nobody had crossed them: the DB rules had never
// been checked against the api's field support, which is exactly the pairing an
// ownership transfer depends on.
//
// This is a FIELD-RESOLUTION gate, not a semantic one. It cannot say the two
// engines agree on what a rule means; it says a rule's selectors are not
// addressing fields this pipeline never produces — the silent-inert class.
// Sigma parsing is covered separately by
// TestMigrationSigmaRulesParseInProductionEvaluator.
//
// It reuses detection.SupportedSigmaFields / RuleFieldSupportWith, the same
// production helpers curate-analyze gates on, rather than deriving the
// supported set independently. A second derivation drifts from the first, and
// the drift shows up as confident wrong answers: an earlier draft of this test
// built its own set out of the alias table alone and reported the WMI
// subscription rule (migration 370) as inert, because it had never heard of
// field_support.go's kitchen-sink event where `consumer` and `event_type` are
// declared. One registry, or the checker becomes the thing that needs checking.

// knownInert are DB rules that cannot fire in EITHER engine because no sensor
// emits the datum they select on. They are recorded, not silenced: an entry here
// is a claim that the rule is dead everywhere, and each was checked against
// server-detect's field map (rules/rule_engine.go) and the agent collectors
// before being added.
//
// The distinction matters for the ownership question. A rule that only the api
// cannot resolve is an ASYMMETRY — moving the `rules` table to a single owner
// would drop live coverage. A rule neither engine resolves is pre-existing dead
// content, and moving ownership costs nothing. The first kind blocks; the second
// does not. `LSASS ダンプ` was the first kind and is fixed (access_mask alias);
// these three are the second.
//
// Do NOT add an entry to make this test green. Add one only after confirming
// the field is absent from BOTH rules/rule_engine.go's map and the agent's
// collectors — otherwise you are hiding an asymmetry, which is what this gate is
// for.
var knownInert = map[string]string{
	"Credential Dumping via DCSync": "selects on Properties (Windows 4662 Directory Service Access). " +
		"The agent does not subscribe to 4662 at all, and rules/rule_engine.go has no mapping " +
		"either — dead in both engines. Covered instead by the builtin DCSync rule keyed on " +
		"process/command line.",
	"Pass-the-Hash": "selects on LogonProcessName + WorkstationName (Windows 4624 detail fields). " +
		"The auth collector emits success/source_ip/auth_method/failure_reason/logon_type only; " +
		"neither field exists in any engine's map. Dead in both.",
	"SMB Lateral Movement - Admin Share Access": "selects on ShareName (Windows 5140 network share " +
		"access). Not collected by the agent and not mapped by either engine. Dead in both.",
}

func TestMigrationSigmaFieldSupportInAPIEvaluator(t *testing.T) {
	supported := SupportedSigmaFields()
	if len(supported) < 50 {
		t.Fatalf("SupportedSigmaFields returned only %d names — the kitchen-sink event is "+
			"broken and this test would fail everything for the wrong reason", len(supported))
	}

	// migrationSigmaBlocks replays the migrations in filename order and keeps the
	// LAST definition of each title, which is what the database ends up with. It
	// does not track `enabled`, so a rule migration 377 disabled is still examined.
	// That only makes this gate stricter — it never lets a real gap through — and a
	// disabled rule whose fields are unresolvable is worth knowing about before
	// anyone re-enables it.
	blocks := migrationSigmaBlocks(t)
	if len(blocks) < 100 {
		t.Fatalf("only %d migration Sigma rules extracted — the extractor is broken and this "+
			"test would pass vacuously", len(blocks))
	}

	type gap struct {
		title       string
		file        string
		unsupported []string
	}
	var inert []gap

	var stale []string
	seenInert := map[string]bool{}
	for title, blk := range blocks {
		ok, unsupported := RuleFieldSupportWith(blk.body, supported)
		if ok {
			continue
		}
		if _, known := knownInert[title]; known {
			seenInert[title] = true
			continue
		}
		sort.Strings(unsupported)
		inert = append(inert, gap{title: title, file: blk.file, unsupported: unsupported})
	}

	// A knownInert entry that no longer applies is worse than no entry: it is a
	// standing exemption for a rule that may since have become resolvable, and the
	// next rule to regress under that title would be waved through.
	for title := range knownInert {
		if !seenInert[title] {
			stale = append(stale, title)
		}
	}
	sort.Strings(stale)
	for _, title := range stale {
		t.Errorf("knownInert lists %q, but that rule now resolves its fields (or no longer "+
			"exists under this title). Remove the entry — a stale exemption silently covers "+
			"whatever takes the name next.", title)
	}

	t.Logf("checked %d DB Sigma rules against %d api-resolvable field names",
		len(blocks), len(supported))

	sort.Slice(inert, func(i, j int) bool { return inert[i].title < inert[j].title })
	for _, g := range inert {
		t.Errorf("DB rule %q (%s) selects on fields the api pipeline cannot resolve: %v\n"+
			"  The rule is not dead today — server-detect may still evaluate it — but that "+
			"makes server-detect its ONLY cover, and any move of the `rules` table to a single "+
			"owner would drop it silently.\n"+
			"  Fix by adding the field to addPipelineSigmaAliases (alert_pipeline.go) when the "+
			"agent emits the datum under another name, and to the kitchen-sink event in "+
			"field_support.go so this gate can see it.",
			g.title, g.file, g.unsupported)
	}
}

// Field resolution is necessary but not sufficient: the alias has to actually
// carry the value through to a match. This drives the rule the gate above found
// — "LSASS ダンプ" (T1003.001, migration 003) — with the event shape the
// credential-access sensor really emits, and asserts it fires.
//
// Before the access_mask→GrantedAccess alias this could not match in server-api
// no matter what arrived, because the selection ANDs GrantedAccess with
// TargetImage and GrantedAccess was never present on the event. server-detect
// matched it, so the rule looked alive in production while the engine that keeps
// up was blind to it.
func TestLSASSDumpRuleFiresInAPIEvaluatorViaAccessMask(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	blk, ok := blocks["LSASS ダンプ"]
	if !ok {
		t.Fatal(`the "LSASS ダンプ" rule is no longer in the migrations — if it was renamed, ` +
			"retarget this test rather than deleting it; it guards the alias, not the name")
	}

	ev := NewSigmaEvaluator()
	if err := ev.LoadRule(blk.body); err != nil {
		t.Fatalf("load rule from %s: %v", blk.file, err)
	}

	// この関数はもともと target_image にフルパスを置き、「これがセンサの出す形だ」と
	// 書いたうえで発火を断言していた。実測すると **その形は出ていない**。
	// agent/internal/collector/credential_access.go は target_image を basename
	// ("lsass.exe") で出す設計で、コメントにもそう書いてある。検証EC2の実DBでも
	// 40 日間の値は "lsass.exe"（9 文字）のみだった。
	//
	// つまりフルパスで緑になっていたのは false green で、このルールは production で
	// 一度も発火していない（全期間 0 件）。ここでは両方の形を並べ、どこまでが効いて
	// いてどこから効かないのかを固定する。
	fires := func(t *testing.T, targetImage string) bool {
		t.Helper()
		event := map[string]interface{}{
			"type":         "credential_access",
			"target_image": targetImage,
			"target_pid":   float64(760),
			"source_image": `C:\Users\v\mimikatz.exe`,
			"source_pid":   float64(4242),
			"access_mask":  "0x1410",
		}
		addPipelineSigmaAliases(event)
		if got, ok := event["GrantedAccess"]; !ok || got != "0x1410" {
			t.Fatalf("access_mask did not alias to GrantedAccess (got %v, present=%v) — "+
				"the alias in addPipelineSigmaAliases is gone or renamed", got, ok)
		}
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == "LSASS ダンプ" {
				return true
			}
		}
		return false
	}

	// ルールの論理と access_mask→GrantedAccess のエイリアスは健全である。パスさえ
	// 揃えば当たる、というのがこの断言。
	if !fires(t, `C:\Windows\System32\lsass.exe`) {
		t.Error(`"LSASS ダンプ" did not fire on an LSASS handle-open with GrantedAccess 0x1410. ` +
			"The rule ANDs TargetImage with GrantedAccess, so losing either alias makes it " +
			"permanently inert in server-api while server-detect still matches it — a gap that " +
			"is invisible from the alert stream because the other engine covers it late.")
	}

	// センサが実際に出す形（basename）。TargetImage は Image / ParentImage と違って
	// basename 正規化の対象に入っていないため、endswith の照合に一致しない。
	//
	// この断言が落ちたなら、TargetImage を addPipelineSigmaAliases の正規化対象に
	// 加えたということである。その場合はまず
	// docs/results/live-20260818-jp-duplicate-rules-inert.md を読むこと——このルールを
	// 到達可能にすると Windows Defender (MsMpEng.exe) の LSASS アクセスで発火する。
	// migration 448 で enabled=false / auto_isolate=false にしてあるのはそのためで、
	// 正規化を入れる側はここを戻す前に発信元の絞り込みが要る。
	if fires(t, "lsass.exe") {
		t.Error("basename の target_image で LSASS ダンプ が発火した。TargetImage の " +
			"basename 正規化が入ったなら、migration 448 の意図（Defender の LSASS " +
			"アクセスで自動隔離される）を確認してからこの断言を更新すること")
	}
}

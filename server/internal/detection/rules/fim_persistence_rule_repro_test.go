package rules

import (
	"context"
	"testing"
)

// Repro for the 2026-07-07 live finding: migration-311 file_event rules that use
// a multi-item `TargetFilename|contains` list did not fire on the endpoint, while
// the single-`endswith` rules (ld.so.preload/rc.local) did. This test drives the
// EXACT rule content + a file event through the real RuleEngine to decide whether
// the cause is the rule/engine (bug) or the live environment (timing/reload).
func TestRuleEngine_FIM_CronDropinContainsList(t *testing.T) {
	const cron = `
title: Linux Cron Drop-in File Written (FIM)
level: medium
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /etc/cron.d/
      - /etc/cron.hourly/
      - /etc/cron.daily/
      - /etc/cron.weekly/
      - /etc/cron.monthly/
      - /var/spool/cron/
  condition: selection
`
	const shellInit = `
title: Linux Shell Init File Modification (FIM)
level: medium
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - /.bashrc
      - /.bash_profile
      - /.bash_login
      - /.profile
      - /.zshrc
      - /etc/profile.d/
  condition: selection
`
	const ldso = `
title: Linux ld.so.preload Hijack (FIM)
level: high
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|endswith: /etc/ld.so.preload
  condition: selection
`
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{
		sigmaRule("cron-fim", cron),
		sigmaRule("shellinit-fim", shellInit),
		sigmaRule("ldso-fim", ldso),
	})

	// The exact shape the endpoint FIM emits (handler.go unpacks fim_change into
	// this flat map; `path` is the canonical field aliased to TargetFilename).
	cronEvt := map[string]interface{}{
		"type": "file", "agent_id": "h", "platform": "linux",
		"path": "/etc/cron.d/edrtest-persist", "change_type": "created",
	}
	bashrcEvt := map[string]interface{}{
		"type": "file", "agent_id": "h", "platform": "linux",
		"path": "/home/ubuntu/.bashrc", "change_type": "modified",
	}
	ldsoEvt := map[string]interface{}{
		"type": "file", "agent_id": "h", "platform": "linux",
		"path": "/etc/ld.so.preload", "change_type": "created",
	}

	mc, _ := e.Evaluate(context.Background(), cronEvt)
	if !hasRule(mc, "cron-fim") {
		t.Errorf("cron-fim (multi-item contains) did NOT match /etc/cron.d/edrtest-persist — reproduces the live non-fire; got %d matches", len(mc))
	}
	mb, _ := e.Evaluate(context.Background(), bashrcEvt)
	if !hasRule(mb, "shellinit-fim") {
		t.Errorf("shellinit-fim (multi-item contains) did NOT match /home/ubuntu/.bashrc; got %d matches", len(mb))
	}
	ml, _ := e.Evaluate(context.Background(), ldsoEvt)
	if !hasRule(ml, "ldso-fim") {
		t.Errorf("ldso-fim (endswith) did NOT match — unexpected, it fired live; got %d matches", len(ml))
	}
}

package rules

import (
	"context"
	"testing"
)

// Guards the Linux measurement gap-fill rules (migration 309). Each detection
// block MUST mirror 309's YAML. Every case feeds the exact command the 2026-07-06
// Linux battery ran (which previously reached only Telemetry/Tactic) and asserts
// the rule now fires, plus a benign command that must NOT match.
//
// Linux process events carry command_line/image_path; the RuleEngine field map
// resolves CommandLine→command_line, so we set command_line directly.

func linuxProc(cmd string) map[string]any {
	return map[string]any{
		"type":         "process",
		"platform":     "linux",
		"agent_id":     "host-linux",
		"image_path":   "/usr/bin/bash",
		"command_line": cmd,
	}
}

func TestLinuxMeasurementRules(t *testing.T) {
	cases := []struct {
		id      string
		content string
		attack  string // battery command that must match
		benign  string // command that must NOT match
	}{
		{
			id: "t1543-002",
			content: `
title: systemd persistence
tags: [attack.t1543.002]
logsource: {product: linux, category: process_creation}
detection:
  systemctl: {CommandLine|contains: systemctl}
  enable: {CommandLine|contains: ' enable'}
  condition: systemctl and enable`,
			attack: `systemctl --user enable edrtest.service`,
			benign: `systemctl --user disable edrtest.service`,
		},
		{
			id: "t1053-003",
			content: `
title: cron persistence
tags: [attack.t1053.003]
logsource: {product: linux, category: process_creation}
detection:
  install_pipe: {CommandLine|contains: '| crontab'}
  install_edit: {CommandLine|contains: 'crontab -e'}
  crondir:
    CommandLine|contains: [/etc/cron.d/, /etc/cron.hourly, /etc/cron.daily, /var/spool/cron]
  condition: install_pipe or install_edit or crondir`,
			attack: `bash -c (crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.x') | crontab -`,
			benign: `crontab -l`,
		},
		{
			id: "t1548-001",
			content: `
title: setuid creation
tags: [attack.t1548.001]
logsource: {product: linux, category: process_creation}
detection:
  chmod: {CommandLine|contains: chmod}
  suid:
    CommandLine|contains: [u+s, g+s, +s, ' 4755', ' 4777', ' 2755', ' 6755', ' 04755']
  condition: chmod and suid`,
			attack: `chmod 4755 /tmp/.edr_suid`,
			benign: `chmod 0644 /tmp/file`,
		},
		{
			id: "t1222-002",
			content: `
title: permissive chmod
tags: [attack.t1222.002]
logsource: {product: linux, category: process_creation}
detection:
  chmod: {CommandLine|contains: chmod}
  perms:
    CommandLine|contains: [' 777', ' 0777', ' 666', a+rwx]
  condition: chmod and perms`,
			attack: `chmod 777 /tmp/.edr_stage`,
			benign: `chmod 755 /usr/local/bin/tool`,
		},
		{
			id: "t1562-001",
			content: `
title: impair defenses
tags: [attack.t1562.001]
logsource: {product: linux, category: process_creation}
detection:
  disable:
    CommandLine|contains:
      - 'setenforce 0'
      - 'systemctl stop auditd'
      - 'auditctl -e 0'
      - 'aa-disable'
      - 'ufw disable'
      - 'iptables -F'
  condition: disable`,
			attack: `systemctl stop auditd`,
			benign: `systemctl status auditd`,
		},
		{
			id: "t1070-003",
			content: `
title: clear history
tags: [attack.t1070.003]
logsource: {product: linux, category: process_creation}
detection:
  histfile_target: {CommandLine|contains: .bash_history}
  clear_verb:
    CommandLine|contains: ['rm ', truncate, '/dev/null', 'cat /dev/null']
  histfile_env:
    CommandLine|contains: ['unset HISTFILE', 'HISTFILE=/dev/null', 'HISTSIZE=0', 'export HISTFILE=']
  condition: (histfile_target and clear_verb) or histfile_env`,
			attack: `rm -f /home/ubuntu/.bash_history`,
			benign: `cat /home/ubuntu/.bash_history`,
		},
		{
			id: "t1003-008",
			content: `
title: shadow access
tags: [attack.t1003.008]
logsource: {product: linux, category: process_creation}
detection:
  shadow:
    CommandLine|contains: [/etc/shadow, /etc/gshadow]
  reader:
    CommandLine|contains: ['cat ', 'cp ', 'less ', 'more ', 'head ', 'tail ', unshadow, 'base64 ', 'awk ', 'cut ']
  condition: shadow and reader`,
			attack: `cat /etc/shadow`,
			benign: `cat /etc/hostname`,
		},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			e := NewRuleEngine()
			e.LoadRules([]*DetectionRule{sigmaRule(c.id, c.content)})

			if m, err := e.Evaluate(context.Background(), linuxProc(c.attack)); err != nil {
				t.Fatalf("Evaluate(attack): %v", err)
			} else if !hasRule(m, c.id) {
				t.Fatalf("rule %s should match battery command %q", c.id, c.attack)
			}

			if m, _ := e.Evaluate(context.Background(), linuxProc(c.benign)); hasRule(m, c.id) {
				t.Errorf("rule %s must NOT match benign command %q", c.id, c.benign)
			}
		})
	}
}
